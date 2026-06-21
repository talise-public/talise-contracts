//! Native Groth16 prover + Sui-format serialization for the Talise privacy
//! circuit.
//!
//! This vendors the proving logic from Vortex's `wasm/mod.rs` but as a native
//! (non-wasm) helper, and uses REAL OS entropy (`OsRng`) for proof randomness
//! rather than Vortex's deterministic `ChaCha20Rng::from_seed([0u8; 32])`.
//!
//! Serialization formats produced here match what the Sui Move verifier
//! consumes (see `vortex_proof::make_public_inputs` /
//! `groth16::proof_points_from_bytes` / `groth16::prepare_verifying_key`):
//!
//! * `vk_hex`             — arkworks `VerifyingKey::serialize_compressed`
//!   (alpha_g1 ‖ beta_g2 ‖ gamma_g2 ‖ delta_g2 ‖ u64-LE-len ‖ gamma_abc_g1[]).
//!   This is byte-identical to what `groth16::prepare_verifying_key` expects.
//! * `proof_hex`          — proofA (32B compressed G1) ‖ proofB (64B compressed
//!   G2) ‖ proofC (32B compressed G1).
//! * `public_inputs_hex`  — the 8 public inputs, each a 32-byte little-endian
//!   field element, concatenated in allocation order:
//!   [pool/vortex, root, public_value, null0, null1, comm0, comm1, hashed_secret].

use crate::circuit::TransactionCircuit;
use crate::constants::{MERKLE_TREE_LEVEL, N_INS, N_OUTS};
use crate::merkle_tree::Path;
use crate::poseidon_opt::{hash1, hash3, hash4};

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use num_bigint::BigUint;
use rand::rngs::OsRng;

/// Result of building + proving a deposit transaction.
pub struct DepositArtifacts {
    pub pk: ProvingKey<Bn254>,
    pub vk: VerifyingKey<Bn254>,
    pub proof: Proof<Bn254>,
    pub public_inputs: Vec<Fr>,
}

/// The secret material backing the two fresh output notes of a deposit. The
/// caller needs these (off-chain) to later build a WITHDRAW that spends these
/// notes: a note's commitment == hash4(amount, hash1(privkey), blinding, vortex)
/// and the vortex domain separator here is the pool field element.
pub struct OutputNote {
    pub amount: Fr,
    pub private_key: Fr,
    pub public_key: Fr,
    pub blinding: Fr,
    pub commitment: Fr,
}

/// Decode a Sui 0x-prefixed (or bare) hex address into the BN254 field element
/// that `proof.move`'s `make_public_inputs` produces for public input [0]:
///
///   self.pool.to_u256().to_field()
///
/// where `address::to_u256` reads the 32-byte address as a BIG-ENDIAN integer
/// and `to_field` = `bcs::to_bytes(&(value % bn254_field_modulus))` (i.e. reduce
/// mod the BN254 scalar-field r, then little-endian 32 bytes). `Fr::from` does
/// the mod-r reduction; the LE serialization is handled at hex-output time by
/// `public_inputs_hex`. So the field element == address_as_u256 mod r.
pub fn pool_address_to_field(addr: &str) -> anyhow::Result<Fr> {
    let s = addr.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if s.is_empty() {
        anyhow::bail!("empty pool address");
    }
    // A Sui address is up to 32 bytes; `to_u256` treats it as a big-endian
    // integer. Parsing the hex string as a big integer is exactly that.
    let big = BigUint::parse_bytes(s.as_bytes(), 16)
        .ok_or_else(|| anyhow::anyhow!("pool address is not valid hex: {addr}"))?;
    // Fr::from(BigUint) reduces mod the BN254 scalar field r.
    Ok(Fr::from(big))
}

/// Decode a u256 given as a DECIMAL string into a field element, matching
/// `proof.move`'s `root.to_field()` (reduce mod r). For `root` this is the
/// Merkle root the proof targets; for a deposit with zero-value inputs the
/// Merkle membership check is skipped, so any root (commonly 0) is accepted.
pub fn u256_decimal_to_field(dec: &str) -> anyhow::Result<Fr> {
    let big = BigUint::parse_bytes(dec.trim().as_bytes(), 10)
        .ok_or_else(|| anyhow::anyhow!("root is not a valid u256 decimal: {dec}"))?;
    Ok(Fr::from(big))
}

/// Generate DEV/TEST Groth16 keys with real OS entropy.
///
/// NOT a trusted setup ceremony — the toxic waste lives (briefly) in this
/// process. Fine for tests / artifact generation, unsafe for production funds.
pub fn dev_setup() -> anyhow::Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>)> {
    let mut rng = OsRng;
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        TransactionCircuit::empty(),
        &mut rng,
    )?;
    let vk = pk.vk.clone();
    Ok((pk, vk))
}

/// Build a witness for the SIMPLEST shielded op: a DEPOSIT of `amount` that
/// creates two output notes whose amounts sum to `amount`, with dummy (zero)
/// input notes.
///
/// `out0_amount + out1_amount` MUST equal `amount` for the value-conservation
/// constraint `sum_ins + public_amount == sum_outs` to hold (sum_ins == 0).
pub fn build_deposit_circuit(
    amount: u64,
    out0_amount: u64,
    out1_amount: u64,
) -> anyhow::Result<TransactionCircuit> {
    // Pool / "vortex" domain separator — an arbitrary fixed field element for
    // the self-contained test path.
    let (circuit, _notes) =
        build_deposit_circuit_for_pool(Fr::from(1u64), Fr::from(0u64), amount, out0_amount, out1_amount)?;
    Ok(circuit)
}

/// Pool-aware deposit witness. Public input [0] (`vortex`) is bound to the pool
/// field element so it equals what `proof.move::make_public_inputs` supplies as
/// `self.pool.to_u256().to_field()`. Public input [1] (`root`) is bound to the
/// given root field element (`self.root.to_field()`). The `vortex` value is also
/// the domain separator hashed into every commitment/nullifier, so output notes
/// are bound to THIS pool — exactly what the on-chain verifier requires.
///
/// Returns the circuit plus the two output-note secrets (needed to later build a
/// withdraw spending these notes).
pub fn build_deposit_circuit_for_pool(
    vortex: Fr,
    root: Fr,
    amount: u64,
    out0_amount: u64,
    out1_amount: u64,
) -> anyhow::Result<(TransactionCircuit, [OutputNote; N_OUTS])> {
    // ---- Dummy input notes (zero amount => Merkle membership check skipped) ----
    let in_private_keys = [Fr::from(12_345u64), Fr::from(67_890u64)];
    let in_amounts = [Fr::from(0u64), Fr::from(0u64)];
    let in_blindings = [Fr::from(999u64), Fr::from(888u64)];
    let in_path_indices = [Fr::from(0u64), Fr::from(1u64)];

    // Nullifiers must differ (circuit enforces null0 != null1).
    let mut input_nullifiers = [Fr::from(0u64); N_INS];
    for i in 0..N_INS {
        let pubkey = hash1(&in_private_keys[i]);
        let commitment = hash4(&in_amounts[i], &pubkey, &in_blindings[i], &vortex);
        let signature = hash3(&in_private_keys[i], &commitment, &in_path_indices[i]);
        input_nullifiers[i] = hash3(&commitment, &in_path_indices[i], &signature);
    }

    // ---- Output notes that sum to `amount` ----
    let out_private_keys = [Fr::from(11_111u64), Fr::from(22_222u64)];
    let out_public_keys = [hash1(&out_private_keys[0]), hash1(&out_private_keys[1])];
    let out_amounts = [Fr::from(out0_amount), Fr::from(out1_amount)];
    let out_blindings = [Fr::from(777u64), Fr::from(666u64)];

    let mut output_commitments = [Fr::from(0u64); N_OUTS];
    for i in 0..N_OUTS {
        output_commitments[i] = hash4(
            &out_amounts[i],
            &out_public_keys[i],
            &out_blindings[i],
            &vortex,
        );
    }

    let notes = [
        OutputNote {
            amount: out_amounts[0],
            private_key: out_private_keys[0],
            public_key: out_public_keys[0],
            blinding: out_blindings[0],
            commitment: output_commitments[0],
        },
        OutputNote {
            amount: out_amounts[1],
            private_key: out_private_keys[1],
            public_key: out_public_keys[1],
            blinding: out_blindings[1],
            commitment: output_commitments[1],
        },
    ];

    // ---- Account secret: ZERO for the unsponsored `transact` path, so the
    // public input [7] hashed_secret == 0 (matching proof.move::public_inputs,
    // which passes bcs::to_bytes(&0u256)). With hashed_account_secret == 0 the
    // circuit skips the secret-equality check.
    let account_secret = Fr::from(0u64);
    let hashed_account_secret = Fr::from(0u64);

    // DEPOSIT: value flows INTO the pool, so public_amount == +amount and
    // sum_ins(0) + public_amount == sum_outs(amount).
    let public_amount = Fr::from(amount);

    let merkle_paths: [Path<MERKLE_TREE_LEVEL>; N_INS] = [Path::empty(), Path::empty()];

    let circuit = TransactionCircuit::new(
        vortex,
        root,
        public_amount,
        input_nullifiers[0],
        input_nullifiers[1],
        output_commitments[0],
        output_commitments[1],
        hashed_account_secret,
        account_secret,
        in_private_keys,
        in_amounts,
        in_blindings,
        in_path_indices,
        merkle_paths,
        out_public_keys,
        out_amounts,
        out_blindings,
    )?;
    Ok((circuit, notes))
}

/// Persist the proving key (arkworks compressed) to `proving_key.bin` and the
/// verifying key (arkworks compressed — the exact bytes Sui's
/// `groth16::prepare_verifying_key` consumes) to both `verifying_key.bin` and
/// `vk_sui.hex`.
pub fn save_keys(
    dir: &std::path::Path,
    pk: &ProvingKey<Bn254>,
    vk: &VerifyingKey<Bn254>,
) -> anyhow::Result<String> {
    std::fs::create_dir_all(dir)?;

    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes)?;
    std::fs::write(dir.join("proving_key.bin"), &pk_bytes)?;

    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)?;
    std::fs::write(dir.join("verifying_key.bin"), &vk_bytes)?;
    let vk_h = hex::encode(&vk_bytes);
    std::fs::write(dir.join("vk_sui.hex"), &vk_h)?;
    Ok(vk_h)
}

/// Load the persisted proving + verifying keys from `dir` (reads
/// `proving_key.bin` and `verifying_key.bin`, both arkworks compressed).
pub fn load_keys(
    dir: &std::path::Path,
) -> anyhow::Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>)> {
    let pk_bytes = std::fs::read(dir.join("proving_key.bin")).map_err(|e| {
        anyhow::anyhow!(
            "cannot read {} ({e}). Run `cargo run --bin keygen` first.",
            dir.join("proving_key.bin").display()
        )
    })?;
    let pk = ProvingKey::<Bn254>::deserialize_compressed(&pk_bytes[..])?;
    let vk = pk.vk.clone();
    Ok((pk, vk))
}

/// Prove a deposit with the given (already-set-up) proving key.
pub fn prove_deposit(
    pk: &ProvingKey<Bn254>,
    circuit: TransactionCircuit,
) -> anyhow::Result<(Proof<Bn254>, Vec<Fr>)> {
    let public_inputs = circuit.get_public_inputs();
    // Real OS entropy for proof randomness — NOT a zero seed.
    let mut rng = OsRng;
    let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
        .map_err(|e| anyhow::anyhow!("Groth16 prove failed: {e}"))?;
    Ok((proof, public_inputs))
}

/// `vk_hex` — arkworks compressed verifying key (== Sui's expected vk bytes).
pub fn vk_hex(vk: &VerifyingKey<Bn254>) -> anyhow::Result<String> {
    let mut bytes = Vec::new();
    vk.serialize_compressed(&mut bytes)?;
    Ok(hex::encode(bytes))
}

/// `proof_hex` — proofA(32B G1) ‖ proofB(64B G2) ‖ proofC(32B G1), all
/// arkworks-compressed, matching `groth16::proof_points_from_bytes`.
pub fn proof_hex(proof: &Proof<Bn254>) -> anyhow::Result<String> {
    let mut a = Vec::new();
    proof.a.serialize_compressed(&mut a)?;
    let mut b = Vec::new();
    proof.b.serialize_compressed(&mut b)?;
    let mut c = Vec::new();
    proof.c.serialize_compressed(&mut c)?;
    debug_assert_eq!(a.len(), 32, "proofA must be 32 bytes (compressed G1)");
    debug_assert_eq!(b.len(), 64, "proofB must be 64 bytes (compressed G2)");
    debug_assert_eq!(c.len(), 32, "proofC must be 32 bytes (compressed G1)");
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&a);
    out.extend_from_slice(&b);
    out.extend_from_slice(&c);
    Ok(hex::encode(out))
}

/// `public_inputs_hex` — each field element as a 32-byte LITTLE-ENDIAN integer,
/// concatenated in allocation order. This matches Move's
/// `bcs::to_bytes(&u256)` encoding used in `vortex_proof::make_public_inputs`.
pub fn public_inputs_hex(public_inputs: &[Fr]) -> String {
    let mut out = Vec::with_capacity(public_inputs.len() * 32);
    for fe in public_inputs {
        let mut le = fe.into_bigint().to_bytes_le();
        le.resize(32, 0u8); // pad/truncate to exactly 32 bytes
        out.extend_from_slice(&le);
    }
    hex::encode(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_groth16::prepare_verifying_key;
    use ark_relations::r1cs::ConstraintSynthesizer;
    use ark_relations::r1cs::ConstraintSystem;

    /// End-to-end: DEV setup -> deposit witness -> real proof -> native verify
    /// == true. Then print the three Sui-format hex artifacts.
    #[test]
    fn deposit_proof_verifies_and_prints_artifacts() {
        // 1) DEV keys (real entropy, NOT a ceremony).
        let (pk, vk) = dev_setup().expect("dev setup");

        // 2) Deposit of 1000 split into output notes 600 + 400.
        let circuit = build_deposit_circuit(1000, 600, 400).expect("build deposit");

        // Sanity: constraints are satisfiable before proving.
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "deposit witness must satisfy constraints (which: {:?})",
            cs.which_is_unsatisfied()
        );

        // 3) Prove.
        let (proof, public_inputs) = prove_deposit(&pk, circuit).expect("prove");
        assert_eq!(public_inputs.len(), 8, "8 public inputs expected");

        // 4) Native Groth16 verify == true.
        let pvk = prepare_verifying_key(&vk);
        let ok = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs).expect("verify");
        assert!(ok, "deposit proof MUST verify against its public inputs");

        // 5) Serialize to Sui format + print.
        let vk_h = vk_hex(&vk).expect("vk hex");
        let proof_h = proof_hex(&proof).expect("proof hex");
        let pubs_h = public_inputs_hex(&public_inputs);

        println!("\n================ TALISE PRIVACY — DEPOSIT PROOF ARTIFACTS ================");
        println!("(DEV/TEST keys, real-entropy OsRng proof; NOT a trusted-setup ceremony)\n");
        println!("public_inputs (decimal, allocation order [pool,root,public_value,null0,null1,comm0,comm1,hashed_secret]):");
        let labels = [
            "pool/vortex",
            "root",
            "public_value",
            "null0",
            "null1",
            "comm0",
            "comm1",
            "hashed_secret",
        ];
        for (l, fe) in labels.iter().zip(public_inputs.iter()) {
            println!("  {l:>14} = {}", fe.into_bigint());
        }
        println!("\nvk_hex (len {} bytes):\n{vk_h}", vk_h.len() / 2);
        println!("\nproof_hex (len {} bytes):\n{proof_h}", proof_h.len() / 2);
        println!(
            "\npublic_inputs_hex (len {} bytes, 8 x 32B LE):\n{pubs_h}",
            pubs_h.len() / 2
        );
        println!("=========================================================================\n");
    }

    /// NEGATIVE: a value-conservation-violating witness must FAIL to verify.
    ///
    /// We prove an honest deposit (so the proof is well-formed) but then verify
    /// it against TAMPERED public inputs in which `public_value` no longer
    /// matches the output sum — i.e. value is not conserved. Groth16 must
    /// reject. We also assert the constraint system itself rejects an
    /// inconsistent witness (outputs sum to more than public_amount).
    #[test]
    fn value_conservation_violation_fails() {
        // (a) Constraint-level: outputs (600+500=1100) != public_amount (1000).
        let bad = build_deposit_circuit(1000, 600, 500).expect("build");
        let cs = ConstraintSystem::<Fr>::new_ref();
        bad.generate_constraints(cs.clone()).unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "non-conserving witness (out sum 1100 != public 1000) must NOT satisfy constraints"
        );

        // (b) Verifier-level: honest proof, but tampered public_value rejects.
        let (pk, vk) = dev_setup().expect("dev setup");
        let circuit = build_deposit_circuit(1000, 600, 400).expect("build");
        let (proof, mut public_inputs) = prove_deposit(&pk, circuit).expect("prove");

        // public_inputs[2] is `public_value`; bump it so conservation is broken.
        public_inputs[2] = Fr::from(9999u64);

        let pvk = prepare_verifying_key(&vk);
        let ok = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs).expect("verify call");
        assert!(
            !ok,
            "proof MUST NOT verify against tampered (non-conserving) public inputs"
        );
    }
}
