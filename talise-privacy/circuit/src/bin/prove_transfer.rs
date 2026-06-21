//! CLI TRANSFER proof generator for the Talise privacy pool.
//!
//! A private TRANSFER spends ONE real input note (proven against the current
//! on-chain Merkle root via its height-26 membership path) and creates TWO fresh
//! output notes whose amounts sum to the input amount. NO coins move in or out of
//! the pool — value stays shielded — so `public_amount == 0`.
//!
//!   1. Reconstruct the height-26 tree from ALL current leaf commitments
//!      (`--leaves`, inserted in pairs exactly as the on-chain `append_pair`
//!      does), generate the membership proof for `--in-leaf-index`, and ASSERT the
//!      reconstructed root == the supplied `--root`. If it mismatches, STOP.
//!   2. Build the TRANSFER witness:
//!        input0 = the REAL note (with its Merkle path),
//!        input1 = a DUMMY zero note with a RANDOM privkey + RANDOM blinding + a
//!                 distinct path_index (so its nullifier is fresh: distinct from
//!                 input0's and distinct from anything in the on-chain spent-set —
//!                 the bug that bit the withdraw),
//!        outputs = note(out0) + note(out1) with FRESH RANDOM blindings,
//!        public_amount = 0, conservation: in_amount + 0 == out0 + out1.
//!   3. Prove against the PERSISTED keys (keys/) and assert native
//!      Groth16::verify == PASS.
//!   4. PRINT proof_hex + the public inputs (decimal) in order
//!      [pool, root, public_value(=0), null0, null1, comm0, comm1, hashed_secret]
//!      AND the two OUTPUT note secrets (so they can be spent/withdrawn later).
//!
//! Usage:
//!   cargo run --release --bin prove_transfer -- \
//!       --pool 0x<addr> --root <u256dec> \
//!       --leaves <c0>,<c1>,<c2>,... \
//!       --in-privkey <u256dec> --in-amount <u64> \
//!       --in-blinding <u256dec> --in-leaf-index <usize> \
//!       [--out0 <u64> --out1 <u64>]   (default split: in-amount, 0)
//!
//! Public input order (matches circuit allocation + proof.move):
//!   [pool, root, public_value, null0, null1, comm0, comm1, hashed_secret]

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::{prepare_verifying_key, Groth16};
use num_bigint::BigUint;
use rand::rngs::OsRng;
use std::path::Path as FsPath;
use std::str::FromStr;

use talise_privacy_circuit::circuit::TransactionCircuit;
use talise_privacy_circuit::constants::{MERKLE_TREE_LEVEL, ZERO_VALUE};
use talise_privacy_circuit::merkle_tree::{Path, SparseMerkleTree};
use talise_privacy_circuit::poseidon_opt::{hash1, hash3, hash4, PoseidonOptimized};
use talise_privacy_circuit::prover::{
    pool_address_to_field, proof_hex, public_inputs_hex, u256_decimal_to_field, vk_hex,
};

struct Args {
    pool: String,
    root: String,
    leaves: Vec<String>,
    in_privkey: String,
    in_amount: u64,
    in_blinding: String,
    in_leaf_index: usize,
    out0: Option<u64>,
    out1: Option<u64>,
    keys_dir: String,
}

fn parse_args() -> anyhow::Result<Args> {
    let mut pool = None;
    let mut root = None;
    let mut leaves = None;
    let mut in_privkey = None;
    let mut in_amount = None;
    let mut in_blinding = None;
    let mut in_leaf_index = None;
    let mut out0 = None;
    let mut out1 = None;
    let mut keys_dir = "keys".to_string();

    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut next = |name: &str| -> anyhow::Result<String> {
            it.next().ok_or_else(|| anyhow::anyhow!("{name} needs a value"))
        };
        match a.as_str() {
            "--pool" => pool = Some(next("--pool")?),
            "--root" => root = Some(next("--root")?),
            "--leaves" => {
                let s = next("--leaves")?;
                let v: Vec<String> = s
                    .split(',')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect();
                leaves = Some(v);
            }
            "--in-privkey" => in_privkey = Some(next("--in-privkey")?),
            "--in-amount" => in_amount = Some(next("--in-amount")?.parse::<u64>()?),
            "--in-blinding" => in_blinding = Some(next("--in-blinding")?),
            "--in-leaf-index" => in_leaf_index = Some(next("--in-leaf-index")?.parse::<usize>()?),
            "--out0" => out0 = Some(next("--out0")?.parse::<u64>()?),
            "--out1" => out1 = Some(next("--out1")?.parse::<u64>()?),
            "--keys-dir" => keys_dir = next("--keys-dir")?,
            "-h" | "--help" => {
                println!(
                    "Usage: prove_transfer --pool <0xADDR> --root <u256dec> \
                     --leaves <c0>,<c1>,... \
                     --in-privkey <u256dec> --in-amount <u64> --in-blinding <u256dec> \
                     --in-leaf-index <usize> [--out0 <a> --out1 <b>] [--keys-dir <dir>]"
                );
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown arg: {other}"),
        }
    }

    Ok(Args {
        pool: pool.ok_or_else(|| anyhow::anyhow!("--pool is required"))?,
        root: root.ok_or_else(|| anyhow::anyhow!("--root is required"))?,
        leaves: leaves.ok_or_else(|| anyhow::anyhow!("--leaves is required"))?,
        in_privkey: in_privkey.ok_or_else(|| anyhow::anyhow!("--in-privkey is required"))?,
        in_amount: in_amount.ok_or_else(|| anyhow::anyhow!("--in-amount is required"))?,
        in_blinding: in_blinding.ok_or_else(|| anyhow::anyhow!("--in-blinding is required"))?,
        in_leaf_index: in_leaf_index
            .ok_or_else(|| anyhow::anyhow!("--in-leaf-index is required"))?,
        out0,
        out1,
        keys_dir,
    })
}

fn fr_dec(s: &str) -> anyhow::Result<Fr> {
    Ok(Fr::from(
        BigUint::from_str(s.trim())
            .map_err(|_| anyhow::anyhow!("not a valid decimal field element: {s}"))?,
    ))
}

/// Compute a nullifier exactly as the circuit does:
///   pubkey    = hash1(privkey)
///   commitment= hash4(amount, pubkey, blinding, vortex)
///   signature = hash3(privkey, commitment, path_index)
///   nullifier = hash3(commitment, path_index, signature)
fn compute_nullifier(privkey: &Fr, amount: &Fr, blinding: &Fr, path_index: &Fr, vortex: &Fr) -> Fr {
    let pubkey = hash1(privkey);
    let commitment = hash4(amount, &pubkey, blinding, vortex);
    let signature = hash3(privkey, &commitment, path_index);
    hash3(&commitment, path_index, &signature)
}

fn main() -> anyhow::Result<()> {
    let args = parse_args()?;

    // Output split: default full amount in out0, 0 in out1.
    let out0 = args.out0.unwrap_or(args.in_amount);
    let out1 = args.out1.unwrap_or(0);
    if out0.checked_add(out1) != Some(args.in_amount) {
        anyhow::bail!(
            "output split {out0}+{out1} must sum to in-amount {} (value conservation)",
            args.in_amount
        );
    }
    if args.in_amount == 0 {
        anyhow::bail!("--in-amount must be non-zero for a TRANSFER (the input note must have value)");
    }

    let hasher = PoseidonOptimized::new_t3();
    let empty_leaf = fr_dec(ZERO_VALUE)?;

    // Public input [0]: pool address -> field element.
    let vortex = pool_address_to_field(&args.pool)?;
    // Public input [1]: the on-chain root we prove against.
    let expected_root = u256_decimal_to_field(&args.root)?;

    // ---- Input note secret material ----
    let in0_privkey = fr_dec(&args.in_privkey)?;
    let in0_amount = Fr::from(args.in_amount);
    let in0_blinding = fr_dec(&args.in_blinding)?;
    let in0_pubkey = hash1(&in0_privkey);
    let in0_commitment = hash4(&in0_amount, &in0_pubkey, &in0_blinding, &vortex);

    // ============================================================
    // STEP 1 — reconstruct the height-26 tree from --leaves
    // ============================================================
    if args.leaves.len() % 2 != 0 {
        anyhow::bail!(
            "--leaves has {} entries; the on-chain tree is appended in PAIRS, so the leaf \
             count must be even. Include the dummy/sibling commitment(s) too.",
            args.leaves.len()
        );
    }
    if args.in_leaf_index >= args.leaves.len() {
        anyhow::bail!(
            "--in-leaf-index {} out of bounds ({} leaves supplied)",
            args.in_leaf_index,
            args.leaves.len()
        );
    }

    let leaf_fields: Vec<Fr> = args
        .leaves
        .iter()
        .map(|s| fr_dec(s))
        .collect::<anyhow::Result<Vec<_>>>()?;

    // Sanity: the supplied leaf at --in-leaf-index must equal the input note's
    // commitment (otherwise the secret material doesn't match the tree).
    if leaf_fields[args.in_leaf_index] != in0_commitment {
        anyhow::bail!(
            "leaf at --in-leaf-index {} ({}) != input note commitment ({}). The input \
             secret material does not match the tree leaf at that index.",
            args.in_leaf_index,
            leaf_fields[args.in_leaf_index].into_bigint(),
            in0_commitment.into_bigint()
        );
    }

    let mut tree = SparseMerkleTree::<MERKLE_TREE_LEVEL>::new_empty(&hasher, &empty_leaf);
    for pair in leaf_fields.chunks(2) {
        tree.insert_pair(pair[0], pair[1], &hasher)?;
    }

    let reconstructed_root = tree.root();
    let root_matches = reconstructed_root == expected_root;

    println!("\n================ TALISE PRIVACY — TRANSFER PROOF (CLI) ================");
    println!("STEP 1: reconstruct height-{MERKLE_TREE_LEVEL} tree + membership proof for leaf_index {}", args.in_leaf_index);
    println!("  leaves supplied    = {}", leaf_fields.len());
    println!("  reconstructed_root = {}", reconstructed_root.into_bigint());
    println!("  on-chain root      = {}", expected_root.into_bigint());
    println!(
        "  ROOT MATCH         = {}",
        if root_matches { "PASS" } else { "FAIL" }
    );
    if !root_matches {
        anyhow::bail!(
            "STOP: reconstructed root != supplied --root. The leaves/index/root do not agree; \
             refusing to build a transfer proof."
        );
    }

    // Membership path for the input leaf.
    let in0_path: Path<MERKLE_TREE_LEVEL> = tree.generate_membership_proof(args.in_leaf_index)?;
    let path_root = in0_path.calculate_root(&in0_commitment, &hasher)?;
    if path_root != expected_root {
        anyhow::bail!(
            "membership path for leaf {} does not recompute the on-chain root",
            args.in_leaf_index
        );
    }
    println!("  membership path recomputes on-chain root: PASS");

    // ============================================================
    // STEP 2 — build the TRANSFER witness
    // ============================================================
    let mut rng = OsRng;

    // input0 = real note. path_index == leaf index in the tree.
    let in0_path_index = Fr::from(args.in_leaf_index as u64);

    // input1 = DUMMY zero note. Random privkey + random blinding + a DISTINCT
    // path_index keep its nullifier fresh (distinct from null0 and from anything
    // in the on-chain spent-set). Amount 0 => its Merkle membership check is
    // skipped, so the empty path is fine.
    let in1_privkey = Fr::rand(&mut rng);
    let in1_amount = Fr::from(0u64);
    let in1_blinding = Fr::rand(&mut rng);
    // Pick a path_index distinct from the real input's (and well within 2^26).
    // Use index 0 unless the real note is AT index 0, in which case use 1.
    let in1_path_index = if args.in_leaf_index == 0 {
        Fr::from(1u64)
    } else {
        Fr::from(0u64)
    };

    let null0 = compute_nullifier(&in0_privkey, &in0_amount, &in0_blinding, &in0_path_index, &vortex);
    let null1 = compute_nullifier(&in1_privkey, &in1_amount, &in1_blinding, &in1_path_index, &vortex);
    assert_ne!(null0, null1, "input nullifiers must be distinct");

    // outputs: two fresh notes summing to in-amount, with RANDOM privkeys +
    // RANDOM blindings (so reruns don't collide and the notes are spendable).
    let out0_privkey = Fr::rand(&mut rng);
    let out0_pubkey = hash1(&out0_privkey);
    let out0_amount = Fr::from(out0);
    let out0_blinding = Fr::rand(&mut rng);
    let comm0 = hash4(&out0_amount, &out0_pubkey, &out0_blinding, &vortex);

    let out1_privkey = Fr::rand(&mut rng);
    let out1_pubkey = hash1(&out1_privkey);
    let out1_amount = Fr::from(out1);
    let out1_blinding = Fr::rand(&mut rng);
    let comm1 = hash4(&out1_amount, &out1_pubkey, &out1_blinding, &vortex);

    // TRANSFER: no coins move => public_amount == 0.
    let public_amount = Fr::from(0u64);
    // Conservation sanity: sum_ins + public_amount == sum_outs.
    debug_assert_eq!(
        (in0_amount + in1_amount) + public_amount,
        out0_amount + out1_amount,
        "value conservation broken"
    );

    // Unsponsored path: account secret = 0 => hashed_secret == 0, check skipped.
    let account_secret = Fr::from(0u64);
    let hashed_account_secret = Fr::from(0u64);

    let merkle_paths: [Path<MERKLE_TREE_LEVEL>; 2] = [in0_path, Path::empty()];

    let circuit = TransactionCircuit::new(
        vortex,
        expected_root,
        public_amount,
        null0,
        null1,
        comm0,
        comm1,
        hashed_account_secret,
        account_secret,
        [in0_privkey, in1_privkey],
        [in0_amount, in1_amount],
        [in0_blinding, in1_blinding],
        [in0_path_index, in1_path_index],
        merkle_paths,
        [out0_pubkey, out1_pubkey],
        [out0_amount, out1_amount],
        [out0_blinding, out1_blinding],
    )?;

    // ============================================================
    // STEP 3 — prove against persisted keys + native verify
    // ============================================================
    let (pk, vk) = talise_privacy_circuit::prover::load_keys(FsPath::new(&args.keys_dir))?;
    let public_inputs = circuit.get_public_inputs();
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)
        .map_err(|e| anyhow::anyhow!("Groth16 prove failed: {e}"))?;

    let pvk = prepare_verifying_key(&vk);
    let ok = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs)
        .map_err(|e| anyhow::anyhow!("verify call failed: {e}"))?;
    println!(
        "\nSTEP 3: native Groth16 verify against persisted VK: {}",
        if ok { "PASS" } else { "FAIL" }
    );
    if !ok {
        anyhow::bail!("FATAL: transfer proof did NOT verify against persisted VK");
    }

    // ============================================================
    // STEP 4 — serialize to Sui format and print
    // ============================================================
    let proof_h = proof_hex(&proof)?;
    let pubs_h = public_inputs_hex(&public_inputs);
    let vk_h = vk_hex(&vk)?;

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

    println!("\nSTEP 4: Sui-format artifacts (decimal + hex)\n");
    println!("inputs:");
    println!("  pool      = {}", args.pool);
    println!("  root      = {} (decimal u256)", args.root);
    println!("  in-amount = {}", args.in_amount);
    println!("  split     = {out0} + {out1}");
    println!("  in-leaf   = index {}\n", args.in_leaf_index);

    println!("public inputs (order [pool,root,public_value,null0,null1,comm0,comm1,hashed_secret]):");
    for (l, fe) in labels.iter().zip(public_inputs.iter()) {
        println!("  {l:>14} = {}", fe.into_bigint());
    }

    println!("\noutput notes (decimal — KEEP THESE to spend/withdraw later):");
    let out_notes = [
        ("note0", out0_amount, out0_privkey, out0_pubkey, out0_blinding, comm0),
        ("note1", out1_amount, out1_privkey, out1_pubkey, out1_blinding, comm1),
    ];
    for (name, amount, privkey, pubkey, blinding, commitment) in out_notes.iter() {
        println!("  {name}:");
        println!("    amount      = {}", amount.into_bigint());
        println!("    private_key = {}", privkey.into_bigint());
        println!("    public_key  = {}", pubkey.into_bigint());
        println!("    blinding    = {}", blinding.into_bigint());
        println!("    commitment  = {}", commitment.into_bigint());
    }
    println!("  (note commitment = Poseidon4(amount, public_key, blinding, pool_field))");

    println!("\nproof_hex (len {} bytes, A32|B64|C32 compressed):\n0x{proof_h}", proof_h.len() / 2);
    println!(
        "\npublic_inputs_hex (len {} bytes, 8 x 32B LE):\n0x{pubs_h}",
        pubs_h.len() / 2
    );
    println!("\nvk_sui.hex (len {} bytes):\n0x{vk_h}", vk_h.len() / 2);
    println!("======================================================================\n");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

    /// Self-test: fabricate a small tree, build a real TRANSFER witness exactly
    /// like `main` does (1 real input + 1 dummy, 2 outputs, public_amount = 0),
    /// confirm the constraint system is satisfied, then DEV-setup + prove + native
    /// verify == PASS. This exercises the full transfer logic without needing the
    /// persisted keys or any on-chain state.
    #[test]
    fn transfer_self_test_proves_and_verifies() {
        let hasher = PoseidonOptimized::new_t3();
        let empty_leaf = fr_dec(ZERO_VALUE).unwrap();
        let vortex = Fr::from(7u64); // arbitrary pool domain separator

        // --- A real input note worth 1000 at leaf index 2 ---
        let in_amount = 1000u64;
        let in0_privkey = Fr::from(424242u64);
        let in0_amount = Fr::from(in_amount);
        let in0_blinding = Fr::from(13579u64);
        let in0_pubkey = hash1(&in0_privkey);
        let in0_commitment = hash4(&in0_amount, &in0_pubkey, &in0_blinding, &vortex);

        // Fabricate a tree with 4 leaves; the real note sits at index 2.
        let leaves = vec![
            Fr::from(111u64),
            Fr::from(222u64),
            in0_commitment,
            Fr::from(444u64),
        ];
        let in_leaf_index = 2usize;

        let mut tree = SparseMerkleTree::<MERKLE_TREE_LEVEL>::new_empty(&hasher, &empty_leaf);
        for pair in leaves.chunks(2) {
            tree.insert_pair(pair[0], pair[1], &hasher).unwrap();
        }
        let root = tree.root();

        let in0_path = tree.generate_membership_proof(in_leaf_index).unwrap();
        assert_eq!(
            in0_path.calculate_root(&in0_commitment, &hasher).unwrap(),
            root,
            "membership path must recompute the tree root"
        );

        // --- Build the transfer witness (split 600 + 400) ---
        let mut rng = OsRng;
        let in0_path_index = Fr::from(in_leaf_index as u64);

        let in1_privkey = Fr::rand(&mut rng);
        let in1_amount = Fr::from(0u64);
        let in1_blinding = Fr::rand(&mut rng);
        let in1_path_index = Fr::from(0u64); // distinct from index 2

        let null0 =
            compute_nullifier(&in0_privkey, &in0_amount, &in0_blinding, &in0_path_index, &vortex);
        let null1 =
            compute_nullifier(&in1_privkey, &in1_amount, &in1_blinding, &in1_path_index, &vortex);
        assert_ne!(null0, null1);

        let out0_privkey = Fr::rand(&mut rng);
        let out0_pubkey = hash1(&out0_privkey);
        let out0_amount = Fr::from(600u64);
        let out0_blinding = Fr::rand(&mut rng);
        let comm0 = hash4(&out0_amount, &out0_pubkey, &out0_blinding, &vortex);

        let out1_privkey = Fr::rand(&mut rng);
        let out1_pubkey = hash1(&out1_privkey);
        let out1_amount = Fr::from(400u64);
        let out1_blinding = Fr::rand(&mut rng);
        let comm1 = hash4(&out1_amount, &out1_pubkey, &out1_blinding, &vortex);

        let public_amount = Fr::from(0u64);

        let circuit = TransactionCircuit::new(
            vortex,
            root,
            public_amount,
            null0,
            null1,
            comm0,
            comm1,
            Fr::from(0u64),
            Fr::from(0u64),
            [in0_privkey, in1_privkey],
            [in0_amount, in1_amount],
            [in0_blinding, in1_blinding],
            [in0_path_index, in1_path_index],
            [in0_path, Path::empty()],
            [out0_pubkey, out1_pubkey],
            [out0_amount, out1_amount],
            [out0_blinding, out1_blinding],
        )
        .unwrap();

        // (a) Constraints satisfied.
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "transfer witness must satisfy constraints (which: {:?})",
            cs.which_is_unsatisfied()
        );

        // (b) DEV setup -> prove -> native verify == PASS.
        let (pk, vk) = talise_privacy_circuit::prover::dev_setup().unwrap();
        let public_inputs = circuit.get_public_inputs();
        assert_eq!(public_inputs.len(), 8);
        assert_eq!(public_inputs[2], Fr::from(0u64), "public_value must be 0 for a transfer");

        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        let pvk = prepare_verifying_key(&vk);
        let ok = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs).unwrap();
        assert!(ok, "transfer proof MUST verify against its public inputs");
    }
}
