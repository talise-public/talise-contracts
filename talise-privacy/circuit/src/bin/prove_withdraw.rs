//! One-shot WITHDRAW proof generator for a SPECIFIC live testnet note.
//!
//! Completes a deposit -> withdraw round-trip on the Talise privacy pool:
//!   1. Reconstruct the height-26 Merkle tree by inserting the deposit's two
//!      output leaves as an `append_pair` pair (leaf0 = note0.commitment,
//!      leaf1 = the sibling commitment), generate the membership proof for
//!      leaf_index 0, and ASSERT the reconstructed root == the CURRENT on-chain
//!      root. If it does not match, STOP (the path/root logic is wrong).
//!   2. Build a WITHDRAW witness: input0 = note0 (with its Merkle path),
//!      input1 = a distinct dummy/zero note (distinct privkey + path_index so the
//!      circuit's null0 != null1 constraint holds); outputs = a zero change note
//!      + a dummy zero note (Sum_out = 0); public_amount = field-negated 1000
//!      (= bn254_modulus - 1000). Value conservation: Sum_in(1000+0) +
//!      public_amount(-1000) == Sum_out(0).
//!   3. Prove against the PERSISTED dev keys (keys/) and assert native
//!      Groth16::verify == PASS.
//!   4. Serialize to Sui format and PRINT proof_hex + the public inputs.
//!
//! All note/leaf/pool/root values are HARDCODED below — this is a one-shot for
//! the live note, not a CLI.

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::{AdditiveGroup, PrimeField};
use ark_groth16::{prepare_verifying_key, Groth16};
use num_bigint::BigUint;
use std::path::Path as FsPath;
use std::str::FromStr;

use talise_privacy_circuit::circuit::TransactionCircuit;
use talise_privacy_circuit::constants::{MERKLE_TREE_LEVEL, ZERO_VALUE};
use talise_privacy_circuit::merkle_tree::{Path, SparseMerkleTree};
use talise_privacy_circuit::poseidon_opt::{hash1, hash3, hash4, PoseidonOptimized};
use talise_privacy_circuit::prover::{
    pool_address_to_field, proof_hex, public_inputs_hex, vk_hex,
};

// ---- HARDCODED live-note parameters --------------------------------------

// note0 — the note we SPEND (leaf index 0).
const NOTE0_AMOUNT: u64 = 1000;
const NOTE0_PRIVATE_KEY: u64 = 11111;
const NOTE0_PUBLIC_KEY: &str =
    "2659885370391636708883459370353623141128982085472165018711164208023811132296";
const NOTE0_BLINDING: u64 = 777;
const NOTE0_COMMITMENT: &str =
    "16025398816562393846027294915624766422017989278198686121729746063548402125175";

// leaf1 — the sibling output note (leaf index 1). Only its commitment matters
// for tree reconstruction.
const LEAF1_COMMITMENT: &str =
    "21740237432543765272726675587868228223450939191577005892743806289395975245876";

// Pool address — must map (via pool_address_to_field) to the same field element
// proof.move's make_public_inputs supplies as public input [0].
const POOL_ADDRESS: &str =
    "0x5ebf860dd79cce9938f491cb9085ab77248633cf766b2a9086d6b667eff0bec5";

// The CURRENT on-chain Merkle root AFTER the deposit (decimal u256).
const ON_CHAIN_ROOT: &str =
    "904454796191478882308201711682734251705910396975487455112623170491392086438";

fn fr_dec(s: &str) -> Fr {
    Fr::from(BigUint::from_str(s).expect("decimal field element"))
}

fn main() -> anyhow::Result<()> {
    let hasher = PoseidonOptimized::new_t3();
    let empty_leaf = fr_dec(ZERO_VALUE);

    // Pool domain separator (== public input [0] / the `vortex` commitment salt).
    let vortex = pool_address_to_field(POOL_ADDRESS)?;

    // ---- note0 secret material + sanity-check its commitment ----
    let note0_privkey = Fr::from(NOTE0_PRIVATE_KEY);
    let note0_pubkey = fr_dec(NOTE0_PUBLIC_KEY);
    let note0_amount = Fr::from(NOTE0_AMOUNT);
    let note0_blinding = Fr::from(NOTE0_BLINDING);
    let note0_commitment = fr_dec(NOTE0_COMMITMENT);

    // public_key must be hash1(private_key) for the circuit to accept note0.
    let derived_pubkey = hash1(&note0_privkey);
    assert_eq!(
        derived_pubkey, note0_pubkey,
        "note0 public_key != hash1(private_key) — secret material is inconsistent"
    );
    // commitment must be hash4(amount, pubkey, blinding, pool_field).
    let derived_commitment = hash4(&note0_amount, &note0_pubkey, &note0_blinding, &vortex);
    assert_eq!(
        derived_commitment, note0_commitment,
        "note0 commitment != hash4(amount, pubkey, blinding, pool_field) — inconsistent"
    );

    let leaf1_commitment = fr_dec(LEAF1_COMMITMENT);

    // ============================================================
    // STEP 1 — reconstruct the height-26 tree and prove leaf_index 0
    // ============================================================
    let mut tree = SparseMerkleTree::<MERKLE_TREE_LEVEL>::new_empty(&hasher, &empty_leaf);
    tree.insert_pair(note0_commitment, leaf1_commitment, &hasher)?;

    let reconstructed_root = tree.root();
    let expected_root = fr_dec(ON_CHAIN_ROOT);

    let root_matches = reconstructed_root == expected_root;
    println!("\n================ TALISE PRIVACY — WITHDRAW PROOF (live note) ================");
    println!("STEP 1: reconstruct height-{MERKLE_TREE_LEVEL} tree + membership proof for leaf_index 0");
    println!("  reconstructed_root = {}", reconstructed_root.into_bigint());
    println!("  on-chain root      = {}", expected_root.into_bigint());
    println!(
        "  ROOT MATCH         = {}",
        if root_matches { "PASS" } else { "FAIL" }
    );
    if !root_matches {
        anyhow::bail!(
            "STOP: reconstructed root != on-chain root. The path/root logic is wrong; \
             refusing to build a withdraw proof."
        );
    }

    // Membership proof (the (left,right) path) for leaf_index 0.
    let note0_path: Path<MERKLE_TREE_LEVEL> = tree.generate_membership_proof(0)?;
    // Native cross-check: this path recomputes the same root from note0.commitment.
    let path_root = note0_path.calculate_root(&note0_commitment, &hasher)?;
    assert_eq!(
        path_root, expected_root,
        "membership path for leaf 0 does not recompute the on-chain root"
    );
    println!("  membership path for leaf 0 recomputes on-chain root: PASS");

    // ============================================================
    // STEP 2 — build the WITHDRAW witness
    // ============================================================
    // input0 = note0 (real, with its Merkle path); path_index 0 (leaf index 0).
    let in0_privkey = note0_privkey;
    let in0_amount = note0_amount;
    let in0_blinding = note0_blinding;
    let in0_path_index = Fr::from(0u64);

    // input1 = DISTINCT dummy/zero note. Distinct privkey + blinding + path_index
    // keeps its nullifier != input0's null0 AND != the two dummy nullifiers the
    // earlier DEPOSIT already spent on-chain:
    //   19306893375094906130145290570647688472812444657673703580568533254060123879721
    //   10934727888315732958434650750013928182351518452698175138581275617244293699909
    // The previous (privkey 67890, blinding 888, path_index 1) dummy COLLIDED with
    // the second value above => ENullifierAlreadySpent (803). Use a fresh privkey +
    // blinding + path_index 3 so the nullifier is distinct from all three. Amount 0
    // means its Merkle membership check is skipped (empty path is fine).
    let in1_privkey = Fr::from(0xDEAD_BEEFu64);
    let in1_amount = Fr::from(0u64);
    let in1_blinding = Fr::from(0xC0FF_EEu64);
    let in1_path_index = Fr::from(3u64);

    // Compute both input nullifiers exactly as the circuit does.
    let compute_nullifier = |privkey: &Fr, amount: &Fr, blinding: &Fr, path_index: &Fr| -> Fr {
        let pubkey = hash1(privkey);
        let commitment = hash4(amount, &pubkey, blinding, &vortex);
        let signature = hash3(privkey, &commitment, path_index);
        hash3(&commitment, path_index, &signature)
    };
    let null0 = compute_nullifier(&in0_privkey, &in0_amount, &in0_blinding, &in0_path_index);
    let null1 = compute_nullifier(&in1_privkey, &in1_amount, &in1_blinding, &in1_path_index);
    assert_ne!(null0, null1, "input nullifiers must be distinct");

    // The two dummy nullifiers the earlier DEPOSIT already spent on-chain. The new
    // withdraw dummy null1 MUST differ from both, or the submit aborts with
    // ENullifierAlreadySpent (803).
    let deposit_dummy_null_a = fr_dec(
        "19306893375094906130145290570647688472812444657673703580568533254060123879721",
    );
    let deposit_dummy_null_b = fr_dec(
        "10934727888315732958434650750013928182351518452698175138581275617244293699909",
    );
    assert_ne!(
        null1, deposit_dummy_null_a,
        "null1 collides with deposit dummy nullifier A (already spent)"
    );
    assert_ne!(
        null1, deposit_dummy_null_b,
        "null1 collides with deposit dummy nullifier B (already spent)"
    );

    // outputs: a zero change note (out0) + a dummy zero note (out1). Sum_out = 0.
    let out0_privkey = Fr::from(11_111u64);
    let out0_pubkey = hash1(&out0_privkey);
    let out0_amount = Fr::from(0u64);
    let out0_blinding = Fr::from(555u64);
    let comm0 = hash4(&out0_amount, &out0_pubkey, &out0_blinding, &vortex);

    let out1_privkey = Fr::from(22_222u64);
    let out1_pubkey = hash1(&out1_privkey);
    let out1_amount = Fr::from(0u64);
    let out1_blinding = Fr::from(444u64);
    let comm1 = hash4(&out1_amount, &out1_pubkey, &out1_blinding, &vortex);

    // WITHDRAW: value flows OUT of the pool. public_amount is field-negated:
    // bn254_modulus - 1000  ==  Fr(0) - Fr(1000).
    let public_amount = Fr::ZERO - Fr::from(NOTE0_AMOUNT);
    // Conservation sanity (in-field): sum_ins + public_amount == sum_outs.
    debug_assert_eq!(
        (in0_amount + in1_amount) + public_amount,
        out0_amount + out1_amount,
        "value conservation broken"
    );

    // account secret = 0 (unsponsored path) => hashed_account_secret == 0, check skipped.
    let account_secret = Fr::ZERO;
    let hashed_account_secret = Fr::ZERO;

    let merkle_paths: [Path<MERKLE_TREE_LEVEL>; 2] = [note0_path, Path::empty()];

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
    let (pk, vk) = talise_privacy_circuit::prover::load_keys(FsPath::new("keys"))?;
    let public_inputs = circuit.get_public_inputs();
    let mut rng = rand::rngs::OsRng;
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
        anyhow::bail!("FATAL: withdraw proof did NOT verify against persisted VK");
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
    println!("public inputs (order [pool,root,public_value,null0,null1,comm0,comm1,hashed_secret]):");
    for (l, fe) in labels.iter().zip(public_inputs.iter()) {
        println!("  {l:>14} = {}", fe.into_bigint());
    }

    println!("\n--- the 5 caller-requested decimals ---");
    println!("public_value (field-negated 1000) = {}", public_amount.into_bigint());
    println!("null0  = {}", null0.into_bigint());
    println!("null1  = {}", null1.into_bigint());
    println!("comm0  = {}", comm0.into_bigint());
    println!("comm1  = {}", comm1.into_bigint());

    println!("\nproof_hex (len {} bytes, A32|B64|C32 compressed):\n0x{proof_h}", proof_h.len() / 2);
    println!(
        "\npublic_inputs_hex (len {} bytes, 8 x 32B LE):\n0x{pubs_h}",
        pubs_h.len() / 2
    );
    println!("\nvk_sui.hex (len {} bytes):\n0x{vk_h}", vk_h.len() / 2);
    println!("============================================================================\n");

    Ok(())
}
