//! MAINNET withdraw proof — spends note0 from the simulated mainnet deposit.
//!
//! Round-trip against the LIVE mainnet pool
//! (0x6bcd28763456db543d0c29acb34970b81e4d7f004d2581fce46b813ece8152c1):
//!   1. Reconstruct the height-26 tree by inserting the deposit's two output
//!      commitments (note0=200000, note1=0) as a pair → the POST-DEPOSIT root.
//!   2. Membership-prove leaf_index 0 (note0) into that root.
//!   3. Build a WITHDRAW of 200000 (field-negated public_value) bound to the
//!      mainnet pool; outputs are two zero notes (Sum_out = 0).
//!   4. Prove against persisted keys + native Groth16 verify == PASS.
//!   5. Print proof_hex + the 8 public inputs (decimal + LE hex).
//!
//! note0 secrets come straight from `prove_deposit --amount 200000` against the
//! live empty root, so this is the genuine spend of the simulated deposit.

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::{AdditiveGroup, PrimeField};
use ark_groth16::{prepare_verifying_key, Groth16};
use std::path::Path as FsPath;

use talise_privacy_circuit::circuit::TransactionCircuit;
use talise_privacy_circuit::constants::{MERKLE_TREE_LEVEL, ZERO_VALUE};
use talise_privacy_circuit::merkle_tree::{Path, SparseMerkleTree};
use talise_privacy_circuit::poseidon_opt::{hash1, hash3, hash4, PoseidonOptimized};
use talise_privacy_circuit::prover::{
    pool_address_to_field, proof_hex, public_inputs_hex, vk_hex,
};

const POOL_ADDRESS: &str =
    "0x6bcd28763456db543d0c29acb34970b81e4d7f004d2581fce46b813ece8152c1";

// note0 (spent) — from prove_deposit --amount 200000 --pool <mainnet> --root <empty>.
const NOTE0_AMOUNT: u64 = 200_000;
const NOTE0_PRIVATE_KEY: u64 = 11_111;
const NOTE0_BLINDING: u64 = 777;
// note1 (sibling, amount 0) — same deposit, blinding 666, privkey 22222.
const NOTE1_AMOUNT: u64 = 0;
const NOTE1_PRIVATE_KEY: u64 = 22_222;
const NOTE1_BLINDING: u64 = 666;

fn main() -> anyhow::Result<()> {
    let hasher = PoseidonOptimized::new_t3();
    let empty_leaf = {
        use num_bigint::BigUint;
        use std::str::FromStr;
        Fr::from(BigUint::from_str(ZERO_VALUE).unwrap())
    };
    let vortex = pool_address_to_field(POOL_ADDRESS)?;

    // ---- reconstruct the deposit's two output commitments ----
    let note0_pubkey = hash1(&Fr::from(NOTE0_PRIVATE_KEY));
    let note0_commitment = hash4(
        &Fr::from(NOTE0_AMOUNT),
        &note0_pubkey,
        &Fr::from(NOTE0_BLINDING),
        &vortex,
    );
    let note1_pubkey = hash1(&Fr::from(NOTE1_PRIVATE_KEY));
    let note1_commitment = hash4(
        &Fr::from(NOTE1_AMOUNT),
        &note1_pubkey,
        &Fr::from(NOTE1_BLINDING),
        &vortex,
    );

    println!("\n========= TALISE PRIVACY — WITHDRAW PROOF (mainnet, post-deposit) =========");
    println!("pool      = {POOL_ADDRESS}");
    println!("note0.commitment = {}", note0_commitment.into_bigint());
    println!("note1.commitment = {}", note1_commitment.into_bigint());

    // STEP 1 — post-deposit tree + root
    let mut tree = SparseMerkleTree::<MERKLE_TREE_LEVEL>::new_empty(&hasher, &empty_leaf);
    tree.insert_pair(note0_commitment, note1_commitment, &hasher)?;
    let post_deposit_root = tree.root();
    println!(
        "POST-DEPOSIT root (target) = {}",
        post_deposit_root.into_bigint()
    );

    // STEP 2 — membership path for leaf 0 (note0)
    let note0_path: Path<MERKLE_TREE_LEVEL> = tree.generate_membership_proof(0)?;
    let path_root = note0_path.calculate_root(&note0_commitment, &hasher)?;
    assert_eq!(
        path_root, post_deposit_root,
        "membership path for leaf 0 does not recompute the post-deposit root"
    );
    println!("membership path for leaf 0 recomputes post-deposit root: PASS");

    // STEP 3 — withdraw witness
    let in0_privkey = Fr::from(NOTE0_PRIVATE_KEY);
    let in0_amount = Fr::from(NOTE0_AMOUNT);
    let in0_blinding = Fr::from(NOTE0_BLINDING);
    let in0_path_index = Fr::from(0u64);

    // input1 = distinct dummy zero note (amount 0 → Merkle check skipped).
    let in1_privkey = Fr::from(0xDEAD_BEEFu64);
    let in1_amount = Fr::from(0u64);
    let in1_blinding = Fr::from(0xC0FF_EEu64);
    let in1_path_index = Fr::from(3u64);

    let compute_nullifier = |privkey: &Fr, amount: &Fr, blinding: &Fr, path_index: &Fr| -> Fr {
        let pubkey = hash1(privkey);
        let commitment = hash4(amount, &pubkey, blinding, &vortex);
        let signature = hash3(privkey, &commitment, path_index);
        hash3(&commitment, path_index, &signature)
    };
    let null0 = compute_nullifier(&in0_privkey, &in0_amount, &in0_blinding, &in0_path_index);
    let null1 = compute_nullifier(&in1_privkey, &in1_amount, &in1_blinding, &in1_path_index);
    assert_ne!(null0, null1, "input nullifiers must be distinct");

    // outputs: two zero notes. Sum_out = 0.
    let out0_pubkey = hash1(&Fr::from(11_111u64));
    let out0_amount = Fr::from(0u64);
    let out0_blinding = Fr::from(555u64);
    let comm0 = hash4(&out0_amount, &out0_pubkey, &out0_blinding, &vortex);

    let out1_pubkey = hash1(&Fr::from(22_222u64));
    let out1_amount = Fr::from(0u64);
    let out1_blinding = Fr::from(444u64);
    let comm1 = hash4(&out1_amount, &out1_pubkey, &out1_blinding, &vortex);

    // WITHDRAW: public_amount = field-negated 200000 (r - 200000).
    let public_amount = Fr::ZERO - Fr::from(NOTE0_AMOUNT);
    debug_assert_eq!(
        (in0_amount + in1_amount) + public_amount,
        out0_amount + out1_amount,
        "value conservation broken"
    );

    let hashed_account_secret = Fr::ZERO;
    let account_secret = Fr::ZERO;
    let merkle_paths: [Path<MERKLE_TREE_LEVEL>; 2] = [note0_path, Path::empty()];

    let circuit = TransactionCircuit::new(
        vortex,
        post_deposit_root,
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

    // STEP 4 — prove + native verify
    let (pk, vk) = talise_privacy_circuit::prover::load_keys(FsPath::new("keys"))?;
    let public_inputs = circuit.get_public_inputs();
    let mut rng = rand::rngs::OsRng;
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)
        .map_err(|e| anyhow::anyhow!("Groth16 prove failed: {e}"))?;
    let pvk = prepare_verifying_key(&vk);
    let ok = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs)
        .map_err(|e| anyhow::anyhow!("verify call failed: {e}"))?;
    println!(
        "native Groth16 verify against persisted VK: {}",
        if ok { "PASS" } else { "FAIL" }
    );
    if !ok {
        anyhow::bail!("FATAL: withdraw proof did NOT verify");
    }

    // STEP 5 — Sui artifacts
    let proof_h = proof_hex(&proof)?;
    let pubs_h = public_inputs_hex(&public_inputs);
    let _ = vk_hex(&vk)?;

    let labels = [
        "pool/vortex", "root", "public_value", "null0", "null1", "comm0", "comm1",
        "hashed_secret",
    ];
    println!("\npublic inputs [pool,root,public_value,null0,null1,comm0,comm1,hashed_secret]:");
    for (l, fe) in labels.iter().zip(public_inputs.iter()) {
        println!("  {l:>14} = {}", fe.into_bigint());
    }
    println!("\nproof_hex (128 bytes):\n{proof_h}");
    println!("\npublic_inputs_hex (256 bytes, 8x32 LE):\n{pubs_h}");
    println!("==========================================================================\n");
    Ok(())
}
