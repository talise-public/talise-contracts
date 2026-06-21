//! Parameterized WITHDRAW proof generator for the PTB harness.
//!
//! Spends note0 (the deposit's first output note) for a full 1000 withdraw:
//!   - reconstruct the height-26 tree from the deposit's two output commitments,
//!   - membership proof for leaf 0 (note0),
//!   - input1 = a fresh distinct dummy zero note,
//!   - outputs = two zero notes (change 0),
//!   - public_amount = field-negated 1000.
//!
//! Bound to the LIVE pool object id. Prints the same Sui-format artifacts as
//! prove_deposit so the Node PTB harness can parse proof_hex + public inputs.

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
    pool_address_to_field, proof_hex, public_inputs_hex, u256_decimal_to_field, vk_hex,
};

// Live pool object id (binds the proof to the deployed ShieldedPool<USDsui>).
const POOL_ADDRESS: &str =
    "0x6bcd28763456db543d0c29acb34970b81e4d7f004d2581fce46b813ece8152c1";

// note0 from the deposit proof (the note we SPEND, leaf 0).
const NOTE0_AMOUNT: u64 = 1000;
const NOTE0_PRIVATE_KEY: u64 = 11111;
const NOTE0_BLINDING: u64 = 777;
// note1 from the deposit (sibling leaf 1) — only its commitment matters here.
const LEAF1_AMOUNT: u64 = 0;
const LEAF1_PRIVATE_KEY: u64 = 22222;
const LEAF1_BLINDING: u64 = 666;

fn fr_dec(s: &str) -> Fr {
    u256_decimal_to_field(s).expect("decimal field element")
}

fn main() -> anyhow::Result<()> {
    let hasher = PoseidonOptimized::new_t3();
    let empty_leaf = fr_dec(ZERO_VALUE);
    let vortex = pool_address_to_field(POOL_ADDRESS)?;

    // Reconstruct note0 + leaf1 commitments exactly as the deposit did.
    let note0_privkey = Fr::from(NOTE0_PRIVATE_KEY);
    let note0_pubkey = hash1(&note0_privkey);
    let note0_amount = Fr::from(NOTE0_AMOUNT);
    let note0_blinding = Fr::from(NOTE0_BLINDING);
    let note0_commitment = hash4(&note0_amount, &note0_pubkey, &note0_blinding, &vortex);

    let leaf1_privkey = Fr::from(LEAF1_PRIVATE_KEY);
    let leaf1_pubkey = hash1(&leaf1_privkey);
    let leaf1_amount = Fr::from(LEAF1_AMOUNT);
    let leaf1_blinding = Fr::from(LEAF1_BLINDING);
    let leaf1_commitment = hash4(&leaf1_amount, &leaf1_pubkey, &leaf1_blinding, &vortex);

    // STEP 1 — reconstruct tree + membership proof for leaf 0.
    let mut tree = SparseMerkleTree::<MERKLE_TREE_LEVEL>::new_empty(&hasher, &empty_leaf);
    tree.insert_pair(note0_commitment, leaf1_commitment, &hasher)?;
    let reconstructed_root = tree.root();
    let note0_path: Path<MERKLE_TREE_LEVEL> = tree.generate_membership_proof(0)?;
    let path_root = note0_path.calculate_root(&note0_commitment, &hasher)?;
    assert_eq!(path_root, reconstructed_root, "membership path must recompute root");

    // STEP 2 — withdraw witness.
    let in0_path_index = Fr::from(0u64);
    // input1 = distinct dummy zero note (fresh privkey/blinding/path_index).
    let in1_privkey = Fr::from(0xDEAD_BEEFu64);
    let in1_amount = Fr::from(0u64);
    let in1_blinding = Fr::from(0xC0FF_EEu64);
    let in1_path_index = Fr::from(3u64);

    let nullifier = |privkey: &Fr, amount: &Fr, blinding: &Fr, path_index: &Fr| -> Fr {
        let pubkey = hash1(privkey);
        let commitment = hash4(amount, &pubkey, blinding, &vortex);
        let signature = hash3(privkey, &commitment, path_index);
        hash3(&commitment, path_index, &signature)
    };
    let null0 = nullifier(&note0_privkey, &note0_amount, &note0_blinding, &in0_path_index);
    let null1 = nullifier(&in1_privkey, &in1_amount, &in1_blinding, &in1_path_index);
    assert_ne!(null0, null1, "input nullifiers must be distinct");

    // outputs: two zero change notes (full withdraw, change 0).
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

    let public_amount = Fr::ZERO - Fr::from(NOTE0_AMOUNT);
    let account_secret = Fr::ZERO;
    let hashed_account_secret = Fr::ZERO;
    let merkle_paths: [Path<MERKLE_TREE_LEVEL>; 2] = [note0_path, Path::empty()];

    let circuit = TransactionCircuit::new(
        vortex,
        reconstructed_root,
        public_amount,
        null0,
        null1,
        comm0,
        comm1,
        hashed_account_secret,
        account_secret,
        [note0_privkey, in1_privkey],
        [note0_amount, in1_amount],
        [note0_blinding, in1_blinding],
        [in0_path_index, in1_path_index],
        merkle_paths,
        [out0_pubkey, out1_pubkey],
        [out0_amount, out1_amount],
        [out0_blinding, out1_blinding],
    )?;

    // STEP 3 — prove + native verify.
    let (pk, vk) = talise_privacy_circuit::prover::load_keys(FsPath::new("keys"))?;
    let public_inputs = circuit.get_public_inputs();
    let mut rng = rand::rngs::OsRng;
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)
        .map_err(|e| anyhow::anyhow!("Groth16 prove failed: {e}"))?;
    let pvk = prepare_verifying_key(&vk);
    let ok = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs)
        .map_err(|e| anyhow::anyhow!("verify call failed: {e}"))?;
    if !ok {
        anyhow::bail!("FATAL: withdraw proof did NOT verify against persisted VK");
    }

    // STEP 4 — Sui-format artifacts.
    let proof_h = proof_hex(&proof)?;
    let pubs_h = public_inputs_hex(&public_inputs);
    let vk_h = vk_hex(&vk)?;

    println!("\n================ TALISE PRIVACY — WITHDRAW PROOF (harness) ================");
    println!("native Groth16 verify against persisted VK: PASS");
    println!("  pool   = {POOL_ADDRESS}");
    println!("  reconstructed_root = {}", reconstructed_root.into_bigint());
    let labels = [
        "pool/vortex", "root", "public_value", "null0", "null1", "comm0", "comm1", "hashed_secret",
    ];
    println!("public_inputs (decimal):");
    for (l, fe) in labels.iter().zip(public_inputs.iter()) {
        println!("  {l:>14} = {}", fe.into_bigint());
    }
    println!("\nproof_hex (len {} bytes, A32|B64|C32 compressed):\n{proof_h}", proof_h.len() / 2);
    println!("\npublic_inputs_hex (len {} bytes, 8 x 32B LE):\n{pubs_h}", pubs_h.len() / 2);
    println!("\nvk_sui.hex (len {} bytes):\n{vk_h}", vk_h.len() / 2);
    println!("==========================================================================\n");
    Ok(())
}
