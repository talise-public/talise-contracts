//! ONE-SHOT LIFECYCLE PROVER for the mainnet shielded-pool harness.
//!
//! Produces a MATCHED pair of REAL Groth16 proofs — a DEPOSIT and the WITHDRAW
//! that spends the EXACT note the deposit created — and emits them as a single
//! JSON artifact the Node harness (web/scripts/shield-mainnet-lifecycle.mjs)
//! turns into the two live transact PTBs.
//!
//! Why both legs in ONE binary: the withdraw must spend the deposit's output
//! note0 (same amount/privkey/blinding/pool) and prove its membership in the
//! POST-DEPOSIT tree. Generating them together guarantees that linkage with
//! freshly-randomized secrets (NOT the toy 11111/777 constants), so each run is
//! a genuine, unique shielded round-trip.
//!
//! ASSUMPTION (documented + asserted by the harness): the deposit is the FIRST
//! transaction in the pool, so the pre-deposit root is the EMPTY-tree root and
//! the deposit's two commitments land at leaves 0 and 1. The post-deposit root
//! is then `appendPair(empty, comm0, comm1)`, which the on-chain
//! `merkle::append_pair` and the SDK `merkle.ts` compute identically (Phase-0
//! Poseidon parity gate). The harness re-derives this same root in TS and
//! asserts equality before building the withdraw PTB.
//!
//! Usage:
//!   cargo run --release --bin prove_lifecycle -- \
//!     --pool 0x6bcd...152c1 --amount 10000000 --empty-root <u256dec>
//!
//!   --amount      micros of USDsui (10000000 = $10.00, the per-tx cap).
//!   --empty-root  the live empty-tree root from the pool object (decimal u256);
//!                 bound as the deposit proof's public root.
//!
//! Output: one JSON object on stdout (between BEGIN_LIFECYCLE_JSON / END markers)
//! with { pool, amount, empty_root, post_deposit_root, deposit{...}, withdraw{...} }.
//! Each leg carries proof_hex (128B) + the 6 u256 public signals the PTB needs.

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::{AdditiveGroup, PrimeField, UniformRand};
use ark_groth16::{prepare_verifying_key, Groth16};
use rand::rngs::OsRng;
use std::path::Path as FsPath;

use talise_privacy_circuit::circuit::TransactionCircuit;
use talise_privacy_circuit::constants::{MERKLE_TREE_LEVEL, ZERO_VALUE};
use talise_privacy_circuit::merkle_tree::{Path, SparseMerkleTree};
use talise_privacy_circuit::poseidon_opt::{hash1, hash3, hash4, PoseidonOptimized};
use talise_privacy_circuit::prover::{
    load_keys, pool_address_to_field, proof_hex, u256_decimal_to_field, vk_hex,
};

struct Args {
    pool: String,
    amount: u64,
    empty_root: String,
    keys_dir: String,
    /// Commitments ALREADY in the pool (decimal u256, in leaf order). On a
    /// non-empty pool the new deposit lands AFTER these, so the withdraw must
    /// prove membership against the real (reconstructed) tree — not an empty one.
    existing_leaves: Vec<String>,
}

fn parse_args() -> anyhow::Result<Args> {
    let mut pool = None;
    let mut amount = None;
    let mut empty_root = None;
    let mut keys_dir = "keys".to_string();
    let mut existing_leaves: Vec<String> = Vec::new();
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--pool" => pool = it.next(),
            "--amount" => {
                amount = Some(
                    it.next()
                        .ok_or_else(|| anyhow::anyhow!("--amount needs a value"))?
                        .parse::<u64>()?,
                )
            }
            "--empty-root" => empty_root = it.next(),
            "--existing-leaves" => {
                let v = it.next().ok_or_else(|| anyhow::anyhow!("--existing-leaves needs a value"))?;
                existing_leaves = v
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            "--keys-dir" => {
                keys_dir = it.next().ok_or_else(|| anyhow::anyhow!("--keys-dir needs a value"))?
            }
            "-h" | "--help" => {
                println!("Usage: prove_lifecycle --pool <0xADDR> --amount <u64> --empty-root <u256dec> [--existing-leaves <dec,dec,...>] [--keys-dir <dir>]");
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown arg: {other}"),
        }
    }
    Ok(Args {
        pool: pool.ok_or_else(|| anyhow::anyhow!("--pool is required"))?,
        amount: amount.ok_or_else(|| anyhow::anyhow!("--amount is required"))?,
        empty_root: empty_root.ok_or_else(|| anyhow::anyhow!("--empty-root is required"))?,
        keys_dir,
        existing_leaves,
    })
}

/// nullifier = Poseidon3(commitment, path_index, Poseidon3(privkey, commitment, path_index)).
fn nullifier(privkey: &Fr, commitment: &Fr, path_index: &Fr) -> Fr {
    let sig = hash3(privkey, commitment, path_index);
    hash3(commitment, path_index, &sig)
}

fn dec(fe: &Fr) -> String {
    fe.into_bigint().to_string()
}

fn main() -> anyhow::Result<()> {
    let args = parse_args()?;
    let mut rng = OsRng;
    let hasher = PoseidonOptimized::new_t3();
    let empty_leaf = u256_decimal_to_field(ZERO_VALUE)?;
    let vortex = pool_address_to_field(&args.pool)?;
    let empty_root_fe = u256_decimal_to_field(&args.empty_root)?;
    let (pk, vk) = load_keys(FsPath::new(&args.keys_dir))?;
    let pvk = prepare_verifying_key(&vk);

    // ── FRESH random note secrets (NOT toy constants) ────────────────────────
    // note0 holds the full deposited amount; note1 is a zero sibling.
    let note0_privkey = Fr::rand(&mut rng);
    let note0_blinding = Fr::rand(&mut rng);
    let note0_amount = Fr::from(args.amount);
    let note0_pubkey = hash1(&note0_privkey);
    let note0_commitment = hash4(&note0_amount, &note0_pubkey, &note0_blinding, &vortex);

    let note1_privkey = Fr::rand(&mut rng);
    let note1_blinding = Fr::rand(&mut rng);
    let note1_amount = Fr::ZERO;
    let note1_pubkey = hash1(&note1_privkey);
    let note1_commitment = hash4(&note1_amount, &note1_pubkey, &note1_blinding, &vortex);

    // ══════════════════════════════════════════════════════════════════════
    // LEG 1 — DEPOSIT  (public_amount = +amount, dummy zero inputs)
    // ══════════════════════════════════════════════════════════════════════
    // Two distinct random dummy zero-input notes (amount 0 ⇒ membership skipped).
    let din0_privkey = Fr::rand(&mut rng);
    let din0_blinding = Fr::rand(&mut rng);
    let din0_idx = Fr::from(0u64);
    let din0_commitment = hash4(&Fr::ZERO, &hash1(&din0_privkey), &din0_blinding, &vortex);
    let dnull0 = nullifier(&din0_privkey, &din0_commitment, &din0_idx);

    let din1_privkey = Fr::rand(&mut rng);
    let din1_blinding = Fr::rand(&mut rng);
    let din1_idx = Fr::from(1u64);
    let din1_commitment = hash4(&Fr::ZERO, &hash1(&din1_privkey), &din1_blinding, &vortex);
    let dnull1 = nullifier(&din1_privkey, &din1_commitment, &din1_idx);
    assert_ne!(dnull0, dnull1, "deposit dummy nullifiers must differ");

    let dep_public_amount = Fr::from(args.amount);
    let dep_paths: [Path<MERKLE_TREE_LEVEL>; 2] = [Path::empty(), Path::empty()];
    let dep_circuit = TransactionCircuit::new(
        vortex,
        empty_root_fe,
        dep_public_amount,
        dnull0,
        dnull1,
        note0_commitment, // out0 = the funded note
        note1_commitment, // out1 = zero sibling
        Fr::ZERO,         // hashed_account_secret
        Fr::ZERO,         // account_secret
        [din0_privkey, din1_privkey],
        [Fr::ZERO, Fr::ZERO],
        [din0_blinding, din1_blinding],
        [din0_idx, din1_idx],
        dep_paths,
        [note0_pubkey, note1_pubkey],
        [note0_amount, note1_amount],
        [note0_blinding, note1_blinding],
    )?;
    let dep_public_inputs = dep_circuit.get_public_inputs();
    let dep_proof = Groth16::<Bn254>::prove(&pk, dep_circuit, &mut rng)
        .map_err(|e| anyhow::anyhow!("deposit prove failed: {e}"))?;
    if !Groth16::<Bn254>::verify_proof(&pvk, &dep_proof, &dep_public_inputs)
        .map_err(|e| anyhow::anyhow!("deposit verify call failed: {e}"))?
    {
        anyhow::bail!("FATAL: deposit proof did NOT verify against persisted VK");
    }
    let dep_proof_h = proof_hex(&dep_proof)?;

    // ══════════════════════════════════════════════════════════════════════
    // POST-DEPOSIT TREE — insert any EXISTING on-chain leaves first, THEN this
    // deposit's pair. On an empty pool note0 lands at leaf 0 (old behavior); on a
    // non-empty pool it lands at leaf `existing_count`, and the withdraw proves
    // membership against the REAL reconstructed root (== the on-chain root).
    // ══════════════════════════════════════════════════════════════════════
    let existing: Vec<Fr> = args
        .existing_leaves
        .iter()
        .map(|s| u256_decimal_to_field(s))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let existing_count = existing.len();
    if existing_count % 2 != 0 {
        anyhow::bail!("--existing-leaves must be an even count (commitments are appended in pairs)");
    }
    let mut tree = SparseMerkleTree::<MERKLE_TREE_LEVEL>::new_empty(&hasher, &empty_leaf);
    let mut i = 0;
    while i < existing_count {
        tree.insert_pair(existing[i], existing[i + 1], &hasher)?;
        i += 2;
    }
    let note0_leaf_index = existing_count as u64; // this deposit's note0 lands here
    tree.insert_pair(note0_commitment, note1_commitment, &hasher)?;
    let post_deposit_root = tree.root();
    let note0_path: Path<MERKLE_TREE_LEVEL> = tree.generate_membership_proof(existing_count)?;
    let path_root = note0_path.calculate_root(&note0_commitment, &hasher)?;
    assert_eq!(path_root, post_deposit_root, "note0 membership must recompute the post-deposit root");

    // ══════════════════════════════════════════════════════════════════════
    // LEG 2 — WITHDRAW  (spend note0 fully; public_amount = r - amount)
    // ══════════════════════════════════════════════════════════════════════
    let win0_idx = Fr::from(note0_leaf_index); // note0's real leaf index
    let wnull0 = nullifier(&note0_privkey, &note0_commitment, &win0_idx);
    // input1 = distinct random dummy zero note. Its path index just needs to be
    // distinct (amount 0 ⇒ membership skipped); use a high offset to avoid any
    // collision with the real leaves or the deposit dummies.
    let win1_privkey = Fr::rand(&mut rng);
    let win1_blinding = Fr::rand(&mut rng);
    let win1_idx = Fr::from(note0_leaf_index + 7);
    let win1_commitment = hash4(&Fr::ZERO, &hash1(&win1_privkey), &win1_blinding, &vortex);
    let wnull1 = nullifier(&win1_privkey, &win1_commitment, &win1_idx);
    assert_ne!(wnull0, wnull1, "withdraw nullifiers must differ");
    // The withdraw nullifier for note0 must differ from the deposit's dummies.
    assert_ne!(wnull0, dnull0);
    assert_ne!(wnull0, dnull1);

    // Full withdraw → both outputs are fresh zero change notes.
    let wout0_privkey = Fr::rand(&mut rng);
    let wout0_blinding = Fr::rand(&mut rng);
    let wout0_pubkey = hash1(&wout0_privkey);
    let wcomm0 = hash4(&Fr::ZERO, &wout0_pubkey, &wout0_blinding, &vortex);
    let wout1_privkey = Fr::rand(&mut rng);
    let wout1_blinding = Fr::rand(&mut rng);
    let wout1_pubkey = hash1(&wout1_privkey);
    let wcomm1 = hash4(&Fr::ZERO, &wout1_pubkey, &wout1_blinding, &vortex);

    let with_public_amount = Fr::ZERO - Fr::from(args.amount); // r - amount
    let with_paths: [Path<MERKLE_TREE_LEVEL>; 2] = [note0_path, Path::empty()];
    let with_circuit = TransactionCircuit::new(
        vortex,
        post_deposit_root,
        with_public_amount,
        wnull0,
        wnull1,
        wcomm0,
        wcomm1,
        Fr::ZERO,
        Fr::ZERO,
        [note0_privkey, win1_privkey],
        [note0_amount, Fr::ZERO],
        [note0_blinding, win1_blinding],
        [win0_idx, win1_idx],
        with_paths,
        [wout0_pubkey, wout1_pubkey],
        [Fr::ZERO, Fr::ZERO],
        [wout0_blinding, wout1_blinding],
    )?;
    let with_public_inputs = with_circuit.get_public_inputs();
    let with_proof = Groth16::<Bn254>::prove(&pk, with_circuit, &mut rng)
        .map_err(|e| anyhow::anyhow!("withdraw prove failed: {e}"))?;
    if !Groth16::<Bn254>::verify_proof(&pvk, &with_proof, &with_public_inputs)
        .map_err(|e| anyhow::anyhow!("withdraw verify call failed: {e}"))?
    {
        anyhow::bail!("FATAL: withdraw proof did NOT verify against persisted VK");
    }
    let with_proof_h = proof_hex(&with_proof)?;

    // ── Sanity to stderr (human-readable) ────────────────────────────────────
    eprintln!("== TALISE PRIVACY — LIFECYCLE PROVER (deposit + matched withdraw) ==");
    eprintln!("native Groth16 verify (deposit):  PASS");
    eprintln!("native Groth16 verify (withdraw): PASS");
    eprintln!("pool              = {}", args.pool);
    eprintln!("amount (micros)   = {}", args.amount);
    eprintln!("empty_root        = {}", args.empty_root);
    eprintln!("post_deposit_root = {}", dec(&post_deposit_root));
    eprintln!("vk_sui.hex (len {} bytes) = {}", vk_hex(&vk)?.len() / 2, vk_hex(&vk)?);

    // ── JSON artifact to stdout (machine-readable) ───────────────────────────
    // Public-input order: [pool, root, public_value, null0, null1, comm0, comm1, hashed_secret].
    let json = format!(
        r#"{{"pool":"{pool}","amount":{amount},"empty_root":"{empty_root}","post_deposit_root":"{pdr}","deposit":{{"proof_hex":"{dph}","root":"{dr}","public_value":"{dpv}","input_nullifier0":"{dn0}","input_nullifier1":"{dn1}","output_commitment0":"{dc0}","output_commitment1":"{dc1}"}},"withdraw":{{"proof_hex":"{wph}","root":"{wr}","public_value":"{wpv}","input_nullifier0":"{wn0}","input_nullifier1":"{wn1}","output_commitment0":"{wc0}","output_commitment1":"{wc1}"}}}}"#,
        pool = args.pool,
        amount = args.amount,
        empty_root = args.empty_root,
        pdr = dec(&post_deposit_root),
        dph = dep_proof_h,
        dr = dec(&dep_public_inputs[1]),
        dpv = dec(&dep_public_inputs[2]),
        dn0 = dec(&dep_public_inputs[3]),
        dn1 = dec(&dep_public_inputs[4]),
        dc0 = dec(&dep_public_inputs[5]),
        dc1 = dec(&dep_public_inputs[6]),
        wph = with_proof_h,
        wr = dec(&with_public_inputs[1]),
        wpv = dec(&with_public_inputs[2]),
        wn0 = dec(&with_public_inputs[3]),
        wn1 = dec(&with_public_inputs[4]),
        wc0 = dec(&with_public_inputs[5]),
        wc1 = dec(&with_public_inputs[6]),
    );
    println!("BEGIN_LIFECYCLE_JSON");
    println!("{json}");
    println!("END_LIFECYCLE_JSON");
    Ok(())
}
