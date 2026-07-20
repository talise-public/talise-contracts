//! PARAMETERIZED WITHDRAW prover — proves a full withdraw for a note whose
//! secrets we ALREADY hold (recovery / sweep of a stranded note).
//!
//! Unlike `prove_withdraw.rs` (hardcoded one-shot) and `prove_lifecycle.rs`
//! (generates fresh secrets), this reads a REAL existing note's secret material
//! from argv and proves the withdraw that spends it, targeting the CURRENT
//! on-chain tree reconstructed from `--existing-leaves`.
//!
//! Usage:
//!   cargo run --release --bin prove_note_withdraw -- \
//!     --pool 0x6bcd...152c1 \
//!     --privkey <dec>  --amount <micros u64>  --blinding <dec> \
//!     --commitment <dec>  --leaf-index <u64> \
//!     --existing-leaves <dec,dec,...>   # ALL current on-chain commitments, leaf order
//!     [--keys-dir keys]
//!
//! Output (stdout, between markers): a JSON object of the SAME shape as
//! prove_lifecycle's `withdraw` block, so web/scripts/shield-recover-execute.mjs
//! feeds it straight into buildTransact:
//!   { proof_hex, root, public_value, input_nullifier0, input_nullifier1,
//!     output_commitment0, output_commitment1 }
//!
//! It NATIVE-VERIFIES the proof against the persisted VK before emitting, and
//! ASSERTS the reconstructed root == the note's membership-path root. No secret
//! is printed (privkey/blinding never appear in output).

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::{AdditiveGroup, PrimeField, UniformRand};
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
    load_keys, pool_address_to_field, proof_hex, u256_decimal_to_field, vk_hex,
};

struct Args {
    pool: String,
    privkey: String,
    amount: u64,
    blinding: String,
    commitment: String,
    leaf_index: u64,
    existing_leaves: Vec<String>,
    keys_dir: String,
}

fn parse_args() -> anyhow::Result<Args> {
    let mut pool = None;
    let mut privkey = None;
    let mut amount = None;
    let mut blinding = None;
    let mut commitment = None;
    let mut leaf_index = None;
    let mut existing_leaves: Vec<String> = Vec::new();
    let mut keys_dir = "keys".to_string();
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--pool" => pool = it.next(),
            "--privkey" => privkey = it.next(),
            "--amount" => {
                amount = Some(
                    it.next()
                        .ok_or_else(|| anyhow::anyhow!("--amount needs a value"))?
                        .parse::<u64>()?,
                )
            }
            "--blinding" => blinding = it.next(),
            "--commitment" => commitment = it.next(),
            "--leaf-index" => {
                leaf_index = Some(
                    it.next()
                        .ok_or_else(|| anyhow::anyhow!("--leaf-index needs a value"))?
                        .parse::<u64>()?,
                )
            }
            "--existing-leaves" => {
                let v = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--existing-leaves needs a value"))?;
                existing_leaves = v
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            "--keys-dir" => {
                keys_dir = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--keys-dir needs a value"))?
            }
            "-h" | "--help" => {
                println!("Usage: prove_note_withdraw --pool <0xADDR> --privkey <dec> --amount <u64> --blinding <dec> --commitment <dec> --leaf-index <u64> --existing-leaves <dec,...> [--keys-dir keys]");
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown arg: {other}"),
        }
    }
    Ok(Args {
        pool: pool.ok_or_else(|| anyhow::anyhow!("--pool is required"))?,
        privkey: privkey.ok_or_else(|| anyhow::anyhow!("--privkey is required"))?,
        amount: amount.ok_or_else(|| anyhow::anyhow!("--amount is required"))?,
        blinding: blinding.ok_or_else(|| anyhow::anyhow!("--blinding is required"))?,
        commitment: commitment.ok_or_else(|| anyhow::anyhow!("--commitment is required"))?,
        leaf_index: leaf_index.ok_or_else(|| anyhow::anyhow!("--leaf-index is required"))?,
        existing_leaves,
        keys_dir,
    })
}

fn fr_dec(s: &str) -> anyhow::Result<Fr> {
    Ok(Fr::from(
        BigUint::from_str(s.trim()).map_err(|_| anyhow::anyhow!("bad decimal field element: {s}"))?,
    ))
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
    let (pk, vk) = load_keys(FsPath::new(&args.keys_dir))?;
    let pvk = prepare_verifying_key(&vk);

    // ── The recovered note's secret material + commitment sanity ──────────────
    let privkey = fr_dec(&args.privkey)?;
    let amount = Fr::from(args.amount);
    let blinding = fr_dec(&args.blinding)?;
    let commitment = fr_dec(&args.commitment)?;
    let pubkey = hash1(&privkey);
    let derived = hash4(&amount, &pubkey, &blinding, &vortex);
    if derived != commitment {
        anyhow::bail!(
            "note secrets inconsistent: hash4(amount,pubkey,blinding,pool) != provided commitment"
        );
    }

    // ── Reconstruct the CURRENT on-chain tree, generate the note's path ───────
    let existing: Vec<Fr> = args
        .existing_leaves
        .iter()
        .map(|s| u256_decimal_to_field(s))
        .collect::<anyhow::Result<Vec<_>>>()?;
    if existing.len() % 2 != 0 {
        anyhow::bail!("--existing-leaves must be an even count (commitments append in pairs)");
    }
    // The provided leaf must actually be at leaf_index in the leaf list.
    let li = args.leaf_index as usize;
    if li >= existing.len() || existing[li] != commitment {
        anyhow::bail!(
            "commitment not found at leaf_index {} in --existing-leaves",
            args.leaf_index
        );
    }
    let mut tree = SparseMerkleTree::<MERKLE_TREE_LEVEL>::new_empty(&hasher, &empty_leaf);
    let mut i = 0;
    while i < existing.len() {
        tree.insert_pair(existing[i], existing[i + 1], &hasher)?;
        i += 2;
    }
    let root = tree.root();
    let note_path: Path<MERKLE_TREE_LEVEL> = tree.generate_membership_proof(li)?;
    let path_root = note_path.calculate_root(&commitment, &hasher)?;
    if path_root != root {
        anyhow::bail!("membership path for leaf {} does not recompute the tree root", li);
    }

    // ── WITHDRAW witness (spend the note fully; public_amount = r - amount) ────
    let in0_idx = Fr::from(args.leaf_index);
    let null0 = nullifier(&privkey, &commitment, &in0_idx);

    // input1 = distinct random dummy zero note (amount 0 ⇒ membership skipped).
    let in1_privkey = Fr::rand(&mut rng);
    let in1_blinding = Fr::rand(&mut rng);
    let in1_idx = Fr::from(args.leaf_index + 7);
    let in1_commitment = hash4(&Fr::ZERO, &hash1(&in1_privkey), &in1_blinding, &vortex);
    let null1 = nullifier(&in1_privkey, &in1_commitment, &in1_idx);
    assert_ne!(null0, null1, "input nullifiers must be distinct");

    // Full withdraw → both outputs are fresh zero change notes (Sum_out = 0).
    let out0_privkey = Fr::rand(&mut rng);
    let out0_blinding = Fr::rand(&mut rng);
    let out0_pubkey = hash1(&out0_privkey);
    let comm0 = hash4(&Fr::ZERO, &out0_pubkey, &out0_blinding, &vortex);
    let out1_privkey = Fr::rand(&mut rng);
    let out1_blinding = Fr::rand(&mut rng);
    let out1_pubkey = hash1(&out1_privkey);
    let comm1 = hash4(&Fr::ZERO, &out1_pubkey, &out1_blinding, &vortex);

    let public_amount = Fr::ZERO - amount; // r - amount (withdraw)
    debug_assert_eq!((amount + Fr::ZERO) + public_amount, Fr::ZERO, "value conservation");

    let paths: [Path<MERKLE_TREE_LEVEL>; 2] = [note_path, Path::empty()];
    let circuit = TransactionCircuit::new(
        vortex,
        root,
        public_amount,
        null0,
        null1,
        comm0,
        comm1,
        Fr::ZERO, // hashed_account_secret (unsponsored)
        Fr::ZERO, // account_secret
        [privkey, in1_privkey],
        [amount, Fr::ZERO],
        [blinding, in1_blinding],
        [in0_idx, in1_idx],
        paths,
        [out0_pubkey, out1_pubkey],
        [Fr::ZERO, Fr::ZERO],
        [out0_blinding, out1_blinding],
    )?;
    let public_inputs = circuit.get_public_inputs();
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)
        .map_err(|e| anyhow::anyhow!("withdraw prove failed: {e}"))?;
    if !Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs)
        .map_err(|e| anyhow::anyhow!("withdraw verify call failed: {e}"))?
    {
        anyhow::bail!("FATAL: withdraw proof did NOT verify against persisted VK");
    }
    let proof_h = proof_hex(&proof)?;

    // ── Human sanity to stderr (no secrets) ───────────────────────────────────
    eprintln!("== prove_note_withdraw — native Groth16 verify: PASS ==");
    eprintln!("pool         = {}", args.pool);
    eprintln!("amount       = {} micros", args.amount);
    eprintln!("leaf_index   = {}", args.leaf_index);
    eprintln!("root         = {}", dec(&root));
    eprintln!("vk (len {}B) = {}", vk_hex(&vk)?.len() / 2, vk_hex(&vk)?);

    // ── JSON (stdout). Public-input order: [pool, root, public_value, null0, null1, comm0, comm1, ...] ──
    let json = format!(
        r#"{{"proof_hex":"{ph}","root":"{r}","public_value":"{pv}","input_nullifier0":"{n0}","input_nullifier1":"{n1}","output_commitment0":"{c0}","output_commitment1":"{c1}"}}"#,
        ph = proof_h,
        r = dec(&public_inputs[1]),
        pv = dec(&public_inputs[2]),
        n0 = dec(&public_inputs[3]),
        n1 = dec(&public_inputs[4]),
        c0 = dec(&public_inputs[5]),
        c1 = dec(&public_inputs[6]),
    );
    println!("BEGIN_NOTE_WITHDRAW_JSON");
    println!("{json}");
    println!("END_NOTE_WITHDRAW_JSON");
    Ok(())
}
