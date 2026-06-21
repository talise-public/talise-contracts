//! Reproducible DEPOSIT proof generator for the Talise privacy pool.
//!
//! Loads the PERSISTED dev keys (keys/proving_key.bin), builds a deposit witness
//! bound to a specific pool address + root + amount, proves with real OsRng, and
//! prints the Sui-format artifacts that `talise_privacy::shielded_pool::transact`
//! will ACCEPT against the matching VK (keys/vk_sui.hex == constants.move).
//!
//! Usage:
//!   cargo run --bin prove_deposit -- --pool 0x1 --root 0 --amount 1000
//!   cargo run --bin prove_deposit -- --pool 0x<addr> --root <u256dec> --amount <u64> \
//!       [--split <out0>,<out1>]
//!
//! Public input order (must match circuit allocation + proof.move):
//!   [pool, root, public_value, null0, null1, comm0, comm1, hashed_secret]

use ark_bn254::Bn254;
use ark_crypto_primitives::snark::SNARK;
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16};

use std::path::Path;
use talise_privacy_circuit::prover::{
    build_deposit_circuit_for_pool, load_keys, pool_address_to_field, proof_hex,
    public_inputs_hex, u256_decimal_to_field, vk_hex,
};

struct Args {
    pool: String,
    root: String,
    amount: u64,
    split: Option<(u64, u64)>,
    keys_dir: String,
}

fn parse_args() -> anyhow::Result<Args> {
    let mut pool = None;
    let mut root = None;
    let mut amount = None;
    let mut split = None;
    let mut keys_dir = "keys".to_string();

    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--pool" => pool = it.next(),
            "--root" => root = it.next(),
            "--amount" => {
                amount = Some(
                    it.next()
                        .ok_or_else(|| anyhow::anyhow!("--amount needs a value"))?
                        .parse::<u64>()?,
                )
            }
            "--split" => {
                let s = it.next().ok_or_else(|| anyhow::anyhow!("--split needs <a>,<b>"))?;
                let (a0, a1) = s
                    .split_once(',')
                    .ok_or_else(|| anyhow::anyhow!("--split must be <a>,<b>"))?;
                split = Some((a0.trim().parse::<u64>()?, a1.trim().parse::<u64>()?));
            }
            "--keys-dir" => {
                keys_dir = it.next().ok_or_else(|| anyhow::anyhow!("--keys-dir needs a value"))?
            }
            "-h" | "--help" => {
                println!(
                    "Usage: prove_deposit --pool <0xADDR> --root <u256dec> --amount <u64> [--split <a>,<b>] [--keys-dir <dir>]"
                );
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown arg: {other}"),
        }
    }

    Ok(Args {
        pool: pool.ok_or_else(|| anyhow::anyhow!("--pool is required"))?,
        root: root.ok_or_else(|| anyhow::anyhow!("--root is required"))?,
        amount: amount.ok_or_else(|| anyhow::anyhow!("--amount is required"))?,
        split,
        keys_dir,
    })
}

fn main() -> anyhow::Result<()> {
    let args = parse_args()?;

    // Default output split: full amount in note0, 0 in note1.
    let (out0, out1) = args.split.unwrap_or((args.amount, 0));
    if out0.checked_add(out1) != Some(args.amount) {
        anyhow::bail!(
            "output split {out0}+{out1} must sum to amount {} (value conservation)",
            args.amount
        );
    }

    // Public input [0]: pool address -> u256 (big-endian) -> mod r.
    let vortex = pool_address_to_field(&args.pool)?;
    // Public input [1]: root u256 decimal -> mod r.
    let root = u256_decimal_to_field(&args.root)?;

    // Load PERSISTED dev keys (stable VK).
    let (pk, vk) = load_keys(Path::new(&args.keys_dir))?;

    // Build pool-bound deposit witness.
    let (circuit, notes) =
        build_deposit_circuit_for_pool(vortex, root, args.amount, out0, out1)?;

    // Prove with real OS entropy.
    let public_inputs = circuit.get_public_inputs();
    let mut rng = rand::rngs::OsRng;
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)
        .map_err(|e| anyhow::anyhow!("Groth16 prove failed: {e}"))?;

    // Native verify against the PERSISTED vk.
    let pvk = prepare_verifying_key(&vk);
    let ok = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs)
        .map_err(|e| anyhow::anyhow!("verify call failed: {e}"))?;
    if !ok {
        anyhow::bail!("FATAL: proof did NOT verify against persisted VK");
    }

    let vk_h = vk_hex(&vk)?;
    let proof_h = proof_hex(&proof)?;
    let pubs_h = public_inputs_hex(&public_inputs);

    println!("\n================ TALISE PRIVACY — DEPOSIT PROOF (pool-bound) ================");
    println!("(DEV/TEST keys, real-entropy OsRng proof; NOT a trusted-setup ceremony)");
    println!("native Groth16 verify against persisted VK: PASS\n");

    println!("inputs:");
    println!("  pool     = {}", args.pool);
    println!("  root     = {} (decimal u256)", args.root);
    println!("  amount   = {}", args.amount);
    println!("  split    = {out0} + {out1}\n");

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
    println!("public_inputs (decimal, order [pool,root,public_value,null0,null1,comm0,comm1,hashed_secret]):");
    for (l, fe) in labels.iter().zip(public_inputs.iter()) {
        println!("  {l:>14} = {}", fe.into_bigint());
    }

    println!("\noutput notes (decimal — KEEP THESE to build a withdraw later):");
    for (i, n) in notes.iter().enumerate() {
        println!("  note{i}:");
        println!("    amount      = {}", n.amount.into_bigint());
        println!("    private_key = {}", n.private_key.into_bigint());
        println!("    public_key  = {}", n.public_key.into_bigint());
        println!("    blinding    = {}", n.blinding.into_bigint());
        println!("    commitment  = {}", n.commitment.into_bigint());
    }
    println!("  (note commitment = Poseidon4(amount, public_key, blinding, pool_field))");

    println!("\nvk_sui.hex (len {} bytes):\n{vk_h}", vk_h.len() / 2);
    println!("\nproof_hex (len {} bytes, A32|B64|C32 compressed):\n{proof_h}", proof_h.len() / 2);
    println!(
        "\npublic_inputs_hex (len {} bytes, 8 x 32B LE):\n{pubs_h}",
        pubs_h.len() / 2
    );
    println!("============================================================================\n");

    Ok(())
}
