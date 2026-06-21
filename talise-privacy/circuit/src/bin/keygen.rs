//! DEV / TEST Groth16 key generation for the Talise privacy circuit.
//!
//! WARNING: These are DEVELOPMENT keys, NOT a trusted-setup ceremony output.
//! The toxic waste is generated locally with OsRng and discarded in-process,
//! which is fine for tests/integration but UNSAFE for production funds.
//!
//! Generate ONCE, then commit to reusing the persisted files so the VK (and
//! therefore `constants.move`'s `verifying_key!()`) stays stable. By default
//! this REFUSES to overwrite existing keys; pass `--force` to regenerate.
//!
//! Writes (to ./keys/):
//!   * proving_key.bin     — arkworks compressed ProvingKey (used by prove_deposit)
//!   * verifying_key.bin   — arkworks compressed VerifyingKey
//!   * vk_sui.hex          — hex of verifying_key.bin (520 bytes), the exact
//!                           bytes Sui's `groth16::prepare_verifying_key` consumes
//!                           and what you paste into constants.move::verifying_key!()

use ark_bn254::Bn254;
use ark_groth16::Groth16;
use rand::rngs::OsRng;

use std::path::Path;
use talise_privacy_circuit::circuit::TransactionCircuit;
use talise_privacy_circuit::prover::save_keys;

pub fn main() -> anyhow::Result<()> {
    let force = std::env::args().any(|a| a == "--force");

    let keys_dir = Path::new("keys");
    let vk_path = keys_dir.join("vk_sui.hex");
    let pk_path = keys_dir.join("proving_key.bin");

    if !force && (vk_path.exists() || pk_path.exists()) {
        let existing = std::fs::read_to_string(&vk_path).unwrap_or_default();
        println!(
            "[DEV KEYS] Keys already exist at ./keys/ — reusing (pass --force to regenerate).\n\
             vk_sui.hex ({} bytes):\n{}",
            existing.len() / 2,
            existing
        );
        return Ok(());
    }

    println!("[DEV KEYS] Generating Groth16 proving/verifying keys (NOT a ceremony)...");
    let circuit = TransactionCircuit::empty();

    // Real entropy from the OS CSPRNG (NOT Vortex's [0u8; 32] ChaCha seed).
    let mut rng = OsRng;

    println!("Running setup (this may take a few minutes)...");
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng)?;
    let vk = pk.vk.clone();

    let vk_h = save_keys(keys_dir, &pk, &vk)?;

    println!(
        "[DEV KEYS] Done. Written to ./keys/ (proving_key.bin, verifying_key.bin, vk_sui.hex).\n\
         vk_sui.hex ({} bytes) — paste into constants.move::verifying_key!():\n{}",
        vk_h.len() / 2,
        vk_h
    );
    Ok(())
}
