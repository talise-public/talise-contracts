//! Browser (WASM) Groth16 prover for the Talise privacy circuit.
//!
//! Mirrors Vortex's `wasm::prove` / `wasm::verify` but with TWO important
//! differences:
//!
//!   1. REAL ENTROPY. Vortex's wasm prover used a fixed seed
//!      (`ChaCha20Rng::from_seed([0u8; 32])`). That is INSECURE — Groth16 proof
//!      randomness must be unpredictable. Here we use `rand::rngs::OsRng`, which
//!      on `wasm32` is backed by `getrandom` with the `js` feature
//!      (`crypto.getRandomValues`). So every proof uses fresh browser entropy.
//!
//!   2. Sui-format hex outputs. In addition to the per-component proof bytes and
//!      the decimal public-input strings (Vortex's shape), we also emit the
//!      exact byte layouts the Talise Move verifier consumes:
//!        * `proofSerializedHex`        = proofA(32B G1) ‖ proofB(64B G2) ‖ proofC(32B G1)
//!        * `publicInputsSerializedHex` = 8 × 32-byte LITTLE-ENDIAN field elements
//!      (matching `prover::proof_hex` / `prover::public_inputs_hex`).
//!
//! The exported `prove(input_json, proving_key_hex)` returns a JSON string with:
//!   { proofA, proofB, proofC, publicInputs, proofSerializedHex, publicInputsSerializedHex }
//! and `verify(proof_json, verifying_key_hex)` returns a bool.

use crate::circuit::TransactionCircuit;
use crate::constants::MERKLE_TREE_LEVEL;
use crate::merkle_tree::Path;

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use num_bigint::BigUint;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use wasm_bindgen::prelude::*;

/// Set the panic hook once so Rust panics surface as readable console errors.
#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
}

/// Proof output. `camelCase` so it round-trips cleanly with JS/TS.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofOutput {
    /// Proof component A (compressed G1: 32 bytes).
    pub proof_a: Vec<u8>,
    /// Proof component B (compressed G2: 64 bytes).
    pub proof_b: Vec<u8>,
    /// Proof component C (compressed G1: 32 bytes).
    pub proof_c: Vec<u8>,
    /// Public inputs as decimal strings, in allocation order.
    pub public_inputs: Vec<String>,
    /// proofA ‖ proofB ‖ proofC (128 bytes) — the bytes the Move verifier wants.
    pub proof_serialized_hex: String,
    /// 8 × 32-byte LE field elements — Move `bcs::to_bytes(&u256)` layout.
    pub public_inputs_serialized_hex: String,
}

/// Circuit input. All values are decimal or 0x-hex strings (u256 in JS).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofInput {
    // Public inputs.
    pub vortex: String,
    pub root: String,
    pub public_amount: String,
    pub input_nullifier_0: String,
    pub input_nullifier_1: String,
    pub output_commitment_0: String,
    pub output_commitment_1: String,
    pub hashed_account_secret: String,

    // Private inputs — input UTXOs.
    pub account_secret: String,
    pub in_private_key_0: String,
    pub in_private_key_1: String,
    pub in_amount_0: String,
    pub in_amount_1: String,
    pub in_blinding_0: String,
    pub in_blinding_1: String,
    pub in_path_index_0: String,
    pub in_path_index_1: String,

    // Merkle paths — array of [left, right] pairs, one per tree level.
    pub merkle_path_0: Vec<[String; 2]>,
    pub merkle_path_1: Vec<[String; 2]>,

    // Private inputs — output UTXOs.
    pub out_public_key_0: String,
    pub out_public_key_1: String,
    pub out_amount_0: String,
    pub out_amount_1: String,
    pub out_blinding_0: String,
    pub out_blinding_1: String,
}

/// Generate a Groth16 proof in the browser.
///
/// * `input_json`       — JSON-serialized [`ProofInput`].
/// * `proving_key_hex`  — hex of the arkworks compressed proving key
///                        (`keys/proving_key.bin`).
///
/// Returns JSON-serialized [`ProofOutput`].
#[wasm_bindgen]
pub fn prove(input_json: &str, proving_key_hex: &str) -> Result<String, JsValue> {
    let input: ProofInput = serde_json::from_str(input_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse input JSON: {e}")))?;

    let pk_bytes = hex::decode(proving_key_hex.trim())
        .map_err(|e| JsValue::from_str(&format!("Failed to decode proving key hex: {e}")))?;
    let pk = ark_groth16::ProvingKey::<Bn254>::deserialize_compressed(&pk_bytes[..])
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize proving key: {e}")))?;

    let vortex = parse_field_element(&input.vortex)?;
    let root = parse_field_element(&input.root)?;
    let public_amount = parse_field_element(&input.public_amount)?;
    let input_nullifier_0 = parse_field_element(&input.input_nullifier_0)?;
    let input_nullifier_1 = parse_field_element(&input.input_nullifier_1)?;
    let output_commitment_0 = parse_field_element(&input.output_commitment_0)?;
    let output_commitment_1 = parse_field_element(&input.output_commitment_1)?;
    let hashed_account_secret = parse_field_element(&input.hashed_account_secret)?;

    let account_secret = parse_field_element(&input.account_secret)?;

    let in_private_keys = [
        parse_field_element(&input.in_private_key_0)?,
        parse_field_element(&input.in_private_key_1)?,
    ];
    let in_amounts = [
        parse_field_element(&input.in_amount_0)?,
        parse_field_element(&input.in_amount_1)?,
    ];
    let in_blindings = [
        parse_field_element(&input.in_blinding_0)?,
        parse_field_element(&input.in_blinding_1)?,
    ];
    let in_path_indices = [
        parse_field_element(&input.in_path_index_0)?,
        parse_field_element(&input.in_path_index_1)?,
    ];

    let merkle_paths = [
        parse_merkle_path(&input.merkle_path_0)?,
        parse_merkle_path(&input.merkle_path_1)?,
    ];

    let out_public_keys = [
        parse_field_element(&input.out_public_key_0)?,
        parse_field_element(&input.out_public_key_1)?,
    ];
    let out_amounts = [
        parse_field_element(&input.out_amount_0)?,
        parse_field_element(&input.out_amount_1)?,
    ];
    let out_blindings = [
        parse_field_element(&input.out_blinding_0)?,
        parse_field_element(&input.out_blinding_1)?,
    ];

    let circuit = TransactionCircuit::new(
        vortex,
        root,
        public_amount,
        input_nullifier_0,
        input_nullifier_1,
        output_commitment_0,
        output_commitment_1,
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
    )
    .map_err(|e| JsValue::from_str(&format!("Failed to create circuit: {e}")))?;

    // Extract public inputs BEFORE proving (Groth16::prove consumes the circuit).
    let public_inputs_field = circuit.get_public_inputs();
    let public_inputs_serialized = circuit
        .get_public_inputs_serialized()
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize public inputs: {e}")))?;

    // Witness sanity check — fail fast with a clear message rather than emitting
    // a proof that will never verify.
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit
        .clone()
        .generate_constraints(cs.clone())
        .map_err(|e| JsValue::from_str(&format!("Failed to generate constraints: {e}")))?;
    let satisfied = cs
        .is_satisfied()
        .map_err(|e| JsValue::from_str(&format!("Failed to check constraints: {e}")))?;
    if !satisfied {
        return Err(JsValue::from_str(&format!(
            "Constraints not satisfied (witness invalid): {:?}",
            cs.which_is_unsatisfied().ok().flatten()
        )));
    }

    // REAL ENTROPY: OsRng -> getrandom(js) -> crypto.getRandomValues. NOT seeded.
    let mut rng = OsRng;
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("Failed to generate proof: {e}")))?;

    // Per-component compressed bytes.
    let mut proof_a_bytes = Vec::new();
    proof
        .a
        .serialize_compressed(&mut proof_a_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize proof.a: {e}")))?;
    let mut proof_b_bytes = Vec::new();
    proof
        .b
        .serialize_compressed(&mut proof_b_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize proof.b: {e}")))?;
    let mut proof_c_bytes = Vec::new();
    proof
        .c
        .serialize_compressed(&mut proof_c_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize proof.c: {e}")))?;

    // Sui-format proof bytes: A ‖ B ‖ C (== prover::proof_hex).
    let mut proof_serialized = Vec::with_capacity(128);
    proof_serialized.extend_from_slice(&proof_a_bytes);
    proof_serialized.extend_from_slice(&proof_b_bytes);
    proof_serialized.extend_from_slice(&proof_c_bytes);

    // Public inputs as decimal strings (Vortex's shape).
    let public_inputs: Vec<String> = public_inputs_field
        .iter()
        .map(|fe| fe.into_bigint().to_string())
        .collect();

    // Sui-format public inputs: 8 × 32-byte LITTLE-ENDIAN (== prover::public_inputs_hex).
    let mut pubs_le = Vec::with_capacity(public_inputs_field.len() * 32);
    for fe in &public_inputs_field {
        let mut le = fe.into_bigint().to_bytes_le();
        le.resize(32, 0u8);
        pubs_le.extend_from_slice(&le);
    }

    // We deliberately keep `public_inputs_serialized` (arkworks-compressed, same
    // as the native helper) as the proof-JSON carrier used by `verify` below, so
    // the round-trip is identical to Vortex. The Sui-LE layout is exposed
    // separately for the Move path.
    let _ = &public_inputs_serialized; // kept for parity / future use

    let output = ProofOutput {
        proof_a: proof_a_bytes,
        proof_b: proof_b_bytes,
        proof_c: proof_c_bytes,
        public_inputs,
        proof_serialized_hex: hex::encode(proof_serialized),
        public_inputs_serialized_hex: hex::encode(pubs_le),
    };

    serde_json::to_string(&output)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize output: {e}")))
}

/// Verify a proof in-wasm against a verifying key. Useful for a self-check
/// before submitting to chain, and for the test harness.
///
/// * `proof_json`         — JSON-serialized [`ProofOutput`] from [`prove`].
/// * `verifying_key_hex`  — hex of the arkworks compressed verifying key
///                          (`keys/verifying_key.bin` / `vk_sui.hex`).
#[wasm_bindgen]
pub fn verify(proof_json: &str, verifying_key_hex: &str) -> Result<bool, JsValue> {
    let proof_output: ProofOutput = serde_json::from_str(proof_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse proof JSON: {e}")))?;

    let vk_bytes = hex::decode(verifying_key_hex.trim())
        .map_err(|e| JsValue::from_str(&format!("Failed to decode VK hex: {e}")))?;
    let vk = ark_groth16::VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..])
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize VK: {e}")))?;
    let pvk = ark_groth16::prepare_verifying_key(&vk);

    // Rebuild the proof from the A‖B‖C bytes (== Sui proof layout).
    let proof_bytes = hex::decode(&proof_output.proof_serialized_hex)
        .map_err(|e| JsValue::from_str(&format!("Failed to decode proof hex: {e}")))?;
    if proof_bytes.len() != 128 {
        return Err(JsValue::from_str(&format!(
            "proof must be 128 bytes (A32‖B64‖C32), got {}",
            proof_bytes.len()
        )));
    }
    let a = ark_bn254::G1Affine::deserialize_compressed(&proof_bytes[0..32])
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize proof.a: {e}")))?;
    let b = ark_bn254::G2Affine::deserialize_compressed(&proof_bytes[32..96])
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize proof.b: {e}")))?;
    let c = ark_bn254::G1Affine::deserialize_compressed(&proof_bytes[96..128])
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize proof.c: {e}")))?;
    let proof = ark_groth16::Proof::<Bn254> { a, b, c };

    let public_inputs: Result<Vec<Fr>, JsValue> = proof_output
        .public_inputs
        .iter()
        .enumerate()
        .map(|(i, s)| {
            parse_field_element(s)
                .map_err(|e| JsValue::from_str(&format!("Failed to parse public input {i}: {e:?}")))
        })
        .collect();
    let public_inputs = public_inputs?;

    Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs)
        .map_err(|e| JsValue::from_str(&format!("Verify failed: {e}")))
}

/// Build a valid DEPOSIT [`ProofInput`] JSON for a pool, without the caller
/// having to reimplement Poseidon in JS. Mirrors the native
/// `prover::build_deposit_circuit_for_pool`: dummy (zero) input notes + two
/// fresh output notes summing to `amount`, `hashed_account_secret == 0`.
///
/// * `pool_hex`  — 0x-prefixed Sui pool address (bound into `vortex`).
/// * `root_dec`  — Merkle root as a u256 decimal string (commonly "0" for deposit).
/// * `amount`    — total deposit amount (== public_value).
/// * `out0`,`out1` — output split; MUST sum to `amount`.
///
/// Returns the JSON to feed straight into [`prove`]. This is the deposit-leg
/// witness assembler; withdraw/internal-transfer witnesses (real input notes +
/// Merkle paths) are assembled by the SDK and passed to [`prove`] directly.
#[wasm_bindgen]
pub fn build_deposit_input(
    pool_hex: &str,
    root_dec: &str,
    amount: u64,
    out0: u64,
    out1: u64,
) -> Result<String, JsValue> {
    use crate::prover::{
        build_deposit_circuit_for_pool, pool_address_to_field, u256_decimal_to_field,
    };

    if out0.checked_add(out1) != Some(amount) {
        return Err(JsValue::from_str(&format!(
            "output split {out0}+{out1} must sum to amount {amount} (value conservation)"
        )));
    }

    let vortex = pool_address_to_field(pool_hex)
        .map_err(|e| JsValue::from_str(&format!("bad pool address: {e}")))?;
    let root = u256_decimal_to_field(root_dec)
        .map_err(|e| JsValue::from_str(&format!("bad root: {e}")))?;

    let (circuit, _notes) = build_deposit_circuit_for_pool(vortex, root, amount, out0, out1)
        .map_err(|e| JsValue::from_str(&format!("build deposit witness failed: {e}")))?;

    // Empty Merkle paths (zero-value inputs => membership check skipped).
    let empty_path: Vec<[String; 2]> = (0..MERKLE_TREE_LEVEL)
        .map(|_| ["0".to_string(), "0".to_string()])
        .collect();
    let fe = |x: &Fr| x.into_bigint().to_string();

    let input = serde_json::json!({
        "vortex": fe(&circuit.vortex),
        "root": fe(&circuit.root),
        "publicAmount": fe(&circuit.public_amount),
        "inputNullifier0": fe(&circuit.input_nullifier_0),
        "inputNullifier1": fe(&circuit.input_nullifier_1),
        "outputCommitment0": fe(&circuit.output_commitment_0),
        "outputCommitment1": fe(&circuit.output_commitment_1),
        "hashedAccountSecret": fe(&circuit.hashed_account_secret),
        "accountSecret": fe(&circuit.account_secret),
        "inPrivateKey0": fe(&circuit.in_private_keys[0]),
        "inPrivateKey1": fe(&circuit.in_private_keys[1]),
        "inAmount0": fe(&circuit.in_amounts[0]),
        "inAmount1": fe(&circuit.in_amounts[1]),
        "inBlinding0": fe(&circuit.in_blindings[0]),
        "inBlinding1": fe(&circuit.in_blindings[1]),
        "inPathIndex0": fe(&circuit.in_path_indices[0]),
        "inPathIndex1": fe(&circuit.in_path_indices[1]),
        "merklePath0": empty_path,
        "merklePath1": empty_path,
        "outPublicKey0": fe(&circuit.out_public_keys[0]),
        "outPublicKey1": fe(&circuit.out_public_keys[1]),
        "outAmount0": fe(&circuit.out_amounts[0]),
        "outAmount1": fe(&circuit.out_amounts[1]),
        "outBlinding0": fe(&circuit.out_blindings[0]),
        "outBlinding1": fe(&circuit.out_blindings[1]),
    });

    serde_json::to_string(&input)
        .map_err(|e| JsValue::from_str(&format!("serialize deposit input failed: {e}")))
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

fn parse_field_element(s: &str) -> Result<Fr, JsValue> {
    let s = s.trim();
    let big_uint = if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        BigUint::parse_bytes(hex_str.as_bytes(), 16)
            .ok_or_else(|| JsValue::from_str(&format!("Failed to parse hex '{s}'")))?
    } else {
        BigUint::from_str(s)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse decimal '{s}': {e}")))?
    };
    Ok(Fr::from(big_uint))
}

fn parse_merkle_path(path_data: &[[String; 2]]) -> Result<Path<MERKLE_TREE_LEVEL>, JsValue> {
    if path_data.len() != MERKLE_TREE_LEVEL {
        return Err(JsValue::from_str(&format!(
            "Invalid Merkle path length: expected {MERKLE_TREE_LEVEL}, got {}",
            path_data.len()
        )));
    }
    let mut path = [(Fr::from(0u64), Fr::from(0u64)); MERKLE_TREE_LEVEL];
    for (i, pair) in path_data.iter().enumerate() {
        path[i] = (parse_field_element(&pair[0])?, parse_field_element(&pair[1])?);
    }
    Ok(Path { path })
}
