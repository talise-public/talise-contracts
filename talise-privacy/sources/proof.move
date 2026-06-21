/// Talise privacy — typed Groth16 proof + the ordered public-input assembly
/// (Workstream A, mirrors `vortex_proof`). The CRITICAL piece is the fixed
/// 8-input order:
///
///   [pool, root, public_value, null0, null1, comm0, comm1, hashed_secret]
///
/// This order is the contract between the circuit and `sui::groth16`. Each
/// input is a 32-byte little-endian field element (BCS of a `u256` reduced mod
/// the BN254 modulus); the verifier concatenates them in this exact sequence.
/// Any reorder silently breaks soundness, so it lives in one place.
module talise_privacy::proof;

use sui::{bcs, groth16::{Self, PublicProofInputs, ProofPoints}};
use talise_privacy::constants;

/// Local mirror of `errors::EValueExceedsFieldModulus` (809). See `errors.move`
/// for the canonical registry; declared locally so `assert!` names a same-module
/// constant (W04005).
const EValueExceedsFieldModulus: u64 = 809;

// === Structs ===

public struct Proof<phantom CoinType> has copy, drop, store {
    root: u256,
    points: ProofPoints,
    input_nullifiers: vector<u256>,
    output_commitments: vector<u256>,
    public_value: u256,
    /// The pool address this proof is bound to (anti cross-pool replay).
    pool: address,
}

// === Public View Functions ===

public fun new<CoinType>(
    pool: address,
    proof_points: vector<u8>,
    root: u256,
    public_value: u256,
    input_nullifier0: u256,
    input_nullifier1: u256,
    output_commitment0: u256,
    output_commitment1: u256,
): Proof<CoinType> {
    input_nullifier0.assert_is_valid_field_element!();
    input_nullifier1.assert_is_valid_field_element!();
    output_commitment0.assert_is_valid_field_element!();
    output_commitment1.assert_is_valid_field_element!();

    Proof {
        root,
        points: groth16::proof_points_from_bytes(proof_points),
        input_nullifiers: vector[input_nullifier0, input_nullifier1],
        output_commitments: vector[output_commitment0, output_commitment1],
        public_value,
        pool,
    }
}

// === Package View Functions ===

public(package) fun root<CoinType>(self: Proof<CoinType>): u256 { self.root }

public(package) fun points<CoinType>(self: Proof<CoinType>): ProofPoints { self.points }

public(package) fun input_nullifiers<CoinType>(self: Proof<CoinType>): vector<u256> {
    self.input_nullifiers
}

public(package) fun output_commitments<CoinType>(self: Proof<CoinType>): vector<u256> {
    self.output_commitments
}

public(package) fun public_value<CoinType>(self: Proof<CoinType>): u256 { self.public_value }

public(package) fun pool<CoinType>(self: Proof<CoinType>): address { self.pool }

/// Assemble the 8 ordered public inputs with a ZERO `hashed_secret` (the
/// unsponsored / `transact` path, where no account-secret is bound in).
public(package) fun public_inputs<CoinType>(self: Proof<CoinType>): PublicProofInputs {
    self.make_public_inputs(bcs::to_bytes(&0u256))
}

/// Same 8 inputs but with a real `hashed_secret` (the sponsored
/// `transact_with_account` path that binds a `NoteAccount` secret).
public(package) fun account_public_inputs<CoinType>(
    self: Proof<CoinType>,
    hashed_secret: u256,
): PublicProofInputs {
    self.make_public_inputs(hashed_secret.to_field())
}

// === Private Functions ===

fun make_public_inputs<CoinType>(
    self: Proof<CoinType>,
    hashed_secret_bytes: vector<u8>,
): PublicProofInputs {
    let bytes = vector[
        self.pool.to_u256().to_field(),
        self.root.to_field(),
        self.public_value.to_field(),
        self.input_nullifiers[0].to_field(),
        self.input_nullifiers[1].to_field(),
        self.output_commitments[0].to_field(),
        self.output_commitments[1].to_field(),
        hashed_secret_bytes,
    ];

    groth16::public_proof_inputs_from_bytes(bytes.flatten())
}

/// Reduce mod the field and BCS-encode (32-byte LE) — the wire format
/// `sui::groth16` expects for each public input.
fun to_field(value: u256): vector<u8> {
    bcs::to_bytes(&(value % constants::bn254_field_modulus!()))
}

// === Macros ===

macro fun assert_is_valid_field_element($value: u256) {
    assert!(
        $value < constants::bn254_field_modulus!(),
        EValueExceedsFieldModulus,
    );
}

// === Aliases ===

use fun to_field as u256.to_field;
use fun assert_is_valid_field_element as u256.assert_is_valid_field_element;
