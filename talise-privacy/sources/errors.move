/// Talise privacy — the CANONICAL abort-code registry (Workstream A).
///
/// 8xx range so codes never collide with `talise_yield::yield_router`'s 4xx
/// codes if both packages ever surface errors through a shared SDK. This module
/// is the single source of truth for the numbering; the modules that actually
/// `assert!` declare a LOCAL `const` with the matching number (the
/// `yield_router` idiom) so the W04005 "abort without named constant" lint is
/// satisfied — a bare `const` is module-private, and the lint only recognizes a
/// directly-referenced same-module constant. Keep the two in sync; this module
/// is what you read to see the whole map.
///
/// The accessor funcs below let off-chain code / future modules read a code by
/// name without hardcoding the literal.
module talise_privacy::errors;

/// Proof targets a Merkle root the pool has never held (stale / forged root).
const EProofRootNotKnown: u64 = 800;
/// `groth16::verify_groth16_proof` returned false.
const EInvalidProof: u64 = 801;
/// The proof's bound pool address != this pool's address (cross-pool replay).
const EInvalidPool: u64 = 802;
/// A revealed input nullifier was already spent (double-spend).
const ENullifierAlreadySpent: u64 = 803;
/// `proof.public_value() != ext_data.public_value()` (deposit/withdraw mismatch).
const EInvalidPublicValue: u64 = 804;
/// Deposit leg: supplied coin value != `ext_data.value`.
const EInvalidDepositValue: u64 = 805;
/// `ext_data.relayer` is set but does not match `ctx.sender()`.
const EInvalidRelayer: u64 = 806;
/// A pool already exists for this CoinType in the registry.
const EPoolAlreadyExists: u64 = 807;
/// Merkle tree at capacity (2^HEIGHT leaves).
const EMerkleTreeOverflow: u64 = 808;
/// A field element (nullifier / commitment / secret) is >= the BN254 modulus
/// (or a hashed_secret is zero).
const EValueExceedsFieldModulus: u64 = 809;
/// Compliance gate refused the cleartext public leg (cap / pause / denylist).
/// Fail-closed, applied AFTER the proof so soundness is untouched.
const EComplianceRefused: u64 = 810;

// === Package View Functions ===

public(package) fun proof_root_not_known(): u64 { EProofRootNotKnown }
public(package) fun invalid_proof(): u64 { EInvalidProof }
public(package) fun invalid_pool(): u64 { EInvalidPool }
public(package) fun nullifier_already_spent(): u64 { ENullifierAlreadySpent }
public(package) fun invalid_public_value(): u64 { EInvalidPublicValue }
public(package) fun invalid_deposit_value(): u64 { EInvalidDepositValue }
public(package) fun invalid_relayer(): u64 { EInvalidRelayer }
public(package) fun pool_already_exists(): u64 { EPoolAlreadyExists }
public(package) fun merkle_tree_overflow(): u64 { EMerkleTreeOverflow }
public(package) fun value_exceeds_field_modulus(): u64 { EValueExceedsFieldModulus }
public(package) fun compliance_refused(): u64 { EComplianceRefused }
