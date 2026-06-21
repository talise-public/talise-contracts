/// Talise privacy — on-chain events (Workstream A, mirrors `vortex_events`).
/// The indexer (Workstream C) polls `NewCommitment` to rebuild the Merkle tree
/// and `NullifierSpent` to mark notes spent. `NewPool` registers a pool's
/// address per CoinType.
module talise_privacy::events;

use sui::event::emit;

// === Events ===

/// Emitted when a `ShieldedPool<CoinType>` is created. Payload = pool address.
public struct NewPool<phantom CoinType> has copy, drop { pool: address }

/// Emitted per appended commitment (two per `transact`). The indexer keys the
/// Merkle leaf by `index`; `encrypted_output` is the note ciphertext the
/// recipient trial-decrypts.
public struct NewCommitment<phantom CoinType> has copy, drop {
    index: u64,
    commitment: u256,
    encrypted_output: vector<u8>,
}

/// Emitted per spent input nullifier. The indexer marks the note unspendable.
public struct NullifierSpent<phantom CoinType> has copy, drop { nullifier: u256 }

// === Package Functions ===

public(package) fun new_pool<CoinType>(pool: address) {
    emit(NewPool<CoinType> { pool });
}

public(package) fun new_commitment<CoinType>(
    index: u64,
    commitment: u256,
    encrypted_output: vector<u8>,
) {
    emit(NewCommitment<CoinType> { index, commitment, encrypted_output });
}

public(package) fun nullifier_spent<CoinType>(nullifier: u256) {
    emit(NullifierSpent<CoinType> { nullifier });
}
