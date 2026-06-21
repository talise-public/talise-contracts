/// Talise privacy — height-26 incremental Merkle tree over BN254
/// (Workstream A, mirrors `vortex_merkle_tree`). Two leaves are appended per
/// `transact`, the same as the circuit's 2-out shape, so the bottom level is
/// pre-combined with one `poseidon2(commitment0, commitment1)` and the walk up
/// starts at level 1.
///
/// CRITICAL (Phase-0 gate): the hash here is `sui::poseidon::poseidon_bn254`,
/// which MUST be byte-identical to the circuit's in-circuit Poseidon gadget —
/// otherwise no deposit is ever spendable. The cross-check is `merkle::new()
/// .root() == Rust-derived empty root` (see merkle_tests + PRIVACY-BUILD-PLAN).
module talise_privacy::merkle;

use std::u64;
use sui::{poseidon, table::{Self, Table}};
use talise_privacy::constants;

/// Local mirror of `errors::EMerkleTreeOverflow` (808) — declared here so the
/// `assert!` references a same-module named constant (W04005). See `errors.move`
/// for the canonical registry.
const EMerkleTreeOverflow: u64 = 808;

// === Structs ===

public struct MerkleTree has key, store {
    id: UID,
    /// Index of the next leaf to write (always even — leaves go in pairs).
    next_index: u64,
    /// Per-level "frontier": the left-sibling hash cached at each level.
    subtrees: vector<u256>,
    /// Ring buffer of the last ROOT_HISTORY_SIZE roots, keyed by ring index.
    root_history: Table<u64, u256>,
    /// Current head of the ring buffer.
    root_index: u64,
}

// === Package Mutative Functions ===

public(package) fun new(ctx: &mut TxContext): MerkleTree {
    let empty_subtree_hashes = constants::empty_subtree_hashes!();
    let height = constants::height!();

    let mut root_history = table::new(ctx);
    // Genesis root = the empty-tree hash at the top level (index HEIGHT).
    root_history.add(0, empty_subtree_hashes[height]);

    let mut subtrees = vector[];
    u64::range_do!(0, height, |i| {
        subtrees.push_back(empty_subtree_hashes[i]);
    });

    MerkleTree {
        id: object::new(ctx),
        next_index: 0,
        subtrees,
        root_history,
        root_index: 0,
    }
}

/// Append two commitments at once (matches the circuit's 2-out shape).
public(package) fun append_pair(self: &mut MerkleTree, commitment0: u256, commitment1: u256) {
    let height = constants::height!();
    let root_history_size = constants::root_history_size!();

    // Capacity check: 2^HEIGHT total leaves.
    assert!(
        (1u64 << (height as u8)) > self.next_index,
        EMerkleTreeOverflow,
    );

    // The two new leaves combine into one node at level 1.
    let mut current_index = self.next_index / 2;
    let mut current_level_hash = poseidon2(commitment0, commitment1);
    let empty_subtree_hashes = constants::empty_subtree_hashes!();

    // Walk levels 1..HEIGHT, folding in the cached frontier.
    u64::range_do!(1, height, |i| {
        let subtree = &mut self.subtrees[i];
        let mut left: u256;
        let mut right: u256;

        if (current_index % 2 == 0) {
            // We are the left child: cache ourselves, pair with the empty sibling.
            left = current_level_hash;
            right = empty_subtree_hashes[i];
            *subtree = current_level_hash;
        } else {
            // We are the right child: pair with the cached left sibling.
            left = *subtree;
            right = current_level_hash;
        };

        current_level_hash = poseidon2(left, right);
        current_index = current_index / 2;
    });

    // Advance the root ring buffer.
    let new_root_index = (self.root_index + 1) % root_history_size;
    self.root_index = new_root_index;
    self.safe_history_add(new_root_index, current_level_hash);
    self.next_index = self.next_index + 2;
}

// === Package View Functions ===

public(package) fun root(self: &MerkleTree): u256 {
    self.root_history[self.root_index]
}

public(package) fun next_index(self: &MerkleTree): u64 {
    self.next_index
}

/// Is `root` one of the last ROOT_HISTORY_SIZE roots? Walks the ring backwards
/// from the head. The all-ZERO root is never "known".
public(package) fun is_known_root(self: &MerkleTree, root: u256): bool {
    if (root == 0) return false;

    let root_history_size = constants::root_history_size!();
    let mut i = self.root_index;

    loop {
        if (self.root_history.contains(i)) {
            if (self.root_history[i] == root) {
                return true
            };
        };

        if (i == 0) {
            i = root_history_size - 1;
        } else {
            i = i - 1;
        };

        if (i == self.root_index) break;
    };

    false
}

// === Private Functions ===

fun safe_history_add(self: &mut MerkleTree, index: u64, value: u256) {
    if (self.root_history.contains(index)) {
        let old_value = &mut self.root_history[index];
        *old_value = value;
    } else {
        self.root_history.add(index, value);
    };
}

fun poseidon2(a: u256, b: u256): u256 {
    poseidon::poseidon_bn254(&vector[a, b])
}
