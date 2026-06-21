/// Tests for `talise_privacy::merkle` — the height-26 incremental tree.
///
/// These assert the tree's OWN behavior (genesis vs post-append roots, ring
/// membership, paired-leaf indexing). The Phase-0 cross-chain gate
/// (Move-root == Rust-root) lives in the circuit repo's CI and is NOT
/// reproduced here — these tests only prove the Move side is internally
/// consistent and uses `sui::poseidon::poseidon_bn254`.
#[test_only]
module talise_privacy::merkle_tests;

use std::unit_test::{assert_eq, destroy};
use sui::test_scenario as ts;
use talise_privacy::merkle::{Self, MerkleTree};

const ADMIN: address = @0xA;

// A couple of arbitrary BN254 field elements to use as commitments.
const C0: u256 = 11111111111111111111;
const C1: u256 = 22222222222222222222;
const C2: u256 = 33333333333333333333;
const C3: u256 = 44444444444444444444;

fun fresh_tree(scenario: &mut ts::Scenario): MerkleTree {
    merkle::new(ts::ctx(scenario))
}

/// A brand-new tree has a non-zero genesis (empty) root, next_index 0, and its
/// own current root is "known" while a random root is not.
#[test]
fun genesis_root_is_nonzero_and_known() {
    let mut scenario = ts::begin(ADMIN);
    let tree = fresh_tree(&mut scenario);

    let genesis = tree.root();
    assert!(genesis != 0);
    assert_eq!(tree.next_index(), 0);
    // The all-zero root is never known.
    assert_eq!(tree.is_known_root(0), false);
    // A random root the tree never held is not known.
    assert_eq!(tree.is_known_root(123456789), false);
    // The genesis root IS known (it's history slot 0).
    assert_eq!(tree.is_known_root(genesis), true);

    destroy(tree);
    ts::end(scenario);
}

/// Appending a pair advances next_index by 2, produces a NEW non-zero root that
/// differs from genesis, and the new root is the one reported by `root()` and
/// recognized by `is_known_root`. A random root stays unknown.
#[test]
fun append_pair_changes_root_and_is_known() {
    let mut scenario = ts::begin(ADMIN);
    let mut tree = fresh_tree(&mut scenario);

    let genesis = tree.root();
    tree.append_pair(C0, C1);

    let root_after = tree.root();
    assert_eq!(tree.next_index(), 2);
    assert!(root_after != 0);
    assert!(root_after != genesis); // the tree actually moved
    assert_eq!(tree.is_known_root(root_after), true);
    assert_eq!(tree.is_known_root(987654321), false); // random root not known

    destroy(tree);
    ts::end(scenario);
}

/// Two appends => next_index 4, the latest root is current + known, AND the
/// previous root is still known (the ring buffer retains recent history).
#[test]
fun two_appends_keep_history_known() {
    let mut scenario = ts::begin(ADMIN);
    let mut tree = fresh_tree(&mut scenario);

    tree.append_pair(C0, C1);
    let root1 = tree.root();

    tree.append_pair(C2, C3);
    let root2 = tree.root();

    assert_eq!(tree.next_index(), 4);
    assert!(root2 != root1);
    assert_eq!(tree.is_known_root(root2), true); // current
    assert_eq!(tree.is_known_root(root1), true); // still in the ring

    destroy(tree);
    ts::end(scenario);
}

/// Determinism: two independently constructed trees fed the same leaves yield
/// the same root (proves `append_pair` is a pure function of its inputs).
#[test]
fun same_leaves_same_root() {
    let mut scenario = ts::begin(ADMIN);

    let mut a = fresh_tree(&mut scenario);
    let mut b = fresh_tree(&mut scenario);
    a.append_pair(C0, C1);
    b.append_pair(C0, C1);
    assert_eq!(a.root(), b.root());

    destroy(a);
    destroy(b);
    ts::end(scenario);
}
