/// THE Phase-0 Poseidon gate (Move side).
///
/// This test recomputes — INDEPENDENTLY of `merkle.move`'s internal frontier
/// path — (a) the empty-subtree hash series and (b) the root of a small tree
/// after appending the pairs (1,2) then (3,4), using `sui::poseidon::
/// poseidon_bn254` directly. It then asserts `merkle::root()` equals that manual
/// recomputation. This proves the Move tree is internally consistent with the
/// raw native Poseidon hash (not merely self-consistent with its own bug).
///
/// The Rust/circuit cross-check (Move-root == Rust-root) is the OTHER half of
/// the Phase-0 gate; a parallel agent is producing the exact decimal root that
/// the arkworks circuit derives for the same (1,2)+(3,4) tree. When that value
/// lands, drop it into `RUST_ROOT_PAIRS_12_34` below and flip
/// `RUST_ROOT_AVAILABLE` to `true` — that is the ONE-LINE change that turns the
/// cross-chain assertion on. Until then the Rust leg is skipped (not failed) so
/// CI stays green without a placeholder masquerading as a real value.
#[test_only]
module talise_privacy::poseidon_root_tests;

use std::unit_test::{assert_eq, destroy};
use sui::{poseidon, test_scenario as ts};
use talise_privacy::{constants, merkle};

const ADMIN: address = @0xA;

const HEIGHT: u64 = 26;

/// The empty-LEAF sentinel ("zero value") this tree uses — index 0 of the
/// committed `empty_subtree_hashes`. It is NOT literal 0 (it's the canonical
/// Tornado-Nova / BN254 zero value); the whole empty-subtree chain is built by
/// repeatedly self-hashing it, so we seed the independent recompute from the
/// SAME sentinel and then verify the chain (and the committed series) match
/// native Poseidon. Verified against the constant in
/// `empty_subtree_hashes_match_native_poseidon`.
const ZERO_LEAF: u256 =
    18688842432741139442778047327644092677418528270738216181718229581494125774932;

// === Rust-side cross-check placeholder (one-line drop-in) ===
//
// PLACEHOLDER — replaced by the parallel agent producing the arkworks-derived
// decimal root for a height-26 tree with leaves (1,2,3,4). When set, flip
// RUST_ROOT_AVAILABLE to true; the test will then assert merkle::root() == it.
const RUST_ROOT_AVAILABLE: bool = true;
const RUST_ROOT_PAIRS_12_34: u256 = 17030486334130427295495872518529323599496048152514727555221161595116072438956;

fun poseidon2(a: u256, b: u256): u256 {
    poseidon::poseidon_bn254(&vector[a, b])
}

/// Recompute the empty-subtree hash series from scratch: h[0] is the empty-leaf
/// sentinel (ZERO_LEAF), h[i] = poseidon2(h[i-1], h[i-1]). Returns HEIGHT+1 ==
/// 27 entries. Crucially this does NOT read the committed constant — it derives
/// the whole chain from the single seed using native Poseidon, so matching the
/// constant is a real cross-check, not a tautology.
fun recompute_empty_subtree_hashes(): vector<u256> {
    let mut out = vector[ZERO_LEAF];
    HEIGHT.do!(|i| {
        let prev = out[i];
        out.push_back(poseidon2(prev, prev));
    });
    out
}

/// The committed `empty_subtree_hashes` constant must equal a fresh native
/// recomputation — i.e. the published series really is the BN254 empty-tree
/// hash chain, not arbitrary bytes. (If this ever fails, the constant must be
/// regenerated from `poseidon_bn254` directly.)
#[test]
fun empty_subtree_hashes_match_native_poseidon() {
    let expected = recompute_empty_subtree_hashes();
    let committed = constants::empty_subtree_hashes!();

    assert_eq!(committed.length(), HEIGHT + 1);
    assert_eq!(expected.length(), HEIGHT + 1);

    expected.length().do!(|i| {
        assert_eq!(committed[i], expected[i]);
    });
}

/// A fresh tree's genesis root is the top empty-subtree hash (index HEIGHT),
/// recomputed natively here rather than read from the constant.
#[test]
fun genesis_root_equals_manual_empty_root() {
    let mut scenario = ts::begin(ADMIN);
    let tree = merkle::new(ts::ctx(&mut scenario));

    let empties = recompute_empty_subtree_hashes();
    assert_eq!(tree.root(), empties[HEIGHT]);

    destroy(tree);
    ts::end(scenario);
}

/// Manually fold a single level-1 node `n` (a pair already poseidon2'd) up the
/// tree against the empty-subtree siblings, producing the height-26 root. For a
/// tree whose ONLY non-empty content is the leftmost pair, every node above
/// level 1 is the left child paired with an empty-subtree sibling.
fun fold_single_left_node_to_root(level1_node: u256, empties: &vector<u256>): u256 {
    let mut current = level1_node;
    // Leftmost path: always the left child, empty sibling on the right.
    std::u64::range_do!(1, HEIGHT, |level| {
        current = poseidon2(current, empties[level]);
    });
    current
}

/// Cross-check: append (1,2) then (3,4) and assert `merkle::root()` equals a
/// fully INDEPENDENT manual recomputation.
///
/// After two pair-appends, leaves [0..4) are filled: indices 0,1 = (1,2) and
/// 2,3 = (3,4). At level 1 there are two non-empty nodes:
///   nodeA = poseidon2(1, 2)   (covers leaves 0,1)
///   nodeB = poseidon2(3, 4)   (covers leaves 2,3)
/// These combine at level 2 into poseidon2(nodeA, nodeB); everything above is
/// the left child paired with an empty sibling up to the root.
#[test]
fun root_after_pairs_12_34_matches_manual() {
    let mut scenario = ts::begin(ADMIN);
    let mut tree = merkle::new(ts::ctx(&mut scenario));

    tree.append_pair(1, 2);
    tree.append_pair(3, 4);
    let actual = tree.root();

    let empties = recompute_empty_subtree_hashes();

    // Level 1 nodes.
    let node_a = poseidon2(1, 2);
    let node_b = poseidon2(3, 4);
    // Level 2: the two filled level-1 nodes combine.
    let level2 = poseidon2(node_a, node_b);
    // Levels 2..HEIGHT: left child + empty sibling.
    let mut current = level2;
    std::u64::range_do!(2, HEIGHT, |level| {
        current = poseidon2(current, empties[level]);
    });
    let manual_root = current;

    assert_eq!(actual, manual_root);

    // Sanity: a single-pair tree built the same way is internally consistent
    // (exercises the leftmost-only helper independently of the two-pair path).
    let single_pair_node = poseidon2(1, 2);
    let single_pair_root = fold_single_left_node_to_root(single_pair_node, &empties);
    assert!(single_pair_root != manual_root); // two pairs differ from one

    // Rust-side cross-check — ONE-LINE activation (see header). Skipped until
    // the arkworks decimal root lands.
    if (RUST_ROOT_AVAILABLE) {
        assert_eq!(actual, RUST_ROOT_PAIRS_12_34);
    };

    destroy(tree);
    ts::end(scenario);
}
