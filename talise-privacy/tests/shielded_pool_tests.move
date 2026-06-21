/// Money-path tests for `talise_privacy::shielded_pool`.
///
/// The groth16 verify uses a DEV placeholder VK, so no REAL passing proof is
/// producible in Move. So we test (a) pool lifecycle + PoolAdminCap admin, and
/// (b) every `process_transaction` guard that fires BEFORE or AT verify — those
/// don't need a valid proof: pool-address bind, known-root, relayer,
/// public-value tie, and that verify itself REJECTS a garbage proof (proving it
/// is wired). The nullifier-already-spent + compliance-gate branches sit AFTER
/// verify, so they're unreachable without a valid proof (the dev VK rejects
/// everything) — documented, not faked.
#[test_only]
module talise_privacy::shielded_pool_tests;

use std::unit_test::assert_eq;
use sui::{coin, sui::SUI, test_scenario as ts};
use talise_privacy::{
    shielded_pool::{Self, Registry, ShieldedPool, PoolAdminCap},
    proof,
    ext_data,
};

const ADMIN: address = @0xA;
const USER: address = @0xB;

/// 128-byte (32 G1 + 64 G2 + 32 G1) dummy compressed proof — parsed by
/// `proof_points_from_bytes` but rejected at verify (the point of the verify test).
fun dummy_points(): vector<u8> {
    let mut v = vector::empty<u8>();
    128u64.do!(|_| v.push_back(0u8));
    v
}

fun setup(s: &mut ts::Scenario) {
    ts::next_tx(s, ADMIN);
    shielded_pool::test_init(ts::ctx(s));
}

/// Create + share a SUI pool; the cap goes to ADMIN. Returns the pool address.
fun create_pool(s: &mut ts::Scenario): address {
    ts::next_tx(s, ADMIN);
    let mut reg = ts::take_shared<Registry>(s);
    let (pool, cap) = shielded_pool::new<SUI>(&mut reg, ts::ctx(s));
    let addr = object::id_address(&pool);
    shielded_pool::share(pool);
    transfer::public_transfer(cap, ADMIN);
    ts::return_shared(reg);
    addr
}

// === Lifecycle + admin ===

#[test]
fun create_and_admin_caps() {
    let mut s = ts::begin(ADMIN);
    setup(&mut s);
    create_pool(&mut s);

    ts::next_tx(&mut s, ADMIN);
    let mut pool = ts::take_shared<ShieldedPool<SUI>>(&s);
    let cap = ts::take_from_sender<PoolAdminCap>(&s);
    assert_eq!(shielded_pool::is_paused(&pool), false);
    assert_eq!(shielded_pool::balance_value(&pool), 0);
    assert_eq!(shielded_pool::next_index(&pool), 0);
    shielded_pool::set_caps(&mut pool, &cap, 100, 50);
    shielded_pool::set_paused(&mut pool, &cap, true);
    assert_eq!(shielded_pool::is_paused(&pool), true);
    ts::return_to_sender(&s, cap);
    ts::return_shared(pool);
    ts::end(s);
}

// === transact guards (no valid proof needed) ===

#[test, expected_failure(abort_code = shielded_pool::EInvalidPool)]
fun transact_wrong_pool_aborts() {
    let mut s = ts::begin(ADMIN);
    setup(&mut s);
    create_pool(&mut s);
    ts::next_tx(&mut s, USER);
    let mut pool = ts::take_shared<ShieldedPool<SUI>>(&s);
    // proof bound to a DIFFERENT pool address → step 1 aborts.
    let p = proof::new<SUI>(@0xBAD, dummy_points(), 0, 1, 1, 2, 3, 4);
    let e = ext_data::new(1, true, @0x0, 0, vector[], vector[]);
    let c = coin::mint_for_testing<SUI>(1, ts::ctx(&mut s));
    let out = shielded_pool::transact(&mut pool, c, p, e, ts::ctx(&mut s));
    coin::burn_for_testing(out);
    ts::return_shared(pool);
    ts::end(s);
}

#[test, expected_failure(abort_code = shielded_pool::EProofRootNotKnown)]
fun transact_unknown_root_aborts() {
    let mut s = ts::begin(ADMIN);
    setup(&mut s);
    let addr = create_pool(&mut s);
    ts::next_tx(&mut s, USER);
    let mut pool = ts::take_shared<ShieldedPool<SUI>>(&s);
    // correct pool, but a root the tree never held → step 2 aborts.
    let p = proof::new<SUI>(addr, dummy_points(), 999999, 1, 1, 2, 3, 4);
    let e = ext_data::new(1, true, @0x0, 0, vector[], vector[]);
    let c = coin::mint_for_testing<SUI>(1, ts::ctx(&mut s));
    let out = shielded_pool::transact(&mut pool, c, p, e, ts::ctx(&mut s));
    coin::burn_for_testing(out);
    ts::return_shared(pool);
    ts::end(s);
}

#[test, expected_failure(abort_code = talise_privacy::ext_data::EInvalidRelayer)]
fun transact_wrong_relayer_aborts() {
    let mut s = ts::begin(ADMIN);
    setup(&mut s);
    let addr = create_pool(&mut s);
    ts::next_tx(&mut s, USER);
    let mut pool = ts::take_shared<ShieldedPool<SUI>>(&s);
    let root = shielded_pool::root(&pool); // genesis root → passes step 2
    assert_eq!(pool.is_known_root(root), true);
    // ext names a relayer that isn't the sender → step 3 aborts.
    let p = proof::new<SUI>(addr, dummy_points(), root, 1, 1, 2, 3, 4);
    let e = ext_data::new(1, true, @0xCAFE, 0, vector[], vector[]);
    let c = coin::mint_for_testing<SUI>(1, ts::ctx(&mut s));
    let out = shielded_pool::transact(&mut pool, c, p, e, ts::ctx(&mut s));
    coin::burn_for_testing(out);
    ts::return_shared(pool);
    ts::end(s);
}

#[test, expected_failure(abort_code = shielded_pool::EInvalidPublicValue)]
fun transact_public_value_mismatch_aborts() {
    let mut s = ts::begin(ADMIN);
    setup(&mut s);
    let addr = create_pool(&mut s);
    ts::next_tx(&mut s, USER);
    let mut pool = ts::take_shared<ShieldedPool<SUI>>(&s);
    let root = shielded_pool::root(&pool);
    // proof.public_value (7) != ext.public_value (deposit value 1, fee 0 ⇒ 1) → step 4 aborts.
    let p = proof::new<SUI>(addr, dummy_points(), root, 7, 1, 2, 3, 4);
    let e = ext_data::new(1, true, @0x0, 0, vector[], vector[]);
    let c = coin::mint_for_testing<SUI>(1, ts::ctx(&mut s));
    let out = shielded_pool::transact(&mut pool, c, p, e, ts::ctx(&mut s));
    coin::burn_for_testing(out);
    ts::return_shared(pool);
    ts::end(s);
}

#[test, expected_failure(abort_code = shielded_pool::EInvalidProof)]
fun transact_garbage_proof_fails_verify() {
    let mut s = ts::begin(ADMIN);
    setup(&mut s);
    let addr = create_pool(&mut s);
    ts::next_tx(&mut s, USER);
    let mut pool = ts::take_shared<ShieldedPool<SUI>>(&s);
    let root = shielded_pool::root(&pool);
    // all pre-verify guards pass (pool ok, genesis root, no relayer,
    // public_value matches) → reaches step 6; the garbage proof is REJECTED.
    let p = proof::new<SUI>(addr, dummy_points(), root, 1, 1, 2, 3, 4);
    let e = ext_data::new(1, true, @0x0, 0, vector[], vector[]);
    let c = coin::mint_for_testing<SUI>(1, ts::ctx(&mut s));
    let out = shielded_pool::transact(&mut pool, c, p, e, ts::ctx(&mut s));
    coin::burn_for_testing(out);
    ts::return_shared(pool);
    ts::end(s);
}
