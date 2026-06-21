/// Full-coverage tests for `talise::yield_router`.
///
/// A `Mock` object (key + store) stands in for a real venue receipt
/// (Suilend Obligation / NAVI AccountCap / Scallop sUSDC / AlphaLend
/// position) — the router custodies + rotates receipts opaquely, so the
/// type doesn't matter for its own logic. Covers: mint, deposit/take,
/// the inline rebalance authority (enable/pause/resume/disable), the
/// registry (worker set + circuit breaker), and the begin/end_rotation
/// hot-potato pair including every guard branch.
#[test_only]
module talise_yield::yield_router_tests;

use std::unit_test::assert_eq;
use sui::{clock, test_scenario as ts, transfer};
use talise_yield::yield_router::{Self, YieldPosition, RebalanceRegistry};

const ADMIN: address = @0xA;
const USER: address = @0xB;
const RANDO: address = @0xC;
const WORKER: address = @0xE;

const SUILEND: u8 = 1;
const NAVI: u8 = 2;

/// Stands in for a venue receipt — carries a notional like a real cToken /
/// sUSDC balance would, so it isn't a bare-UID struct the linter mistakes
/// for a capability.
public struct Mock has key, store { id: UID, notional: u64 }

fun mint_mock(scenario: &mut ts::Scenario): Mock {
    Mock { id: object::new(ts::ctx(scenario)), notional: 0 }
}

fun a_clock(scenario: &mut ts::Scenario): clock::Clock {
    clock::create_for_testing(ts::ctx(scenario))
}

fun setup(scenario: &mut ts::Scenario) {
    ts::next_tx(scenario, ADMIN);
    yield_router::new_registry(ts::ctx(scenario));
    ts::next_tx(scenario, ADMIN);
    let mut reg = ts::take_shared<RebalanceRegistry>(scenario);
    yield_router::add_worker(&mut reg, WORKER, ts::ctx(scenario));
    ts::return_shared(reg);
    ts::next_tx(scenario, USER);
    yield_router::mint_position(ts::ctx(scenario));
}

// ── Lifecycle ──────────────────────────────────────────────────────

#[test]
fun mint_sets_owner_and_empty_state() {
    let mut scenario = ts::begin(ADMIN);
    ts::next_tx(&mut scenario, USER);
    yield_router::mint_position(ts::ctx(&mut scenario));
    ts::next_tx(&mut scenario, USER);
    let pos = ts::take_shared<YieldPosition>(&scenario);
    assert_eq!(yield_router::owner(&pos), USER);
    assert_eq!(yield_router::basis_usdc(&pos), 0);
    assert_eq!(yield_router::active_venues(&pos), 0);
    assert_eq!(yield_router::rotations_total(&pos), 0);
    assert_eq!(yield_router::rebalance_enabled(&pos), false);
    ts::return_shared(pos);
    ts::end(scenario);
}

#[test]
fun deposit_then_take_tracks_basis_and_venue() {
    let mut scenario = ts::begin(ADMIN);
    setup(&mut scenario);

    ts::next_tx(&mut scenario, USER);
    let mut pos = ts::take_shared<YieldPosition>(&scenario);
    let m = mint_mock(&mut scenario);
    yield_router::deposit_receipt(&mut pos, m, NAVI, 1_000, ts::ctx(&mut scenario));
    assert_eq!(yield_router::basis_usdc(&pos), 1_000);
    assert_eq!(yield_router::holds(&pos, NAVI), true);

    let back: Mock = yield_router::take_receipt(&mut pos, NAVI, 400, ts::ctx(&mut scenario));
    assert_eq!(yield_router::basis_usdc(&pos), 600);
    assert_eq!(yield_router::holds(&pos, NAVI), false);
    transfer::public_transfer(back, USER);
    ts::return_shared(pos);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = yield_router::ENotOwner)]
fun deposit_by_non_owner_aborts() {
    let mut scenario = ts::begin(ADMIN);
    setup(&mut scenario);
    ts::next_tx(&mut scenario, RANDO);
    let mut pos = ts::take_shared<YieldPosition>(&scenario);
    let m = mint_mock(&mut scenario);
    yield_router::deposit_receipt(&mut pos, m, NAVI, 1, ts::ctx(&mut scenario));
    ts::return_shared(pos);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = yield_router::EVenueNotAllowed)]
fun deposit_unknown_venue_aborts() {
    let mut scenario = ts::begin(ADMIN);
    setup(&mut scenario);
    ts::next_tx(&mut scenario, USER);
    let mut pos = ts::take_shared<YieldPosition>(&scenario);
    let m = mint_mock(&mut scenario);
    yield_router::deposit_receipt(&mut pos, m, 9, 1, ts::ctx(&mut scenario)); // venue 9 invalid
    ts::return_shared(pos);
    ts::end(scenario);
}

// ── Rebalance authority ────────────────────────────────────────────

#[test]
fun enable_pause_resume_disable() {
    let mut scenario = ts::begin(ADMIN);
    setup(&mut scenario);
    ts::next_tx(&mut scenario, USER);
    let mut pos = ts::take_shared<YieldPosition>(&scenario);
    let clk = a_clock(&mut scenario);
    yield_router::enable_rebalance(&mut pos, 10_000, 50_000, 1_000_000, &clk, ts::ctx(&mut scenario));
    assert_eq!(yield_router::rebalance_enabled(&pos), true);
    yield_router::pause(&mut pos, ts::ctx(&mut scenario));
    yield_router::resume(&mut pos, ts::ctx(&mut scenario));
    yield_router::disable_rebalance(&mut pos, ts::ctx(&mut scenario));
    assert_eq!(yield_router::rebalance_enabled(&pos), false);
    clock::destroy_for_testing(clk);
    ts::return_shared(pos);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = yield_router::ENotOwner)]
fun enable_by_non_owner_aborts() {
    let mut scenario = ts::begin(ADMIN);
    setup(&mut scenario);
    ts::next_tx(&mut scenario, RANDO);
    let mut pos = ts::take_shared<YieldPosition>(&scenario);
    let clk = a_clock(&mut scenario);
    yield_router::enable_rebalance(&mut pos, 1, 1, 1, &clk, ts::ctx(&mut scenario));
    clock::destroy_for_testing(clk);
    ts::return_shared(pos);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = yield_router::ENotOwner)]
fun add_worker_by_non_admin_aborts() {
    let mut scenario = ts::begin(ADMIN);
    setup(&mut scenario);
    ts::next_tx(&mut scenario, RANDO);
    let mut reg = ts::take_shared<RebalanceRegistry>(&scenario);
    yield_router::add_worker(&mut reg, RANDO, ts::ctx(&mut scenario));
    ts::return_shared(reg);
    ts::end(scenario);
}

// ── Rotation (the hot-potato pair) ─────────────────────────────────

/// Drives a full NAVI → Suilend rotation: deposit a receipt, arm the
/// authority, then as the WORKER begin+end the rotation. Asserts the
/// receipt moved venues and the rotation counter ticked.
fun arm_and_deposit(scenario: &mut ts::Scenario, clk: &clock::Clock) {
    ts::next_tx(scenario, USER);
    let mut pos = ts::take_shared<YieldPosition>(scenario);
    let m = mint_mock(scenario);
    yield_router::deposit_receipt(&mut pos, m, NAVI, 5_000, ts::ctx(scenario));
    yield_router::enable_rebalance(&mut pos, 10_000, 50_000, 1_000_000, clk, ts::ctx(scenario));
    ts::return_shared(pos);
}

#[test]
fun rotation_moves_receipt_between_venues() {
    let mut scenario = ts::begin(ADMIN);
    setup(&mut scenario);
    ts::next_tx(&mut scenario, USER);
    let clk = a_clock(&mut scenario);
    arm_and_deposit(&mut scenario, &clk);

    ts::next_tx(&mut scenario, WORKER);
    let mut pos = ts::take_shared<YieldPosition>(&scenario);
    let reg = ts::take_shared<RebalanceRegistry>(&scenario);
    let (old, ticket) = yield_router::begin_rotation<Mock>(
        &mut pos, &reg, NAVI, SUILEND, 5_000, &clk, ts::ctx(&mut scenario),
    );
    assert_eq!(yield_router::holds(&pos, NAVI), false);
    let fresh = mint_mock(&mut scenario);
    yield_router::end_rotation(&mut pos, fresh, ticket, &clk);
    assert_eq!(yield_router::holds(&pos, SUILEND), true);
    assert_eq!(yield_router::rotations_total(&pos), 1);
    transfer::public_transfer(old, USER);
    ts::return_shared(pos);
    ts::return_shared(reg);
    clock::destroy_for_testing(clk);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = yield_router::EWrongWorker)]
fun rotation_by_non_worker_aborts() {
    let mut scenario = ts::begin(ADMIN);
    setup(&mut scenario);
    ts::next_tx(&mut scenario, USER);
    let clk = a_clock(&mut scenario);
    arm_and_deposit(&mut scenario, &clk);

    ts::next_tx(&mut scenario, RANDO); // not a registered worker
    let mut pos = ts::take_shared<YieldPosition>(&scenario);
    let reg = ts::take_shared<RebalanceRegistry>(&scenario);
    let (old, ticket) = yield_router::begin_rotation<Mock>(
        &mut pos, &reg, NAVI, SUILEND, 5_000, &clk, ts::ctx(&mut scenario),
    );
    transfer::public_transfer(old, USER);
    yield_router::end_rotation(&mut pos, mint_mock(&mut scenario), ticket, &clk);
    ts::return_shared(pos);
    ts::return_shared(reg);
    clock::destroy_for_testing(clk);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = yield_router::EAmountExceedsCap)]
fun rotation_over_cap_aborts() {
    let mut scenario = ts::begin(ADMIN);
    setup(&mut scenario);
    ts::next_tx(&mut scenario, USER);
    let clk = a_clock(&mut scenario);
    arm_and_deposit(&mut scenario, &clk); // max_per_rotation = 10_000

    ts::next_tx(&mut scenario, WORKER);
    let mut pos = ts::take_shared<YieldPosition>(&scenario);
    let reg = ts::take_shared<RebalanceRegistry>(&scenario);
    let (old, ticket) = yield_router::begin_rotation<Mock>(
        &mut pos, &reg, NAVI, SUILEND, 20_000, &clk, ts::ctx(&mut scenario), // over cap
    );
    transfer::public_transfer(old, USER);
    yield_router::end_rotation(&mut pos, mint_mock(&mut scenario), ticket, &clk);
    ts::return_shared(pos);
    ts::return_shared(reg);
    clock::destroy_for_testing(clk);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = yield_router::ESameVenue)]
fun rotation_same_venue_aborts() {
    let mut scenario = ts::begin(ADMIN);
    setup(&mut scenario);
    ts::next_tx(&mut scenario, USER);
    let clk = a_clock(&mut scenario);
    arm_and_deposit(&mut scenario, &clk);

    ts::next_tx(&mut scenario, WORKER);
    let mut pos = ts::take_shared<YieldPosition>(&scenario);
    let reg = ts::take_shared<RebalanceRegistry>(&scenario);
    let (old, ticket) = yield_router::begin_rotation<Mock>(
        &mut pos, &reg, NAVI, NAVI, 1_000, &clk, ts::ctx(&mut scenario), // same venue
    );
    transfer::public_transfer(old, USER);
    yield_router::end_rotation(&mut pos, mint_mock(&mut scenario), ticket, &clk);
    ts::return_shared(pos);
    ts::return_shared(reg);
    clock::destroy_for_testing(clk);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = yield_router::EVenuePaused)]
fun rotation_into_paused_venue_aborts() {
    let mut scenario = ts::begin(ADMIN);
    setup(&mut scenario);
    // Admin trips the circuit breaker on Suilend.
    ts::next_tx(&mut scenario, ADMIN);
    let mut reg = ts::take_shared<RebalanceRegistry>(&scenario);
    yield_router::set_venue_paused(&mut reg, SUILEND, true, ts::ctx(&mut scenario));
    ts::return_shared(reg);

    ts::next_tx(&mut scenario, USER);
    let clk = a_clock(&mut scenario);
    arm_and_deposit(&mut scenario, &clk);

    ts::next_tx(&mut scenario, WORKER);
    let mut pos = ts::take_shared<YieldPosition>(&scenario);
    let reg2 = ts::take_shared<RebalanceRegistry>(&scenario);
    let (old, ticket) = yield_router::begin_rotation<Mock>(
        &mut pos, &reg2, NAVI, SUILEND, 5_000, &clk, ts::ctx(&mut scenario), // into paused venue
    );
    transfer::public_transfer(old, USER);
    yield_router::end_rotation(&mut pos, mint_mock(&mut scenario), ticket, &clk);
    ts::return_shared(pos);
    ts::return_shared(reg2);
    clock::destroy_for_testing(clk);
    ts::end(scenario);
}
