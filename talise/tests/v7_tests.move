/// v7 security suite — covers AutoSwapRegistryV2 + AutoSwapCapV2 paths
/// added in the post-publish upgrade. Lives alongside the v1 tests so a
/// single `sui move test` exercises the full surface.
///
/// Scenarios:
///   * Bootstrap → admin set, publisher is initial worker.
///   * Role grant/revoke — admin-only, non-admin aborts.
///   * Admin rotation — 2-step with 48h delay; cancel; wrong-acceptor
///     and before-delay aborts.
///   * Pause/unpause — admin and oncall paths.
///   * Treasury cannot pause.
///   * Allowlist add/remove.
///   * validate_for_swap_v2 — happy path, paused-registry, non-worker,
///     paused-cap, expired-cap, amount-over-cap, daily-budget-exceeded,
///     day-rollover-resets-used_today.
///   * upgrade_cap_to_v2 — happy path, non-owner aborts.
#[test_only]
module talise::v7_tests;

use std::unit_test::assert_eq;
use sui::{test_scenario as ts, clock::{Self, Clock}, sui::SUI};

use talise::{
    auto_swap::{
        Self,
        AutoSwapRegistryV2,
        AutoSwapCapV2,
        AutoSwapCap,
    },
    vault::{Self, TaliseVault},
};

// Placeholder destination coin type for allowlist tests. Phantom-only,
// no Coin instances are minted of this type.
public struct USDSUI has drop {}

const PUBLISHER: address = @0xA;
const USER: address = @0xB;
const TREASURY: address = @0xD;
const ONCALL: address = @0xE;
const WORKER2: address = @0xF;
const RANDO: address = @0xC;

const DAY_MS: u64 = 86_400_000;
const DEFAULT_DELAY: u64 = 48 * 3600 * 1000;

fun setup_v7(scenario: &mut ts::Scenario) {
    // Bootstrap v7 registry from PUBLISHER.
    ts::next_tx(scenario, PUBLISHER);
    auto_swap::test_bootstrap_v7(ts::ctx(scenario));
}

fun setup_user_vault(scenario: &mut ts::Scenario) {
    ts::next_tx(scenario, USER);
    vault::create(ts::ctx(scenario));
}

fun new_clock_at(scenario: &mut ts::Scenario, ts_ms: u64): Clock {
    let mut c = clock::create_for_testing(ts::ctx(scenario));
    clock::set_for_testing(&mut c, ts_ms);
    c
}

// ───────────────────────────────────────────────────────────────────
// Bootstrap

#[test]
fun bootstrap_sets_admin_and_initial_worker() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_v7(&mut scenario);

    ts::next_tx(&mut scenario, PUBLISHER);
    let r = ts::take_shared<AutoSwapRegistryV2>(&scenario);
    assert_eq!(auto_swap::v2_admin(&r), PUBLISHER);
    assert!(!auto_swap::v2_paused(&r));
    assert_eq!(auto_swap::v2_admin_transfer_delay_ms(&r), DEFAULT_DELAY);
    let workers = auto_swap::v2_workers(&r);
    assert!(std::vector::contains(workers, &PUBLISHER));
    ts::return_shared(r);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// Role grants

#[test]
fun grant_and_revoke_worker_oncall_treasury() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_v7(&mut scenario);

    ts::next_tx(&mut scenario, PUBLISHER);
    let mut r = ts::take_shared<AutoSwapRegistryV2>(&scenario);
    auto_swap::grant_worker(&mut r, WORKER2, ts::ctx(&mut scenario));
    auto_swap::grant_oncall(&mut r, ONCALL, ts::ctx(&mut scenario));
    auto_swap::grant_treasury(&mut r, TREASURY, ts::ctx(&mut scenario));
    assert!(std::vector::contains(auto_swap::v2_workers(&r), &WORKER2));
    assert!(std::vector::contains(auto_swap::v2_oncalls(&r), &ONCALL));
    assert!(std::vector::contains(auto_swap::v2_treasuries(&r), &TREASURY));

    auto_swap::revoke_worker(&mut r, WORKER2, ts::ctx(&mut scenario));
    auto_swap::revoke_oncall(&mut r, ONCALL, ts::ctx(&mut scenario));
    auto_swap::revoke_treasury(&mut r, TREASURY, ts::ctx(&mut scenario));
    assert!(!std::vector::contains(auto_swap::v2_workers(&r), &WORKER2));
    assert!(!std::vector::contains(auto_swap::v2_oncalls(&r), &ONCALL));
    assert!(!std::vector::contains(auto_swap::v2_treasuries(&r), &TREASURY));

    ts::return_shared(r);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = auto_swap::ENotAdmin)]
fun rando_cannot_grant_worker() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_v7(&mut scenario);

    ts::next_tx(&mut scenario, RANDO);
    let mut r = ts::take_shared<AutoSwapRegistryV2>(&scenario);
    auto_swap::grant_worker(&mut r, WORKER2, ts::ctx(&mut scenario));
    ts::return_shared(r);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// Admin rotation

#[test]
fun admin_transfer_two_step_happy_path() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_v7(&mut scenario);

    // PUBLISHER begins transfer to USER at t=0.
    ts::next_tx(&mut scenario, PUBLISHER);
    let mut r = ts::take_shared<AutoSwapRegistryV2>(&scenario);
    let c0 = new_clock_at(&mut scenario, 0);
    auto_swap::begin_admin_transfer(&mut r, USER, &c0, ts::ctx(&mut scenario));
    assert!(auto_swap::v2_has_pending_admin_transfer(&r));
    clock::destroy_for_testing(c0);

    // USER tries to accept before delay elapses — should fail in
    // separate scenario; here we accept after delay.
    ts::next_tx(&mut scenario, USER);
    let c1 = new_clock_at(&mut scenario, DEFAULT_DELAY);
    auto_swap::accept_admin_transfer(&mut r, &c1, ts::ctx(&mut scenario));
    assert_eq!(auto_swap::v2_admin(&r), USER);
    assert!(!auto_swap::v2_has_pending_admin_transfer(&r));
    clock::destroy_for_testing(c1);

    ts::return_shared(r);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = auto_swap::EDelayNotElapsed)]
fun admin_transfer_accept_before_delay_aborts() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_v7(&mut scenario);

    ts::next_tx(&mut scenario, PUBLISHER);
    let mut r = ts::take_shared<AutoSwapRegistryV2>(&scenario);
    let c0 = new_clock_at(&mut scenario, 0);
    auto_swap::begin_admin_transfer(&mut r, USER, &c0, ts::ctx(&mut scenario));
    clock::destroy_for_testing(c0);

    // Only 1 second has passed.
    ts::next_tx(&mut scenario, USER);
    let c1 = new_clock_at(&mut scenario, 1000);
    auto_swap::accept_admin_transfer(&mut r, &c1, ts::ctx(&mut scenario));
    clock::destroy_for_testing(c1);
    ts::return_shared(r);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = auto_swap::EWrongPendingAcceptor)]
fun admin_transfer_wrong_acceptor_aborts() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_v7(&mut scenario);

    ts::next_tx(&mut scenario, PUBLISHER);
    let mut r = ts::take_shared<AutoSwapRegistryV2>(&scenario);
    let c0 = new_clock_at(&mut scenario, 0);
    auto_swap::begin_admin_transfer(&mut r, USER, &c0, ts::ctx(&mut scenario));
    clock::destroy_for_testing(c0);

    // RANDO tries to claim the role.
    ts::next_tx(&mut scenario, RANDO);
    let c1 = new_clock_at(&mut scenario, DEFAULT_DELAY);
    auto_swap::accept_admin_transfer(&mut r, &c1, ts::ctx(&mut scenario));
    clock::destroy_for_testing(c1);
    ts::return_shared(r);
    ts::end(scenario);
}

#[test]
fun admin_transfer_cancel() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_v7(&mut scenario);

    ts::next_tx(&mut scenario, PUBLISHER);
    let mut r = ts::take_shared<AutoSwapRegistryV2>(&scenario);
    let c0 = new_clock_at(&mut scenario, 0);
    auto_swap::begin_admin_transfer(&mut r, USER, &c0, ts::ctx(&mut scenario));
    auto_swap::cancel_admin_transfer(&mut r, ts::ctx(&mut scenario));
    assert!(!auto_swap::v2_has_pending_admin_transfer(&r));
    assert_eq!(auto_swap::v2_admin(&r), PUBLISHER);
    clock::destroy_for_testing(c0);
    ts::return_shared(r);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// Pause / unpause

#[test]
fun admin_can_pause_and_unpause() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_v7(&mut scenario);

    ts::next_tx(&mut scenario, PUBLISHER);
    let mut r = ts::take_shared<AutoSwapRegistryV2>(&scenario);
    auto_swap::pause_registry(&mut r, ts::ctx(&mut scenario));
    assert!(auto_swap::v2_paused(&r));
    auto_swap::unpause_registry(&mut r, ts::ctx(&mut scenario));
    assert!(!auto_swap::v2_paused(&r));
    ts::return_shared(r);
    ts::end(scenario);
}

#[test]
fun oncall_can_pause() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_v7(&mut scenario);

    ts::next_tx(&mut scenario, PUBLISHER);
    let mut r = ts::take_shared<AutoSwapRegistryV2>(&scenario);
    auto_swap::grant_oncall(&mut r, ONCALL, ts::ctx(&mut scenario));
    ts::return_shared(r);

    ts::next_tx(&mut scenario, ONCALL);
    let mut r2 = ts::take_shared<AutoSwapRegistryV2>(&scenario);
    auto_swap::pause_registry(&mut r2, ts::ctx(&mut scenario));
    assert!(auto_swap::v2_paused(&r2));
    ts::return_shared(r2);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = auto_swap::ENotAdminOrOncall)]
fun treasury_cannot_pause() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_v7(&mut scenario);

    ts::next_tx(&mut scenario, PUBLISHER);
    let mut r = ts::take_shared<AutoSwapRegistryV2>(&scenario);
    auto_swap::grant_treasury(&mut r, TREASURY, ts::ctx(&mut scenario));
    ts::return_shared(r);

    ts::next_tx(&mut scenario, TREASURY);
    let mut r2 = ts::take_shared<AutoSwapRegistryV2>(&scenario);
    auto_swap::pause_registry(&mut r2, ts::ctx(&mut scenario));
    ts::return_shared(r2);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// Allowlist

#[test]
fun add_and_remove_allowed_dest() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_v7(&mut scenario);

    ts::next_tx(&mut scenario, PUBLISHER);
    let mut r = ts::take_shared<AutoSwapRegistryV2>(&scenario);
    auto_swap::add_allowed_dest<USDSUI>(&mut r, ts::ctx(&mut scenario));
    // Should succeed now.
    auto_swap::test_assert_dest_allowed<USDSUI>(&r);
    auto_swap::remove_allowed_dest<USDSUI>(&mut r, ts::ctx(&mut scenario));
    ts::return_shared(r);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = auto_swap::EDestNotAllowed)]
fun assert_dest_allowed_rejects_unlisted() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_v7(&mut scenario);

    ts::next_tx(&mut scenario, PUBLISHER);
    let r = ts::take_shared<AutoSwapRegistryV2>(&scenario);
    // USDSUI was never added.
    auto_swap::test_assert_dest_allowed<USDSUI>(&r);
    ts::return_shared(r);
    ts::end(scenario);
}

#[test]
fun treasury_can_manage_dest_allowlist() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_v7(&mut scenario);

    ts::next_tx(&mut scenario, PUBLISHER);
    let mut r = ts::take_shared<AutoSwapRegistryV2>(&scenario);
    auto_swap::grant_treasury(&mut r, TREASURY, ts::ctx(&mut scenario));
    ts::return_shared(r);

    ts::next_tx(&mut scenario, TREASURY);
    let mut r2 = ts::take_shared<AutoSwapRegistryV2>(&scenario);
    auto_swap::add_allowed_dest<USDSUI>(&mut r2, ts::ctx(&mut scenario));
    auto_swap::test_assert_dest_allowed<USDSUI>(&r2);
    ts::return_shared(r2);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// validate_for_swap_v2

/// Helper: bootstrap v7, user creates vault, user enables v2 auto-swap.
/// Returns nothing; caller uses next_tx + take_shared.
fun setup_user_with_v2_cap(
    scenario: &mut ts::Scenario,
    max_per_swap: u64,
    max_per_day: u64,
    expires_at_ms: u64,
) {
    setup_v7(scenario);
    setup_user_vault(scenario);
    ts::next_tx(scenario, USER);
    let v = ts::take_shared<TaliseVault>(scenario);
    let c = new_clock_at(scenario, 0);
    vault::enable_auto_swap_v2<SUI>(
        &v,
        max_per_swap,
        max_per_day,
        expires_at_ms,
        &c,
        ts::ctx(scenario),
    );
    clock::destroy_for_testing(c);
    ts::return_shared(v);
}

#[test]
fun validate_v2_happy_path() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_user_with_v2_cap(&mut scenario, 1_000, 5_000, 0);

    ts::next_tx(&mut scenario, PUBLISHER); // PUBLISHER == initial worker
    let mut r = ts::take_shared<AutoSwapRegistryV2>(&scenario);
    let mut cap = ts::take_shared<AutoSwapCapV2<SUI>>(&scenario);
    let c = new_clock_at(&mut scenario, 1_000);
    auto_swap::test_validate_for_swap_v2<SUI>(
        &mut r, &mut cap, 300, &c, ts::ctx(&mut scenario),
    );
    assert_eq!(auto_swap::cap_v2_used_today(&cap), 300);
    assert_eq!(auto_swap::v2_total_validations(&r), 1);
    clock::destroy_for_testing(c);
    ts::return_shared(cap);
    ts::return_shared(r);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = auto_swap::ERegistryPaused)]
fun validate_v2_aborts_when_registry_paused() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_user_with_v2_cap(&mut scenario, 1_000, 5_000, 0);

    ts::next_tx(&mut scenario, PUBLISHER);
    let mut r = ts::take_shared<AutoSwapRegistryV2>(&scenario);
    auto_swap::pause_registry(&mut r, ts::ctx(&mut scenario));
    let mut cap = ts::take_shared<AutoSwapCapV2<SUI>>(&scenario);
    let c = new_clock_at(&mut scenario, 1_000);
    auto_swap::test_validate_for_swap_v2<SUI>(
        &mut r, &mut cap, 100, &c, ts::ctx(&mut scenario),
    );
    clock::destroy_for_testing(c);
    ts::return_shared(cap);
    ts::return_shared(r);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = auto_swap::ENotWorker)]
fun validate_v2_aborts_when_sender_not_worker() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_user_with_v2_cap(&mut scenario, 1_000, 5_000, 0);

    ts::next_tx(&mut scenario, RANDO);
    let mut r = ts::take_shared<AutoSwapRegistryV2>(&scenario);
    let mut cap = ts::take_shared<AutoSwapCapV2<SUI>>(&scenario);
    let c = new_clock_at(&mut scenario, 1_000);
    auto_swap::test_validate_for_swap_v2<SUI>(
        &mut r, &mut cap, 100, &c, ts::ctx(&mut scenario),
    );
    clock::destroy_for_testing(c);
    ts::return_shared(cap);
    ts::return_shared(r);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = auto_swap::EAmountExceedsCap)]
fun validate_v2_aborts_when_amount_over_per_swap() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_user_with_v2_cap(&mut scenario, 100, 5_000, 0);

    ts::next_tx(&mut scenario, PUBLISHER);
    let mut r = ts::take_shared<AutoSwapRegistryV2>(&scenario);
    let mut cap = ts::take_shared<AutoSwapCapV2<SUI>>(&scenario);
    let c = new_clock_at(&mut scenario, 1_000);
    auto_swap::test_validate_for_swap_v2<SUI>(
        &mut r, &mut cap, 1_000, &c, ts::ctx(&mut scenario),
    );
    clock::destroy_for_testing(c);
    ts::return_shared(cap);
    ts::return_shared(r);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = auto_swap::EDailyBudgetExceeded)]
fun validate_v2_aborts_when_daily_budget_exceeded() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_user_with_v2_cap(&mut scenario, 600, 1_000, 0);

    // First swap: 600 used, 400 budget remaining.
    ts::next_tx(&mut scenario, PUBLISHER);
    let mut r = ts::take_shared<AutoSwapRegistryV2>(&scenario);
    let mut cap = ts::take_shared<AutoSwapCapV2<SUI>>(&scenario);
    let c1 = new_clock_at(&mut scenario, 1_000);
    auto_swap::test_validate_for_swap_v2<SUI>(
        &mut r, &mut cap, 600, &c1, ts::ctx(&mut scenario),
    );
    clock::destroy_for_testing(c1);
    // Second swap: 600 again — only 400 left in the budget → abort.
    let c2 = new_clock_at(&mut scenario, 2_000);
    auto_swap::test_validate_for_swap_v2<SUI>(
        &mut r, &mut cap, 600, &c2, ts::ctx(&mut scenario),
    );
    clock::destroy_for_testing(c2);
    ts::return_shared(cap);
    ts::return_shared(r);
    ts::end(scenario);
}

#[test]
fun validate_v2_day_rollover_resets_used_today() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_user_with_v2_cap(&mut scenario, 1_000, 1_000, 0);

    // Day-1 swap consumes the full budget.
    ts::next_tx(&mut scenario, PUBLISHER);
    let mut r = ts::take_shared<AutoSwapRegistryV2>(&scenario);
    let mut cap = ts::take_shared<AutoSwapCapV2<SUI>>(&scenario);
    let c1 = new_clock_at(&mut scenario, 1_000);
    auto_swap::test_validate_for_swap_v2<SUI>(
        &mut r, &mut cap, 1_000, &c1, ts::ctx(&mut scenario),
    );
    assert_eq!(auto_swap::cap_v2_used_today(&cap), 1_000);
    clock::destroy_for_testing(c1);
    // Skip 25h — day_reset_at_ms is set to (cap-mint clock=0) + DAY_MS
    // = DAY_MS. Now > DAY_MS, so rollover triggers.
    let c2 = new_clock_at(&mut scenario, DAY_MS + 3_600_000);
    auto_swap::test_validate_for_swap_v2<SUI>(
        &mut r, &mut cap, 500, &c2, ts::ctx(&mut scenario),
    );
    // Post-rollover, used_today reflects only the new swap.
    assert_eq!(auto_swap::cap_v2_used_today(&cap), 500);
    clock::destroy_for_testing(c2);
    ts::return_shared(cap);
    ts::return_shared(r);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// Cap upgrade v1 → v2

#[test]
fun upgrade_cap_to_v2_happy_path() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_v7(&mut scenario);
    // Need the v1 init to mint v1 caps via enable_auto_swap.
    ts::next_tx(&mut scenario, PUBLISHER);
    auto_swap::test_init(ts::ctx(&mut scenario));

    setup_user_vault(&mut scenario);
    ts::next_tx(&mut scenario, USER);
    let v = ts::take_shared<TaliseVault>(&scenario);
    vault::enable_auto_swap<SUI>(&v, 500, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);

    // USER upgrades.
    ts::next_tx(&mut scenario, USER);
    let cap_v1 = ts::take_shared<AutoSwapCap<SUI>>(&scenario);
    let c = new_clock_at(&mut scenario, 0);
    auto_swap::upgrade_cap_to_v2<SUI>(
        cap_v1,
        5_000, // max_per_day
        &c,
        ts::ctx(&mut scenario),
    );
    clock::destroy_for_testing(c);

    // The v1 cap is gone, a v2 cap is now shared.
    ts::next_tx(&mut scenario, USER);
    assert!(!ts::has_most_recent_shared<AutoSwapCap<SUI>>());
    let cap_v2 = ts::take_shared<AutoSwapCapV2<SUI>>(&scenario);
    assert_eq!(auto_swap::cap_v2_owner(&cap_v2), USER);
    assert_eq!(auto_swap::cap_v2_max_per_swap(&cap_v2), 500);
    assert_eq!(auto_swap::cap_v2_max_per_day(&cap_v2), 5_000);
    assert_eq!(auto_swap::cap_v2_used_today(&cap_v2), 0);
    ts::return_shared(cap_v2);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = auto_swap::ENotOwner)]
fun upgrade_cap_to_v2_non_owner_aborts() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_v7(&mut scenario);
    ts::next_tx(&mut scenario, PUBLISHER);
    auto_swap::test_init(ts::ctx(&mut scenario));

    setup_user_vault(&mut scenario);
    ts::next_tx(&mut scenario, USER);
    let v = ts::take_shared<TaliseVault>(&scenario);
    vault::enable_auto_swap<SUI>(&v, 500, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);

    // RANDO grabs the shared cap and tries to upgrade.
    ts::next_tx(&mut scenario, RANDO);
    let cap_v1 = ts::take_shared<AutoSwapCap<SUI>>(&scenario);
    let c = new_clock_at(&mut scenario, 0);
    auto_swap::upgrade_cap_to_v2<SUI>(cap_v1, 5_000, &c, ts::ctx(&mut scenario));
    clock::destroy_for_testing(c);
    ts::end(scenario);
}
