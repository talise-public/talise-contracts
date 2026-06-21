/// Sanity tests for the auto-swap consent + bounds surface.
/// Covers the post-audit invariants: enable runs vault-owner check,
/// validate gates on admin/expired/paused/cap-max, hot-potato
/// SwapTicket forces deposit, owner-only mutations on the cap.
///
/// NOTE (v3+ shared-cap migration): `vault::enable_auto_swap` now
/// `transfer::public_share_object`s the cap so the worker can reference
/// it via `&AutoSwapCap<T>` in a PTB the worker signs. Tests take the
/// cap via `take_shared` (or `take_shared_by_id` when multiple caps
/// coexist) and return it via `return_shared`. The owner-only mutation
/// checks (`cap.owner == ctx.sender()`) are still enforced by the
/// module; tests of "non-owner cannot mutate" simply have RANDO take
/// the shared cap directly instead of receiving a transferred copy.
#[test_only]
module talise::auto_swap_tests;

use std::unit_test::assert_eq;
use sui::{test_scenario as ts, coin, sui::SUI};

use talise::{auto_swap::{Self, AutoSwapRegistry, AutoSwapCap}, vault::{Self, TaliseVault}};

const PUBLISHER: address = @0xA;
const USER: address = @0xB;
const WORKER: address = @0xA;  // admin == publisher in v1
const RANDO: address = @0xC;

/// Helper: run the auto_swap module init to create the shared Registry
/// + transfer AdminCap to PUBLISHER.
fun setup_registry(scenario: &mut ts::Scenario) {
    ts::next_tx(scenario, PUBLISHER);
    auto_swap::test_init(ts::ctx(scenario));
}

/// Helper: USER creates a vault and the next-tx context can take it.
fun setup_user_vault(scenario: &mut ts::Scenario) {
    ts::next_tx(scenario, USER);
    vault::create(ts::ctx(scenario));
}

#[test]
fun enable_then_disable_round_trip() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario);

    // USER enables auto-swap for SUI against their own vault.
    ts::next_tx(&mut scenario, USER);
    let v = ts::take_shared<TaliseVault>(&scenario);
    vault::enable_auto_swap<SUI>(
        &v,
        10_000_000_000, // 10 SUI in mist
        0,              // no expiry
        ts::ctx(&mut scenario),
    );
    ts::return_shared(v);

    // Cap is a SHARED object now (v3+). Take it via take_shared.
    ts::next_tx(&mut scenario, USER);
    let cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);
    assert_eq!(auto_swap::cap_owner(&cap), USER);
    assert_eq!(auto_swap::cap_max(&cap), 10_000_000_000);
    assert!(!auto_swap::cap_paused(&cap));

    auto_swap::disable<SUI>(cap, ts::ctx(&mut scenario));

    // After disable the shared object is deleted — it should no longer
    // be discoverable as a shared object.
    ts::next_tx(&mut scenario, USER);
    assert!(!ts::has_most_recent_shared<AutoSwapCap<SUI>>());

    ts::end(scenario);
}

#[test, expected_failure(abort_code = vault::ENotOwner)]
fun rando_cannot_enable_against_user_vault() {
    // The audit's critical issue: previously a user could mint a cap
    // pointing at someone else's vault id. Now enable lives in vault
    // and asserts vault.owner == ctx.sender(), so RANDO must abort.
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario);

    ts::next_tx(&mut scenario, RANDO);
    let v = ts::take_shared<TaliseVault>(&scenario);
    vault::enable_auto_swap<SUI>(&v, 1_000_000, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = auto_swap::EAmountExceedsCap)]
fun validate_rejects_amount_over_cap() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario);

    ts::next_tx(&mut scenario, USER);
    let v = ts::take_shared<TaliseVault>(&scenario);
    vault::enable_auto_swap<SUI>(&v, 100, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);

    ts::next_tx(&mut scenario, USER);
    let cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);

    // Worker tries to swap 1000 against a cap of 100 — should abort.
    ts::next_tx(&mut scenario, WORKER);
    let mut registry = ts::take_shared<AutoSwapRegistry>(&scenario);
    auto_swap::test_validate_for_swap<SUI>(
        &mut registry, &cap, 1000, 0, ts::ctx(&mut scenario),
    );
    ts::return_shared(registry);
    ts::return_shared(cap);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = auto_swap::EWrongAdmin)]
fun validate_rejects_non_admin_sender() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario);

    ts::next_tx(&mut scenario, USER);
    let v = ts::take_shared<TaliseVault>(&scenario);
    vault::enable_auto_swap<SUI>(&v, 10_000_000_000, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);

    ts::next_tx(&mut scenario, USER);
    let cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);

    // RANDO is not the admin — should abort.
    ts::next_tx(&mut scenario, RANDO);
    let mut registry = ts::take_shared<AutoSwapRegistry>(&scenario);
    auto_swap::test_validate_for_swap<SUI>(
        &mut registry, &cap, 100, 0, ts::ctx(&mut scenario),
    );
    ts::return_shared(registry);
    ts::return_shared(cap);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = auto_swap::ECapPaused)]
fun validate_rejects_paused_cap() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario);

    ts::next_tx(&mut scenario, USER);
    let v = ts::take_shared<TaliseVault>(&scenario);
    vault::enable_auto_swap<SUI>(&v, 10_000_000_000, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);

    ts::next_tx(&mut scenario, USER);
    let mut cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);
    auto_swap::pause<SUI>(&mut cap, ts::ctx(&mut scenario));

    ts::next_tx(&mut scenario, WORKER);
    let mut registry = ts::take_shared<AutoSwapRegistry>(&scenario);
    auto_swap::test_validate_for_swap<SUI>(
        &mut registry, &cap, 100, 0, ts::ctx(&mut scenario),
    );
    ts::return_shared(registry);
    ts::return_shared(cap);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = auto_swap::ECapExpired)]
fun validate_rejects_expired_cap() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario);

    // Cap expires at ms = 1000.
    ts::next_tx(&mut scenario, USER);
    let v = ts::take_shared<TaliseVault>(&scenario);
    vault::enable_auto_swap<SUI>(&v, 10_000_000_000, 1000, ts::ctx(&mut scenario));
    ts::return_shared(v);

    ts::next_tx(&mut scenario, USER);
    let cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);

    // Worker validates at ms = 2000 (after expiry) — should abort.
    ts::next_tx(&mut scenario, WORKER);
    let mut registry = ts::take_shared<AutoSwapRegistry>(&scenario);
    auto_swap::test_validate_for_swap<SUI>(
        &mut registry, &cap, 100, 2000, ts::ctx(&mut scenario),
    );
    ts::return_shared(registry);
    ts::return_shared(cap);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = auto_swap::ENotOwner)]
fun rando_cannot_pause_someone_elses_cap() {
    // Cap is shared (v3+), so RANDO can reference it via take_shared —
    // but the inner `assert!(ctx.sender() == cap.owner)` aborts.
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario);

    ts::next_tx(&mut scenario, USER);
    let v = ts::take_shared<TaliseVault>(&scenario);
    vault::enable_auto_swap<SUI>(&v, 10_000_000_000, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);

    // RANDO takes the shared cap and tries to pause it.
    ts::next_tx(&mut scenario, RANDO);
    let mut cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);
    auto_swap::pause<SUI>(&mut cap, ts::ctx(&mut scenario));
    ts::return_shared(cap);
    ts::end(scenario);
}

#[test]
fun deposit_and_withdraw_round_trip() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario);

    // RANDO deposits fake SUI. Anyone can deposit.
    ts::next_tx(&mut scenario, RANDO);
    let mut v = ts::take_shared<TaliseVault>(&scenario);
    let c = coin::mint_for_testing<SUI>(5_000_000, ts::ctx(&mut scenario));
    vault::deposit<SUI>(&mut v, c, ts::ctx(&mut scenario));
    assert_eq!(vault::balance_of<SUI>(&v), 5_000_000);
    ts::return_shared(v);

    // USER withdraws 2_000_000.
    ts::next_tx(&mut scenario, USER);
    let mut v2 = ts::take_shared<TaliseVault>(&scenario);
    let withdrawn = vault::withdraw<SUI>(&mut v2, 2_000_000, ts::ctx(&mut scenario));
    assert_eq!(withdrawn.value(), 2_000_000);
    assert_eq!(vault::balance_of<SUI>(&v2), 3_000_000);
    coin::burn_for_testing(withdrawn);
    ts::return_shared(v2);

    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// Resume + update_bounds + read accessors + owner-only mutation guards

#[test]
fun pause_then_resume_round_trip() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario);

    ts::next_tx(&mut scenario, USER);
    let v = ts::take_shared<TaliseVault>(&scenario);
    vault::enable_auto_swap<SUI>(&v, 10_000, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);

    ts::next_tx(&mut scenario, USER);
    let mut cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);
    auto_swap::pause<SUI>(&mut cap, ts::ctx(&mut scenario));
    assert!(auto_swap::cap_paused(&cap));

    auto_swap::resume<SUI>(&mut cap, ts::ctx(&mut scenario));
    assert!(!auto_swap::cap_paused(&cap));

    // After resume, validate should succeed (sender = WORKER = admin).
    ts::next_tx(&mut scenario, WORKER);
    let mut registry = ts::take_shared<AutoSwapRegistry>(&scenario);
    auto_swap::test_validate_for_swap<SUI>(
        &mut registry, &cap, 100, 0, ts::ctx(&mut scenario),
    );
    assert_eq!(auto_swap::total_validations(&registry), 1);
    assert_eq!(auto_swap::admin(&registry), PUBLISHER);
    ts::return_shared(registry);
    ts::return_shared(cap);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = auto_swap::ENotOwner)]
fun rando_cannot_resume() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario);

    ts::next_tx(&mut scenario, USER);
    let v = ts::take_shared<TaliseVault>(&scenario);
    vault::enable_auto_swap<SUI>(&v, 10_000, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);

    // RANDO takes the shared cap and tries to resume it.
    ts::next_tx(&mut scenario, RANDO);
    let mut cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);
    auto_swap::resume<SUI>(&mut cap, ts::ctx(&mut scenario));
    ts::return_shared(cap);
    ts::end(scenario);
}

#[test]
fun update_bounds_happy_path() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario);

    ts::next_tx(&mut scenario, USER);
    let v = ts::take_shared<TaliseVault>(&scenario);
    vault::enable_auto_swap<SUI>(&v, 1_000, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);

    ts::next_tx(&mut scenario, USER);
    let mut cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);
    assert_eq!(auto_swap::cap_max(&cap), 1_000);
    assert_eq!(auto_swap::cap_expiry(&cap), 0);

    auto_swap::update_bounds<SUI>(&mut cap, 5_555, 9_999_999, ts::ctx(&mut scenario));
    assert_eq!(auto_swap::cap_max(&cap), 5_555);
    assert_eq!(auto_swap::cap_expiry(&cap), 9_999_999);

    ts::return_shared(cap);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = auto_swap::ENotOwner)]
fun rando_cannot_update_bounds() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario);

    ts::next_tx(&mut scenario, USER);
    let v = ts::take_shared<TaliseVault>(&scenario);
    vault::enable_auto_swap<SUI>(&v, 1_000, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);

    // RANDO takes the shared cap and tries to update bounds.
    ts::next_tx(&mut scenario, RANDO);
    let mut cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);
    auto_swap::update_bounds<SUI>(&mut cap, 9_999, 0, ts::ctx(&mut scenario));
    ts::return_shared(cap);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = auto_swap::EInvalidMax)]
fun update_bounds_rejects_zero_max() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario);

    ts::next_tx(&mut scenario, USER);
    let v = ts::take_shared<TaliseVault>(&scenario);
    vault::enable_auto_swap<SUI>(&v, 1_000, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);

    ts::next_tx(&mut scenario, USER);
    let mut cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);
    auto_swap::update_bounds<SUI>(&mut cap, 0, 0, ts::ctx(&mut scenario));
    ts::return_shared(cap);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = auto_swap::EInvalidMax)]
fun enable_rejects_zero_max() {
    // mint_cap asserts max_per_swap > 0. Trip it via enable_auto_swap.
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario);

    ts::next_tx(&mut scenario, USER);
    let v = ts::take_shared<TaliseVault>(&scenario);
    vault::enable_auto_swap<SUI>(&v, 0, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = auto_swap::ENotOwner)]
fun rando_cannot_disable_someone_elses_cap() {
    // disable() also has the owner check; cover that branch.
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario);

    ts::next_tx(&mut scenario, USER);
    let v = ts::take_shared<TaliseVault>(&scenario);
    vault::enable_auto_swap<SUI>(&v, 1_000, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);

    // RANDO takes the shared cap and tries to disable it.
    ts::next_tx(&mut scenario, RANDO);
    let cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);
    auto_swap::disable<SUI>(cap, ts::ctx(&mut scenario));
    ts::end(scenario);
}

#[test]
fun validate_accepts_unexpired_cap_with_future_expiry() {
    // Exercises the `assert!(now_ms <= cap.expires_at_ms)` true branch.
    // Existing validate-passing tests use expires_at_ms=0 (no expiry),
    // which short-circuits the assert; only abort tests hit the false
    // branch. We need a passing test with a non-zero expiry to cover
    // the true branch of the inner if-assertion.
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario);

    ts::next_tx(&mut scenario, USER);
    let v = ts::take_shared<TaliseVault>(&scenario);
    vault::enable_auto_swap<SUI>(&v, 10_000, 5_000, ts::ctx(&mut scenario));
    ts::return_shared(v);

    ts::next_tx(&mut scenario, USER);
    let cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);

    ts::next_tx(&mut scenario, WORKER);
    let mut registry = ts::take_shared<AutoSwapRegistry>(&scenario);
    // now_ms = 1000, expiry = 5000 → unexpired, passes.
    auto_swap::test_validate_for_swap<SUI>(
        &mut registry, &cap, 100, 1_000, ts::ctx(&mut scenario),
    );
    assert_eq!(auto_swap::total_validations(&registry), 1);
    ts::return_shared(registry);
    ts::return_shared(cap);
    ts::end(scenario);
}

#[test]
fun cap_vault_accessor_returns_correct_id() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario);

    ts::next_tx(&mut scenario, USER);
    let v = ts::take_shared<TaliseVault>(&scenario);
    let vid = sui::object::id(&v);
    vault::enable_auto_swap<SUI>(&v, 1_000, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);

    ts::next_tx(&mut scenario, USER);
    let cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);
    assert_eq!(auto_swap::cap_vault(&cap), vid);
    ts::return_shared(cap);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = vault::ENotOwner)]
fun rando_cannot_withdraw() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario);

    ts::next_tx(&mut scenario, USER);
    let mut v = ts::take_shared<TaliseVault>(&scenario);
    let c = coin::mint_for_testing<SUI>(5_000_000, ts::ctx(&mut scenario));
    vault::deposit<SUI>(&mut v, c, ts::ctx(&mut scenario));
    ts::return_shared(v);

    ts::next_tx(&mut scenario, RANDO);
    let mut v2 = ts::take_shared<TaliseVault>(&scenario);
    let stolen = vault::withdraw<SUI>(&mut v2, 1, ts::ctx(&mut scenario));
    coin::burn_for_testing(stolen);
    ts::return_shared(v2);
    ts::end(scenario);
}
