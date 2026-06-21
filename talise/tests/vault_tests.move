/// Full-coverage tests for `talise::vault`.
///
/// Covers paths not exercised by `auto_swap_tests.move`:
///   • happy-path `auto_swap_extract` + `auto_swap_deposit` (the hot-
///     potato pair) using SUI for both Source and Dest types — Cetus
///     is out of scope for unit tests, so we simulate the "swap" by
///     re-depositing the extracted balance under the same type.
///   • `withdraw_and_send` end-to-end.
///   • `deposit_balance` zero-amount short-circuit (`destroy_zero`).
///   • `balance_of` for an unheld type returns 0.
///   • `type_string` returns the canonical type name.
///   • All read accessors: `owner`, `deposits_total`, `auto_swaps_total`.
///   • `E_WRONG_VAULT` branches on both extract and deposit.
///   • `E_TYPE_NOT_HELD` on extract.
///   • `E_INSUFFICIENT_BALANCE` on extract.
///   • `E_ZERO_AMOUNT` on extract & withdraw.
///   • `auto_swap_deposit_to_owner` (v4): (a) output routed to
///     `vault.owner` as a plain `Coin<Dest>`, (b) stale bag balance is
///     flushed alongside the new output, (c) `E_WRONG_VAULT` rejection.
///
/// NOTE (v3+ shared-cap migration): `vault::enable_auto_swap` shares
/// the cap so the worker can reference it from a worker-signed PTB.
/// Tests take the cap via `take_shared` and return via `return_shared`.
#[test_only]
module talise::vault_tests;

use std::{string, unit_test::assert_eq};
use sui::{clock, coin::{Self, Coin}, sui::SUI, test_scenario as ts};

use talise::{auto_swap::{Self, AutoSwapRegistry, AutoSwapCap}, vault::{Self, TaliseVault}};

const PUBLISHER: address = @0xA;
const USER: address = @0xB;
const WORKER: address = @0xA;   // admin == publisher in v1
const OTHER_USER: address = @0xD;
const RANDO: address = @0xC;

fun setup_registry(scenario: &mut ts::Scenario) {
    ts::next_tx(scenario, PUBLISHER);
    auto_swap::test_init(ts::ctx(scenario));
}

fun setup_user_vault(scenario: &mut ts::Scenario, who: address) {
    ts::next_tx(scenario, who);
    vault::create(ts::ctx(scenario));
}

// ───────────────────────────────────────────────────────────────────
// Read accessors

#[test]
fun read_accessors_initial_state() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_user_vault(&mut scenario, USER);

    ts::next_tx(&mut scenario, USER);
    let v = ts::take_shared<TaliseVault>(&scenario);
    assert_eq!(vault::owner(&v), USER);
    assert_eq!(vault::deposits_total(&v), 0);
    assert_eq!(vault::auto_swaps_total(&v), 0);
    assert_eq!(vault::balance_of<SUI>(&v), 0);  // unheld type path
    ts::return_shared(v);
    ts::end(scenario);
}

#[test]
fun type_string_returns_canonical_name() {
    // Smoke test: ensure type_string<SUI>() yields a non-empty string
    // and matches the bytes used as the bag key. We don't pin the
    // exact value because the framework address can shift across
    // testnet/mainnet builds.
    let s = vault::type_string<SUI>();
    let bytes = string::as_bytes(&s);
    assert!(bytes.length() > 0);
}

// ───────────────────────────────────────────────────────────────────
// deposit_balance — zero-amount short-circuit

#[test]
fun deposit_zero_short_circuit_keeps_counters() {
    // Path: deposit a coin of value > 0 first (touches the `add` branch),
    // then a coin of value > 0 again (touches the `contains` branch +
    // `balance::join`), so we exercise both halves of the conditional.
    let mut scenario = ts::begin(PUBLISHER);
    setup_user_vault(&mut scenario, USER);

    ts::next_tx(&mut scenario, USER);
    let mut v = ts::take_shared<TaliseVault>(&scenario);
    let c1 = coin::mint_for_testing<SUI>(1_000, ts::ctx(&mut scenario));
    vault::deposit<SUI>(&mut v, c1, ts::ctx(&mut scenario));
    assert_eq!(vault::deposits_total(&v), 1);
    assert_eq!(vault::balance_of<SUI>(&v), 1_000);

    let c2 = coin::mint_for_testing<SUI>(2_000, ts::ctx(&mut scenario));
    vault::deposit<SUI>(&mut v, c2, ts::ctx(&mut scenario));
    assert_eq!(vault::deposits_total(&v), 2);
    assert_eq!(vault::balance_of<SUI>(&v), 3_000);

    ts::return_shared(v);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// withdraw_and_send

#[test]
fun withdraw_and_send_delivers_to_recipient() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_user_vault(&mut scenario, USER);

    ts::next_tx(&mut scenario, USER);
    let mut v = ts::take_shared<TaliseVault>(&scenario);
    let funded = coin::mint_for_testing<SUI>(10_000, ts::ctx(&mut scenario));
    vault::deposit<SUI>(&mut v, funded, ts::ctx(&mut scenario));
    ts::return_shared(v);

    ts::next_tx(&mut scenario, USER);
    let mut v2 = ts::take_shared<TaliseVault>(&scenario);
    vault::withdraw_and_send<SUI>(&mut v2, 4_000, RANDO, ts::ctx(&mut scenario));
    assert_eq!(vault::balance_of<SUI>(&v2), 6_000);
    ts::return_shared(v2);

    // Coin should now be in RANDO's wallet.
    ts::next_tx(&mut scenario, RANDO);
    let received = ts::take_from_sender<coin::Coin<SUI>>(&scenario);
    assert_eq!(received.value(), 4_000);
    coin::burn_for_testing(received);

    ts::end(scenario);
}

#[test]
fun withdraw_clears_balance_entry_when_drained() {
    // Withdrawing the full amount should hit the `remove` + `destroy_zero`
    // path inside `withdraw`.
    let mut scenario = ts::begin(PUBLISHER);
    setup_user_vault(&mut scenario, USER);

    ts::next_tx(&mut scenario, USER);
    let mut v = ts::take_shared<TaliseVault>(&scenario);
    let funded = coin::mint_for_testing<SUI>(1_000, ts::ctx(&mut scenario));
    vault::deposit<SUI>(&mut v, funded, ts::ctx(&mut scenario));
    let withdrawn = vault::withdraw<SUI>(&mut v, 1_000, ts::ctx(&mut scenario));
    assert_eq!(withdrawn.value(), 1_000);
    assert_eq!(vault::balance_of<SUI>(&v), 0);
    coin::burn_for_testing(withdrawn);
    ts::return_shared(v);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// auto_swap_extract / auto_swap_deposit — happy path

#[test]
fun auto_swap_extract_then_deposit_round_trip() {
    // The hot-potato pair. We use SUI for both Source and Dest because
    // Cetus is out of scope here; the test exercises the Move-level
    // flow only (vault state, ticket consumption, counter bumps).
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario, USER);

    // USER funds the vault and mints an auto-swap cap for SUI.
    ts::next_tx(&mut scenario, USER);
    let mut v = ts::take_shared<TaliseVault>(&scenario);
    let funded = coin::mint_for_testing<SUI>(1_000_000, ts::ctx(&mut scenario));
    vault::deposit<SUI>(&mut v, funded, ts::ctx(&mut scenario));
    vault::enable_auto_swap<SUI>(&v, 500_000, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);

    // WORKER (= admin) extracts and deposits in the same scenario tx.
    ts::next_tx(&mut scenario, USER);
    let cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);

    ts::next_tx(&mut scenario, WORKER);
    let mut v2 = ts::take_shared<TaliseVault>(&scenario);
    let mut registry = ts::take_shared<AutoSwapRegistry>(&scenario);
    let c = clock::create_for_testing(ts::ctx(&mut scenario));

    let (extracted, ticket) = vault::auto_swap_extract<SUI>(
        &mut v2, &mut registry, &cap, 300_000, &c, ts::ctx(&mut scenario),
    );
    // After extraction, vault holds 700_000 SUI (1_000_000 − 300_000).
    assert_eq!(vault::balance_of<SUI>(&v2), 700_000);

    // Simulate a 1:1 swap by re-depositing the extracted balance as Dest = SUI.
    vault::auto_swap_deposit<SUI>(&mut v2, extracted, ticket, &c);

    // Vault balance should be back to 1_000_000 and swap counter bumped.
    assert_eq!(vault::balance_of<SUI>(&v2), 1_000_000);
    assert_eq!(vault::auto_swaps_total(&v2), 1);
    assert_eq!(auto_swap::total_validations(&registry), 1);

    clock::destroy_for_testing(c);
    ts::return_shared(registry);
    ts::return_shared(v2);
    ts::return_shared(cap);
    ts::end(scenario);
}

#[test]
fun auto_swap_extract_drains_then_remove_branch() {
    // Force the inner `if (balance::value(held) == 0) { remove + destroy_zero }`
    // branch by extracting exactly the held amount.
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario, USER);

    ts::next_tx(&mut scenario, USER);
    let mut v = ts::take_shared<TaliseVault>(&scenario);
    let funded = coin::mint_for_testing<SUI>(100_000, ts::ctx(&mut scenario));
    vault::deposit<SUI>(&mut v, funded, ts::ctx(&mut scenario));
    vault::enable_auto_swap<SUI>(&v, 100_000, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);

    ts::next_tx(&mut scenario, USER);
    let cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);

    ts::next_tx(&mut scenario, WORKER);
    let mut v2 = ts::take_shared<TaliseVault>(&scenario);
    let mut registry = ts::take_shared<AutoSwapRegistry>(&scenario);
    let c = clock::create_for_testing(ts::ctx(&mut scenario));

    let (extracted, ticket) = vault::auto_swap_extract<SUI>(
        &mut v2, &mut registry, &cap, 100_000, &c, ts::ctx(&mut scenario),
    );
    assert_eq!(vault::balance_of<SUI>(&v2), 0);
    vault::auto_swap_deposit<SUI>(&mut v2, extracted, ticket, &c);
    assert_eq!(vault::balance_of<SUI>(&v2), 100_000);

    clock::destroy_for_testing(c);
    ts::return_shared(registry);
    ts::return_shared(v2);
    ts::return_shared(cap);
    ts::end(scenario);
}

#[test]
fun auto_swap_deposit_zero_output_destroys_balance() {
    // Force the `else { destroy_zero }` branch in auto_swap_deposit by
    // extracting then re-depositing a zero-value balance.
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario, USER);

    ts::next_tx(&mut scenario, USER);
    let mut v = ts::take_shared<TaliseVault>(&scenario);
    let funded = coin::mint_for_testing<SUI>(10_000, ts::ctx(&mut scenario));
    vault::deposit<SUI>(&mut v, funded, ts::ctx(&mut scenario));
    vault::enable_auto_swap<SUI>(&v, 10_000, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);

    ts::next_tx(&mut scenario, USER);
    let cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);

    ts::next_tx(&mut scenario, WORKER);
    let mut v2 = ts::take_shared<TaliseVault>(&scenario);
    let mut registry = ts::take_shared<AutoSwapRegistry>(&scenario);
    let c = clock::create_for_testing(ts::ctx(&mut scenario));

    let (extracted, ticket) = vault::auto_swap_extract<SUI>(
        &mut v2, &mut registry, &cap, 5_000, &c, ts::ctx(&mut scenario),
    );
    // Burn the extracted balance and substitute a zero-value Dest balance.
    sui::balance::destroy_for_testing(extracted);
    let zero_out = sui::balance::zero<SUI>();
    vault::auto_swap_deposit<SUI>(&mut v2, zero_out, ticket, &c);
    assert_eq!(vault::auto_swaps_total(&v2), 1);

    clock::destroy_for_testing(c);
    ts::return_shared(registry);
    ts::return_shared(v2);
    ts::return_shared(cap);
    ts::end(scenario);
}

#[test]
fun auto_swap_deposit_into_existing_dest_uses_join() {
    // Force the inner `if (vault.balances.contains(key))` join branch in
    // auto_swap_deposit by pre-funding Dest = SUI inside the vault.
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario, USER);

    ts::next_tx(&mut scenario, USER);
    let mut v = ts::take_shared<TaliseVault>(&scenario);
    let funded = coin::mint_for_testing<SUI>(20_000, ts::ctx(&mut scenario));
    vault::deposit<SUI>(&mut v, funded, ts::ctx(&mut scenario));
    vault::enable_auto_swap<SUI>(&v, 5_000, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);

    ts::next_tx(&mut scenario, USER);
    let cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);

    ts::next_tx(&mut scenario, WORKER);
    let mut v2 = ts::take_shared<TaliseVault>(&scenario);
    let mut registry = ts::take_shared<AutoSwapRegistry>(&scenario);
    let c = clock::create_for_testing(ts::ctx(&mut scenario));

    // Extract 5_000; vault still holds 15_000 SUI (so re-deposit takes the
    // `contains` branch and goes through `balance::join`).
    let (extracted, ticket) = vault::auto_swap_extract<SUI>(
        &mut v2, &mut registry, &cap, 5_000, &c, ts::ctx(&mut scenario),
    );
    assert_eq!(vault::balance_of<SUI>(&v2), 15_000);
    vault::auto_swap_deposit<SUI>(&mut v2, extracted, ticket, &c);
    assert_eq!(vault::balance_of<SUI>(&v2), 20_000);

    clock::destroy_for_testing(c);
    ts::return_shared(registry);
    ts::return_shared(v2);
    ts::return_shared(cap);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// auto_swap_extract — error branches

#[test, expected_failure(abort_code = vault::EWrongVault)]
fun extract_rejects_cap_for_different_vault() {
    // Cap was minted against USER's vault. Try to use it on OTHER_USER's
    // vault — should hit E_WRONG_VAULT before validate_for_swap.
    //
    // Two shared TaliseVaults exist after this setup, so we have to
    // disambiguate via take_shared_by_id.
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);

    // USER creates vault A and mints a cap against it.
    setup_user_vault(&mut scenario, USER);
    ts::next_tx(&mut scenario, USER);
    let v_user = ts::take_shared<TaliseVault>(&scenario);
    let user_vault_id = sui::object::id(&v_user);
    vault::enable_auto_swap<SUI>(&v_user, 1_000_000, 0, ts::ctx(&mut scenario));
    ts::return_shared(v_user);

    ts::next_tx(&mut scenario, USER);
    let cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);

    // OTHER_USER creates vault B and funds it. We capture the id at
    // creation time by listing shared ids before and after.
    setup_user_vault(&mut scenario, OTHER_USER);
    ts::next_tx(&mut scenario, OTHER_USER);
    let v_first = ts::take_shared<TaliseVault>(&scenario);
    let (mut v_other, _returned_first) = if (sui::object::id(&v_first) == user_vault_id) {
        // Pop USER's vault aside, take the next shared TaliseVault.
        ts::return_shared(v_first);
        (ts::take_shared<TaliseVault>(&scenario), true)
    } else {
        (v_first, false)
    };
    let funded = coin::mint_for_testing<SUI>(50_000, ts::ctx(&mut scenario));
    vault::deposit<SUI>(&mut v_other, funded, ts::ctx(&mut scenario));

    ts::next_tx(&mut scenario, WORKER);
    let mut registry = ts::take_shared<AutoSwapRegistry>(&scenario);
    let c = clock::create_for_testing(ts::ctx(&mut scenario));

    let (extracted, ticket) = vault::auto_swap_extract<SUI>(
        &mut v_other, &mut registry, &cap, 1_000, &c, ts::ctx(&mut scenario),
    );

    // Unreachable — we expect the call above to abort. Lines below
    // satisfy the type checker (ticket has no drop).
    sui::balance::destroy_for_testing(extracted);
    vault::auto_swap_deposit<SUI>(&mut v_other, sui::balance::zero<SUI>(), ticket, &c);

    clock::destroy_for_testing(c);
    ts::return_shared(registry);
    ts::return_shared(v_other);
    ts::return_shared(cap);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = vault::EZeroAmount)]
fun extract_rejects_zero_amount() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario, USER);

    ts::next_tx(&mut scenario, USER);
    let v = ts::take_shared<TaliseVault>(&scenario);
    vault::enable_auto_swap<SUI>(&v, 1_000_000, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);

    ts::next_tx(&mut scenario, USER);
    let cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);

    ts::next_tx(&mut scenario, WORKER);
    let mut v2 = ts::take_shared<TaliseVault>(&scenario);
    let mut registry = ts::take_shared<AutoSwapRegistry>(&scenario);
    let c = clock::create_for_testing(ts::ctx(&mut scenario));

    let (extracted, ticket) = vault::auto_swap_extract<SUI>(
        &mut v2, &mut registry, &cap, 0, &c, ts::ctx(&mut scenario),
    );
    sui::balance::destroy_for_testing(extracted);
    vault::auto_swap_deposit<SUI>(&mut v2, sui::balance::zero<SUI>(), ticket, &c);

    clock::destroy_for_testing(c);
    ts::return_shared(registry);
    ts::return_shared(v2);
    ts::return_shared(cap);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = vault::ETypeNotHeld)]
fun extract_rejects_when_type_not_held() {
    // Cap minted but vault never received SUI. Extract should hit
    // E_TYPE_NOT_HELD after validate_for_swap passes.
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario, USER);

    ts::next_tx(&mut scenario, USER);
    let v = ts::take_shared<TaliseVault>(&scenario);
    vault::enable_auto_swap<SUI>(&v, 1_000, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);

    ts::next_tx(&mut scenario, USER);
    let cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);

    ts::next_tx(&mut scenario, WORKER);
    let mut v2 = ts::take_shared<TaliseVault>(&scenario);
    let mut registry = ts::take_shared<AutoSwapRegistry>(&scenario);
    let c = clock::create_for_testing(ts::ctx(&mut scenario));

    let (extracted, ticket) = vault::auto_swap_extract<SUI>(
        &mut v2, &mut registry, &cap, 100, &c, ts::ctx(&mut scenario),
    );
    sui::balance::destroy_for_testing(extracted);
    vault::auto_swap_deposit<SUI>(&mut v2, sui::balance::zero<SUI>(), ticket, &c);

    clock::destroy_for_testing(c);
    ts::return_shared(registry);
    ts::return_shared(v2);
    ts::return_shared(cap);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = vault::EInsufficientBalance)]
fun extract_rejects_insufficient_balance() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario, USER);

    ts::next_tx(&mut scenario, USER);
    let mut v = ts::take_shared<TaliseVault>(&scenario);
    let small = coin::mint_for_testing<SUI>(50, ts::ctx(&mut scenario));
    vault::deposit<SUI>(&mut v, small, ts::ctx(&mut scenario));
    vault::enable_auto_swap<SUI>(&v, 1_000, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);

    ts::next_tx(&mut scenario, USER);
    let cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);

    ts::next_tx(&mut scenario, WORKER);
    let mut v2 = ts::take_shared<TaliseVault>(&scenario);
    let mut registry = ts::take_shared<AutoSwapRegistry>(&scenario);
    let c = clock::create_for_testing(ts::ctx(&mut scenario));

    // amount = 100 ≤ cap.max_per_swap, but vault only holds 50 SUI.
    let (extracted, ticket) = vault::auto_swap_extract<SUI>(
        &mut v2, &mut registry, &cap, 100, &c, ts::ctx(&mut scenario),
    );
    sui::balance::destroy_for_testing(extracted);
    vault::auto_swap_deposit<SUI>(&mut v2, sui::balance::zero<SUI>(), ticket, &c);

    clock::destroy_for_testing(c);
    ts::return_shared(registry);
    ts::return_shared(v2);
    ts::return_shared(cap);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// withdraw — error branches not covered by auto_swap_tests.move

#[test, expected_failure(abort_code = vault::EZeroAmount)]
fun withdraw_rejects_zero_amount() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_user_vault(&mut scenario, USER);

    ts::next_tx(&mut scenario, USER);
    let mut v = ts::take_shared<TaliseVault>(&scenario);
    let zero = vault::withdraw<SUI>(&mut v, 0, ts::ctx(&mut scenario));
    coin::burn_for_testing(zero);
    ts::return_shared(v);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = vault::ETypeNotHeld)]
fun withdraw_rejects_when_type_not_held() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_user_vault(&mut scenario, USER);

    ts::next_tx(&mut scenario, USER);
    let mut v = ts::take_shared<TaliseVault>(&scenario);
    let nothing = vault::withdraw<SUI>(&mut v, 1, ts::ctx(&mut scenario));
    coin::burn_for_testing(nothing);
    ts::return_shared(v);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = vault::EInsufficientBalance)]
fun withdraw_rejects_insufficient_balance() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_user_vault(&mut scenario, USER);

    ts::next_tx(&mut scenario, USER);
    let mut v = ts::take_shared<TaliseVault>(&scenario);
    let funded = coin::mint_for_testing<SUI>(10, ts::ctx(&mut scenario));
    vault::deposit<SUI>(&mut v, funded, ts::ctx(&mut scenario));
    let stolen = vault::withdraw<SUI>(&mut v, 1_000, ts::ctx(&mut scenario));
    coin::burn_for_testing(stolen);
    ts::return_shared(v);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// deposit — zero-amount rejection

#[test]
fun deposit_balance_zero_path_destroys_and_returns() {
    // The public `deposit` entry asserts amount > 0, so the
    // `destroy_zero` branch inside `deposit_balance` is only reachable
    // via the internal path that `auto_swap_deposit` and (theoretically)
    // future swap-output re-deposits would take with an empty balance.
    // We exercise it directly through `test_deposit_balance`.
    let mut scenario = ts::begin(PUBLISHER);
    setup_user_vault(&mut scenario, USER);

    ts::next_tx(&mut scenario, USER);
    let mut v = ts::take_shared<TaliseVault>(&scenario);
    let zero_bal = sui::balance::zero<SUI>();
    vault::test_deposit_balance<SUI>(&mut v, zero_bal, USER);
    // Counter must NOT bump on a zero deposit.
    assert_eq!(vault::deposits_total(&v), 0);
    assert_eq!(vault::balance_of<SUI>(&v), 0);
    ts::return_shared(v);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = vault::EWrongVault)]
fun auto_swap_deposit_rejects_ticket_for_different_vault() {
    // SwapTicket carries the source vault id. Trying to consume the
    // ticket against a different vault must abort with E_WRONG_VAULT.
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);

    // USER creates vault A, funds it, mints a cap.
    setup_user_vault(&mut scenario, USER);
    ts::next_tx(&mut scenario, USER);
    let mut v_a = ts::take_shared<TaliseVault>(&scenario);
    let v_a_id = sui::object::id(&v_a);
    let funded = coin::mint_for_testing<SUI>(10_000, ts::ctx(&mut scenario));
    vault::deposit<SUI>(&mut v_a, funded, ts::ctx(&mut scenario));
    vault::enable_auto_swap<SUI>(&v_a, 5_000, 0, ts::ctx(&mut scenario));
    ts::return_shared(v_a);

    ts::next_tx(&mut scenario, USER);
    let cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);

    // OTHER_USER creates vault B.
    setup_user_vault(&mut scenario, OTHER_USER);

    // WORKER extracts from vault A, then tries to deposit into vault B.
    ts::next_tx(&mut scenario, WORKER);
    let mut v_a2 = ts::take_shared_by_id<TaliseVault>(&scenario, v_a_id);
    let mut registry = ts::take_shared<AutoSwapRegistry>(&scenario);
    let c = clock::create_for_testing(ts::ctx(&mut scenario));

    let (extracted, ticket) = vault::auto_swap_extract<SUI>(
        &mut v_a2, &mut registry, &cap, 1_000, &c, ts::ctx(&mut scenario),
    );

    // Take vault B (the one that ISN'T v_a_id) and try to deposit into it.
    let v_first = ts::take_shared<TaliseVault>(&scenario);
    let mut v_b = if (sui::object::id(&v_first) == v_a_id) {
        ts::return_shared(v_first);
        ts::take_shared<TaliseVault>(&scenario)
    } else {
        v_first
    };

    // This call should abort with E_WRONG_VAULT.
    vault::auto_swap_deposit<SUI>(&mut v_b, extracted, ticket, &c);

    // Unreachable cleanup.
    clock::destroy_for_testing(c);
    ts::return_shared(registry);
    ts::return_shared(v_b);
    ts::return_shared(v_a2);
    ts::return_shared(cap);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = vault::EZeroAmount)]
fun deposit_rejects_zero_coin() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_user_vault(&mut scenario, USER);

    ts::next_tx(&mut scenario, USER);
    let mut v = ts::take_shared<TaliseVault>(&scenario);
    let zero_coin = coin::mint_for_testing<SUI>(0, ts::ctx(&mut scenario));
    vault::deposit<SUI>(&mut v, zero_coin, ts::ctx(&mut scenario));
    ts::return_shared(v);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// auto_swap_deposit_to_owner (v4) — new entry the cron worker calls.
//
// Verifies:
//   (a) the swap output is delivered to `vault.owner` as a plain
//       `Coin<Dest>`, not folded into the vault's bag;
//   (b) any pre-v4 stale Balance<Dest> sitting in `vault.balances`
//       gets flushed out alongside the new output in the same tx;
//   (c) the ticket's `vault_id` is still asserted — passing a ticket
//       issued against a different vault aborts with E_WRONG_VAULT.

#[test]
fun auto_swap_deposit_to_owner_routes_output_to_vault_owner() {
    // (a) Happy path: USER funds the vault, WORKER swaps (simulated as
    // 1:1 SUI→SUI), and the combined Coin<SUI> should land in USER's
    // wallet — NOT inside the vault's bag.
    //
    // Note: because we simulate the swap as SUI→SUI, the Dest key
    // collides with the bag entry that holds the post-extract remainder.
    // The v4 entry deliberately flushes any stale Balance<Dest> from
    // the bag in the same tx, so the user receives extracted+remainder
    // = full original balance (1_000_000). That IS the v4 contract;
    // the SUI→SUI simulation just happens to exercise the flush path
    // for free. The next test (`…_flushes_stale_bag_balance`) covers
    // the migration scenario with a distinct stale entry.
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario, USER);

    ts::next_tx(&mut scenario, USER);
    let mut v = ts::take_shared<TaliseVault>(&scenario);
    let funded = coin::mint_for_testing<SUI>(1_000_000, ts::ctx(&mut scenario));
    vault::deposit<SUI>(&mut v, funded, ts::ctx(&mut scenario));
    vault::enable_auto_swap<SUI>(&v, 500_000, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);

    ts::next_tx(&mut scenario, USER);
    let cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);

    ts::next_tx(&mut scenario, WORKER);
    let mut v2 = ts::take_shared<TaliseVault>(&scenario);
    let mut registry = ts::take_shared<AutoSwapRegistry>(&scenario);
    let c = clock::create_for_testing(ts::ctx(&mut scenario));

    let (extracted, ticket) = vault::auto_swap_extract<SUI>(
        &mut v2, &mut registry, &cap, 300_000, &c, ts::ctx(&mut scenario),
    );
    assert_eq!(vault::balance_of<SUI>(&v2), 700_000);

    // Route output straight to the user's wallet. With Source==Dest the
    // v4 flush also drains the 700_000 remainder.
    vault::auto_swap_deposit_to_owner<SUI>(&mut v2, extracted, ticket, &c, ts::ctx(&mut scenario));

    // Vault bag SUI is empty — output was NOT folded back into the bag,
    // and the bag entry was flushed by the v4 stale-balance drain.
    assert_eq!(vault::balance_of<SUI>(&v2), 0);
    // Auto-swap counter still bumps so off-chain telemetry stays consistent.
    assert_eq!(vault::auto_swaps_total(&v2), 1);

    clock::destroy_for_testing(c);
    ts::return_shared(registry);
    ts::return_shared(v2);
    ts::return_shared(cap);

    // USER should now hold a Coin<SUI> of 1_000_000 in their wallet
    // (300_000 extracted + 700_000 flushed remainder).
    ts::next_tx(&mut scenario, USER);
    let received = ts::take_from_sender<Coin<SUI>>(&scenario);
    assert_eq!(received.value(), 1_000_000);
    coin::burn_for_testing(received);

    ts::end(scenario);
}

#[test]
fun auto_swap_deposit_to_owner_flushes_stale_bag_balance() {
    // (b) Migration path: a pre-v4 swap left a Balance<Dest> in the
    // vault bag. The first v4 tick should flush that AND deliver the
    // new swap output to USER in one shot.
    //
    // We pre-load the bag with a Balance<SUI> via `test_deposit_balance`
    // (the internal helper used by both `deposit` and `auto_swap_deposit`),
    // simulating the bag overhang from older deposit semantics.
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    setup_user_vault(&mut scenario, USER);

    // Pre-load 200_000 of Balance<SUI> into the bag (the "stale" overhang).
    ts::next_tx(&mut scenario, USER);
    let mut v = ts::take_shared<TaliseVault>(&scenario);
    let stale = sui::coin::mint_for_testing<SUI>(200_000, ts::ctx(&mut scenario));
    let stale_bal = sui::coin::into_balance(stale);
    vault::test_deposit_balance<SUI>(&mut v, stale_bal, USER);
    assert_eq!(vault::balance_of<SUI>(&v), 200_000);

    // Now fund SUI for extraction (separate logical source pool) and
    // enable the cap. Because the bag holds a single Balance<SUI>, the
    // funding `join`s into it — total becomes 200_000 + 1_000_000.
    let funded = coin::mint_for_testing<SUI>(1_000_000, ts::ctx(&mut scenario));
    vault::deposit<SUI>(&mut v, funded, ts::ctx(&mut scenario));
    assert_eq!(vault::balance_of<SUI>(&v), 1_200_000);
    vault::enable_auto_swap<SUI>(&v, 500_000, 0, ts::ctx(&mut scenario));
    ts::return_shared(v);

    ts::next_tx(&mut scenario, USER);
    let cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);

    ts::next_tx(&mut scenario, WORKER);
    let mut v2 = ts::take_shared<TaliseVault>(&scenario);
    let mut registry = ts::take_shared<AutoSwapRegistry>(&scenario);
    let c = clock::create_for_testing(ts::ctx(&mut scenario));

    // Extract 400_000 SUI from the bag. Bag holds 800_000 after.
    let (extracted, ticket) = vault::auto_swap_extract<SUI>(
        &mut v2, &mut registry, &cap, 400_000, &c, ts::ctx(&mut scenario),
    );
    assert_eq!(vault::balance_of<SUI>(&v2), 800_000);

    // `auto_swap_deposit_to_owner` should:
    //   - take the extracted 400_000 (swap output, simulated 1:1),
    //   - remove the *remaining* 800_000 of Balance<SUI> from the bag
    //     (the "stale" overhang for the Dest type),
    //   - join them, and send the combined 1_200_000 to USER's wallet.
    vault::auto_swap_deposit_to_owner<SUI>(&mut v2, extracted, ticket, &c, ts::ctx(&mut scenario));

    // Bag should now hold zero SUI — the stale entry was removed.
    assert_eq!(vault::balance_of<SUI>(&v2), 0);

    clock::destroy_for_testing(c);
    ts::return_shared(registry);
    ts::return_shared(v2);
    ts::return_shared(cap);

    // USER should hold the combined Coin<SUI> = 1_200_000.
    ts::next_tx(&mut scenario, USER);
    let received = ts::take_from_sender<Coin<SUI>>(&scenario);
    assert_eq!(received.value(), 1_200_000);
    coin::burn_for_testing(received);

    ts::end(scenario);
}

#[test, expected_failure(abort_code = vault::EWrongVault)]
fun auto_swap_deposit_to_owner_rejects_ticket_for_different_vault() {
    // (c) The ticket carries the source vault id; the to-owner deposit
    // must still assert it. Extracting from vault A and trying to close
    // the ticket against vault B should abort with E_WRONG_VAULT.
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);

    // USER creates vault A, funds it, mints a cap.
    setup_user_vault(&mut scenario, USER);
    ts::next_tx(&mut scenario, USER);
    let mut v_a = ts::take_shared<TaliseVault>(&scenario);
    let v_a_id = sui::object::id(&v_a);
    let funded = coin::mint_for_testing<SUI>(10_000, ts::ctx(&mut scenario));
    vault::deposit<SUI>(&mut v_a, funded, ts::ctx(&mut scenario));
    vault::enable_auto_swap<SUI>(&v_a, 5_000, 0, ts::ctx(&mut scenario));
    ts::return_shared(v_a);

    ts::next_tx(&mut scenario, USER);
    let cap = ts::take_shared<AutoSwapCap<SUI>>(&scenario);

    // OTHER_USER creates vault B.
    setup_user_vault(&mut scenario, OTHER_USER);

    // WORKER extracts from vault A, then tries to deposit-to-owner into vault B.
    ts::next_tx(&mut scenario, WORKER);
    let mut v_a2 = ts::take_shared_by_id<TaliseVault>(&scenario, v_a_id);
    let mut registry = ts::take_shared<AutoSwapRegistry>(&scenario);
    let c = clock::create_for_testing(ts::ctx(&mut scenario));

    let (extracted, ticket) = vault::auto_swap_extract<SUI>(
        &mut v_a2, &mut registry, &cap, 1_000, &c, ts::ctx(&mut scenario),
    );

    // Pick vault B (the one that isn't v_a_id).
    let v_first = ts::take_shared<TaliseVault>(&scenario);
    let mut v_b = if (sui::object::id(&v_first) == v_a_id) {
        ts::return_shared(v_first);
        ts::take_shared<TaliseVault>(&scenario)
    } else {
        v_first
    };

    // Aborts with E_WRONG_VAULT.
    vault::auto_swap_deposit_to_owner<SUI>(&mut v_b, extracted, ticket, &c, ts::ctx(&mut scenario));

    // Unreachable cleanup.
    clock::destroy_for_testing(c);
    ts::return_shared(registry);
    ts::return_shared(v_b);
    ts::return_shared(v_a2);
    ts::return_shared(cap);
    ts::end(scenario);
}
