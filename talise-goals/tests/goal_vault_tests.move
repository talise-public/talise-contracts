/// Tests for the per-goal savings vault.
///
/// Coverage:
///   • happy path: create → deposit → progress/complete → withdraw → close
///   • create_with funds the vault in one call
///   • owner-only: a non-owner withdraw aborts ENotOwner
///   • over-withdraw aborts EInsufficientBalance
///   • progress_bps / is_complete math (incl. 0-target and over-target caps)
///
/// Dummy coin type `T = SUI` via `coin::mint_for_testing`.
#[test_only]
module talise_goals::goal_vault_tests;

use std::unit_test::assert_eq;
use sui::{clock, coin, sui::SUI, test_scenario as ts};
use talise_goals::goal_vault::{Self, GoalVault};

const OWNER: address = @0xA;
const RANDO: address = @0xB;

const VENUE_NAVI: u8 = 1;

/// Stand-in for a venue lending receipt (NAVI account/obligation). key+store
/// is all `park_receipt`/`take_receipt` require of `R`.
public struct FakeReceipt has key, store { id: UID }

#[test]
fun create_deposit_withdraw_close() {
    let mut sc = ts::begin(OWNER);
    let clk = clock::create_for_testing(ts::ctx(&mut sc));

    goal_vault::create<SUI>(b"Singapore Trip", 1000, &clk, ts::ctx(&mut sc));
    ts::next_tx(&mut sc, OWNER);
    let mut v = ts::take_from_sender<GoalVault<SUI>>(&sc);
    assert_eq!(goal_vault::balance(&v), 0);
    assert_eq!(goal_vault::target(&v), 1000);
    assert_eq!(goal_vault::owner(&v), OWNER);
    assert_eq!(goal_vault::is_complete(&v), false);

    // deposit 600 → 60% progress, not complete
    goal_vault::deposit(&mut v, coin::mint_for_testing<SUI>(600, ts::ctx(&mut sc)));
    assert_eq!(goal_vault::balance(&v), 600);
    assert_eq!(goal_vault::progress_bps(&v), 6000);
    assert_eq!(goal_vault::is_complete(&v), false);

    // deposit 500 → 1100 ≥ target → complete, progress capped at 10000
    goal_vault::deposit(&mut v, coin::mint_for_testing<SUI>(500, ts::ctx(&mut sc)));
    assert_eq!(goal_vault::balance(&v), 1100);
    assert_eq!(goal_vault::is_complete(&v), true);
    assert_eq!(goal_vault::progress_bps(&v), 10000);
    assert_eq!(goal_vault::deposits_total(&v), 1100);

    // withdraw 400 anytime → 700 left
    let out = goal_vault::withdraw(&mut v, 400, ts::ctx(&mut sc));
    assert_eq!(coin::value(&out), 400);
    assert_eq!(goal_vault::balance(&v), 700);
    assert_eq!(goal_vault::withdrawals_total(&v), 400);
    coin::burn_for_testing(out);

    // close → returns remaining 700 and deletes the object
    let rest = goal_vault::close(v, ts::ctx(&mut sc));
    assert_eq!(coin::value(&rest), 700);
    coin::burn_for_testing(rest);

    clock::destroy_for_testing(clk);
    ts::end(sc);
}

#[test]
fun create_with_funds_immediately() {
    let mut sc = ts::begin(OWNER);
    let clk = clock::create_for_testing(ts::ctx(&mut sc));

    let seed = coin::mint_for_testing<SUI>(250, ts::ctx(&mut sc));
    goal_vault::create_with<SUI>(b"Laptop", 250, seed, &clk, ts::ctx(&mut sc));
    ts::next_tx(&mut sc, OWNER);
    let v = ts::take_from_sender<GoalVault<SUI>>(&sc);
    assert_eq!(goal_vault::balance(&v), 250);
    assert_eq!(goal_vault::is_complete(&v), true);
    assert_eq!(goal_vault::deposits_total(&v), 250);

    let rest = goal_vault::close(v, ts::ctx(&mut sc));
    coin::burn_for_testing(rest);
    clock::destroy_for_testing(clk);
    ts::end(sc);
}

#[test]
fun zero_target_never_complete() {
    let mut sc = ts::begin(OWNER);
    let clk = clock::create_for_testing(ts::ctx(&mut sc));
    goal_vault::create_with<SUI>(b"Open fund", 0, coin::mint_for_testing<SUI>(999, ts::ctx(&mut sc)), &clk, ts::ctx(&mut sc));
    ts::next_tx(&mut sc, OWNER);
    let v = ts::take_from_sender<GoalVault<SUI>>(&sc);
    assert_eq!(goal_vault::is_complete(&v), false);
    assert_eq!(goal_vault::progress_bps(&v), 0);
    let rest = goal_vault::close(v, ts::ctx(&mut sc));
    coin::burn_for_testing(rest);
    clock::destroy_for_testing(clk);
    ts::end(sc);
}

#[test]
fun park_and_take_receipt() {
    let mut sc = ts::begin(OWNER);
    let clk = clock::create_for_testing(ts::ctx(&mut sc));
    goal_vault::create<SUI>(b"Yielding goal", 1000, &clk, ts::ctx(&mut sc));
    ts::next_tx(&mut sc, OWNER);
    let mut v = ts::take_from_sender<GoalVault<SUI>>(&sc);

    // Owner parks a venue receipt (after an SDK supply PTB) → venue/basis set.
    let receipt = FakeReceipt { id: object::new(ts::ctx(&mut sc)) };
    goal_vault::park_receipt(&mut v, receipt, VENUE_NAVI, 800, ts::ctx(&mut sc));
    assert_eq!(goal_vault::venue(&v), VENUE_NAVI);
    assert_eq!(goal_vault::basis(&v), 800);
    assert_eq!(goal_vault::has_receipt(&v), true);

    // Owner pulls it back out to run a redeem PTB → tracking cleared.
    let back: FakeReceipt = goal_vault::take_receipt(&mut v, ts::ctx(&mut sc));
    assert_eq!(goal_vault::venue(&v), 0);
    assert_eq!(goal_vault::basis(&v), 0);
    assert_eq!(goal_vault::has_receipt(&v), false);
    let FakeReceipt { id } = back;
    id.delete();

    let rest = goal_vault::close(v, ts::ctx(&mut sc));
    coin::burn_for_testing(rest);
    clock::destroy_for_testing(clk);
    ts::end(sc);
}

#[test, expected_failure(abort_code = goal_vault::EReceiptParked)]
fun cannot_close_with_parked_receipt() {
    let mut sc = ts::begin(OWNER);
    let clk = clock::create_for_testing(ts::ctx(&mut sc));
    goal_vault::create<SUI>(b"Yielding goal", 0, &clk, ts::ctx(&mut sc));
    ts::next_tx(&mut sc, OWNER);
    let mut v = ts::take_from_sender<GoalVault<SUI>>(&sc);
    let receipt = FakeReceipt { id: object::new(ts::ctx(&mut sc)) };
    goal_vault::park_receipt(&mut v, receipt, VENUE_NAVI, 100, ts::ctx(&mut sc));

    // Closing while a receipt is parked must abort (funds would be orphaned).
    let rest = goal_vault::close(v, ts::ctx(&mut sc));

    coin::burn_for_testing(rest);
    clock::destroy_for_testing(clk);
    ts::end(sc);
}

#[test, expected_failure(abort_code = goal_vault::ENotOwner)]
fun non_owner_cannot_withdraw() {
    let mut sc = ts::begin(OWNER);
    let clk = clock::create_for_testing(ts::ctx(&mut sc));
    goal_vault::create_with<SUI>(b"Vault", 0, coin::mint_for_testing<SUI>(500, ts::ctx(&mut sc)), &clk, ts::ctx(&mut sc));
    ts::next_tx(&mut sc, OWNER);
    let mut v = ts::take_from_sender<GoalVault<SUI>>(&sc);

    // RANDO signs the next tx and tries to withdraw → aborts ENotOwner.
    ts::next_tx(&mut sc, RANDO);
    let out = goal_vault::withdraw(&mut v, 100, ts::ctx(&mut sc));

    // Unreachable, but must type-check (no drop on these resources).
    coin::burn_for_testing(out);
    ts::return_to_address(OWNER, v);
    clock::destroy_for_testing(clk);
    ts::end(sc);
}

#[test, expected_failure(abort_code = goal_vault::EInsufficientBalance)]
fun cannot_overdraw() {
    let mut sc = ts::begin(OWNER);
    let clk = clock::create_for_testing(ts::ctx(&mut sc));
    goal_vault::create_with<SUI>(b"Vault", 0, coin::mint_for_testing<SUI>(100, ts::ctx(&mut sc)), &clk, ts::ctx(&mut sc));
    ts::next_tx(&mut sc, OWNER);
    let mut v = ts::take_from_sender<GoalVault<SUI>>(&sc);

    let out = goal_vault::withdraw(&mut v, 999, ts::ctx(&mut sc)); // > balance → aborts

    coin::burn_for_testing(out);
    ts::return_to_address(OWNER, v);
    clock::destroy_for_testing(clk);
    ts::end(sc);
}
