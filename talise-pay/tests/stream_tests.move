/// Tests for the streaming-payments escrow.
///
/// Coverage:
///   • happy path: create → release per-tranche, last tranche pays remainder
///   • access control: non-worker release aborts E_NOT_WORKER;
///     non-sender pause/cancel aborts E_NOT_SENDER
///   • registry kill switch: paused registry blocks release (E_REGISTRY_PAUSED)
///   • clock gate: release before due aborts E_TRANCHE_NOT_DUE
///   • idempotency / double-pay prevention: second release in same interval
///     aborts E_TRANCHE_NOT_DUE; release past completion aborts
///     E_STREAM_COMPLETE
///   • claim_accrued permissionless safety valve only ever pays the recipient
///   • cancel returns the undistributed remainder to the sender
///   • worker add/remove + remove-of-absent aborts
///
/// Caps use a dummy coin type `T = SUI` via `coin::mint_for_testing` →
/// `coin::into_balance` to obtain the `Balance<T>` that `create` expects.
#[test_only]
module talise::stream_tests;

use std::unit_test::assert_eq;
use sui::{balance, clock, coin, sui::SUI, test_scenario as ts};
use talise::stream::{Self, StreamRegistry, StreamAdminCap, Stream};

const PUBLISHER: address = @0xA;
const SENDER: address = @0xB;
const RECIPIENT: address = @0xC;
const WORKER: address = @0xD;
const RANDO: address = @0xE;

const INTERVAL: u64 = 1_000; // 1s in ms
const START: u64 = 10_000;

// ───────────────────────────────────────────────────────────────────
// Helpers

fun setup_registry(scenario: &mut ts::Scenario) {
    ts::next_tx(scenario, PUBLISHER);
    stream::test_init(ts::ctx(scenario));
}

/// PUBLISHER grants WORKER the worker role.
fun grant_worker(scenario: &mut ts::Scenario) {
    ts::next_tx(scenario, PUBLISHER);
    let cap = ts::take_from_sender<StreamAdminCap>(scenario);
    let mut reg = ts::take_shared<StreamRegistry>(scenario);
    stream::add_worker(&mut reg, &cap, WORKER);
    ts::return_shared(reg);
    ts::return_to_sender(scenario, cap);
}

/// SENDER funds a stream: `total` mist, `num_tranches` tranches of
/// `tranche_amount` each (last pays remainder). Clock is at ms=0.
fun fund_stream(
    scenario: &mut ts::Scenario,
    total: u64,
    tranche_amount: u64,
    num_tranches: u64,
): ID {
    ts::next_tx(scenario, SENDER);
    let mut reg = ts::take_shared<StreamRegistry>(scenario);
    let c = clock::create_for_testing(ts::ctx(scenario));
    let funds = coin::mint_for_testing<SUI>(total, ts::ctx(scenario)).into_balance();
    let sid = stream::create<SUI>(
        &mut reg,
        funds,
        RECIPIENT,
        tranche_amount,
        num_tranches,
        START,
        INTERVAL,
        &c,
        ts::ctx(scenario),
    );
    clock::destroy_for_testing(c);
    ts::return_shared(reg);
    sid
}

// ───────────────────────────────────────────────────────────────────
// Happy path

#[test]
fun create_then_release_all_tranches() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);

    // 3 tranches of 100; total 300 (last tranche pays the remainder = 100).
    let sid = fund_stream(&mut scenario, 300, 100, 3);

    // Tranche 1 at due_at = START + 0*INTERVAL = 10_000.
    ts::next_tx(&mut scenario, WORKER);
    {
        let mut reg = ts::take_shared<StreamRegistry>(&scenario);
        let mut s = ts::take_shared_by_id<Stream<SUI>>(&scenario, sid);
        let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
        clock::set_for_testing(&mut c, START); // exactly due
        stream::release<SUI>(&mut reg, &mut s, &c, ts::ctx(&mut scenario));
        assert_eq!(stream::tranches_done(&s), 1);
        assert_eq!(stream::released_amount(&s), 100);
        assert_eq!(stream::escrow_value(&s), 200);
        clock::destroy_for_testing(c);
        ts::return_shared(s);
        ts::return_shared(reg);
    };

    // Tranche 2 at due_at = START + 1*INTERVAL = 11_000.
    ts::next_tx(&mut scenario, WORKER);
    {
        let mut reg = ts::take_shared<StreamRegistry>(&scenario);
        let mut s = ts::take_shared_by_id<Stream<SUI>>(&scenario, sid);
        let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
        clock::set_for_testing(&mut c, START + INTERVAL);
        stream::release<SUI>(&mut reg, &mut s, &c, ts::ctx(&mut scenario));
        assert_eq!(stream::tranches_done(&s), 2);
        assert_eq!(stream::released_amount(&s), 200);
        clock::destroy_for_testing(c);
        ts::return_shared(s);
        ts::return_shared(reg);
    };

    // Tranche 3 (last) at due_at = START + 2*INTERVAL = 12_000. Pays remainder.
    ts::next_tx(&mut scenario, WORKER);
    {
        let mut reg = ts::take_shared<StreamRegistry>(&scenario);
        let mut s = ts::take_shared_by_id<Stream<SUI>>(&scenario, sid);
        let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
        clock::set_for_testing(&mut c, START + 2 * INTERVAL);
        stream::release<SUI>(&mut reg, &mut s, &c, ts::ctx(&mut scenario));
        assert_eq!(stream::tranches_done(&s), 3);
        assert_eq!(stream::released_amount(&s), 300);
        assert_eq!(stream::escrow_value(&s), 0);
        clock::destroy_for_testing(c);
        ts::return_shared(s);
        ts::return_shared(reg);
    };

    // Recipient must hold three coins now; sender holds none.
    ts::next_tx(&mut scenario, RECIPIENT);
    {
        let coin_held = ts::take_from_sender<coin::Coin<SUI>>(&scenario);
        coin::burn_for_testing(coin_held);
        let coin2 = ts::take_from_sender<coin::Coin<SUI>>(&scenario);
        coin::burn_for_testing(coin2);
        let coin3 = ts::take_from_sender<coin::Coin<SUI>>(&scenario);
        assert_eq!(coin3.value(), 100);
        coin::burn_for_testing(coin3);
    };

    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// Clock gate

#[test, expected_failure(abort_code = stream::ETrancheNotDue)]
fun release_before_due_aborts() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    let sid = fund_stream(&mut scenario, 300, 100, 3);

    ts::next_tx(&mut scenario, WORKER);
    let mut reg = ts::take_shared<StreamRegistry>(&scenario);
    let mut s = ts::take_shared_by_id<Stream<SUI>>(&scenario, sid);
    let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut c, START - 1); // one ms before first due
    stream::release<SUI>(&mut reg, &mut s, &c, ts::ctx(&mut scenario));
    clock::destroy_for_testing(c);
    ts::return_shared(s);
    ts::return_shared(reg);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// Idempotency / double-pay prevention

#[test, expected_failure(abort_code = stream::ETrancheNotDue)]
fun second_release_same_interval_aborts() {
    // Two releases at the SAME timestamp: the second's due_at has advanced
    // by one INTERVAL (because tranches_done bumped), so it is not yet due.
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    let sid = fund_stream(&mut scenario, 300, 100, 3);

    ts::next_tx(&mut scenario, WORKER);
    let mut reg = ts::take_shared<StreamRegistry>(&scenario);
    let mut s = ts::take_shared_by_id<Stream<SUI>>(&scenario, sid);
    let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut c, START); // due for tranche 1 only
    stream::release<SUI>(&mut reg, &mut s, &c, ts::ctx(&mut scenario));
    // Replay (double-fired cron) at the same ms — tranche 2 not yet due.
    stream::release<SUI>(&mut reg, &mut s, &c, ts::ctx(&mut scenario));
    clock::destroy_for_testing(c);
    ts::return_shared(s);
    ts::return_shared(reg);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = stream::EStreamComplete)]
fun release_after_completion_aborts() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    // 1 tranche → completes immediately.
    let sid = fund_stream(&mut scenario, 100, 100, 1);

    ts::next_tx(&mut scenario, WORKER);
    let mut reg = ts::take_shared<StreamRegistry>(&scenario);
    let mut s = ts::take_shared_by_id<Stream<SUI>>(&scenario, sid);
    let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut c, START + 100 * INTERVAL);
    stream::release<SUI>(&mut reg, &mut s, &c, ts::ctx(&mut scenario)); // completes
    assert_eq!(stream::tranches_done(&s), 1);
    stream::release<SUI>(&mut reg, &mut s, &c, ts::ctx(&mut scenario)); // aborts
    clock::destroy_for_testing(c);
    ts::return_shared(s);
    ts::return_shared(reg);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// Access control

#[test, expected_failure(abort_code = stream::ENotWorker)]
fun non_worker_release_aborts() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    let sid = fund_stream(&mut scenario, 300, 100, 3);

    // RANDO is not a registered worker.
    ts::next_tx(&mut scenario, RANDO);
    let mut reg = ts::take_shared<StreamRegistry>(&scenario);
    let mut s = ts::take_shared_by_id<Stream<SUI>>(&scenario, sid);
    let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut c, START);
    stream::release<SUI>(&mut reg, &mut s, &c, ts::ctx(&mut scenario));
    clock::destroy_for_testing(c);
    ts::return_shared(s);
    ts::return_shared(reg);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = stream::ERegistryPaused)]
fun paused_registry_blocks_release() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    let sid = fund_stream(&mut scenario, 300, 100, 3);

    // Admin trips the kill switch.
    ts::next_tx(&mut scenario, PUBLISHER);
    {
        let cap = ts::take_from_sender<StreamAdminCap>(&scenario);
        let mut reg = ts::take_shared<StreamRegistry>(&scenario);
        stream::set_paused(&mut reg, &cap, true);
        ts::return_shared(reg);
        ts::return_to_sender(&scenario, cap);
    };

    ts::next_tx(&mut scenario, WORKER);
    let mut reg = ts::take_shared<StreamRegistry>(&scenario);
    let mut s = ts::take_shared_by_id<Stream<SUI>>(&scenario, sid);
    let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut c, START);
    stream::release<SUI>(&mut reg, &mut s, &c, ts::ctx(&mut scenario));
    clock::destroy_for_testing(c);
    ts::return_shared(s);
    ts::return_shared(reg);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = stream::ENotSender)]
fun non_sender_pause_aborts() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    let sid = fund_stream(&mut scenario, 300, 100, 3);

    ts::next_tx(&mut scenario, RANDO);
    let mut s = ts::take_shared_by_id<Stream<SUI>>(&scenario, sid);
    stream::pause<SUI>(&mut s, ts::ctx(&mut scenario));
    ts::return_shared(s);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = stream::ENotSender)]
fun non_sender_cancel_aborts() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    let sid = fund_stream(&mut scenario, 300, 100, 3);

    ts::next_tx(&mut scenario, RANDO);
    let mut s = ts::take_shared_by_id<Stream<SUI>>(&scenario, sid);
    let stolen = stream::cancel_and_withdraw<SUI>(&mut s, ts::ctx(&mut scenario));
    coin::burn_for_testing(stolen);
    ts::return_shared(s);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// Pause blocks release

#[test, expected_failure(abort_code = stream::EPaused)]
fun paused_stream_blocks_release() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    let sid = fund_stream(&mut scenario, 300, 100, 3);

    // SENDER pauses.
    ts::next_tx(&mut scenario, SENDER);
    {
        let mut s = ts::take_shared_by_id<Stream<SUI>>(&scenario, sid);
        stream::pause<SUI>(&mut s, ts::ctx(&mut scenario));
        assert!(stream::is_paused(&s));
        ts::return_shared(s);
    };

    ts::next_tx(&mut scenario, WORKER);
    let mut reg = ts::take_shared<StreamRegistry>(&scenario);
    let mut s = ts::take_shared_by_id<Stream<SUI>>(&scenario, sid);
    let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut c, START);
    stream::release<SUI>(&mut reg, &mut s, &c, ts::ctx(&mut scenario));
    clock::destroy_for_testing(c);
    ts::return_shared(s);
    ts::return_shared(reg);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// claim_accrued safety valve + cancel refund

#[test]
fun claim_accrued_releases_due_tranches_to_recipient() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    let sid = fund_stream(&mut scenario, 300, 100, 3);

    // RANDO (not a worker) calls the permissionless valve at a time when
    // the first two tranches are due (START + 1*INTERVAL).
    ts::next_tx(&mut scenario, RANDO);
    let mut s = ts::take_shared_by_id<Stream<SUI>>(&scenario, sid);
    let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut c, START + INTERVAL);
    stream::claim_accrued<SUI>(&mut s, &c, ts::ctx(&mut scenario));
    assert_eq!(stream::tranches_done(&s), 2);
    assert_eq!(stream::released_amount(&s), 200);
    clock::destroy_for_testing(c);
    ts::return_shared(s);

    // The funds went to RECIPIENT (hardwired), never to RANDO.
    ts::next_tx(&mut scenario, RECIPIENT);
    {
        let coin1 = ts::take_from_sender<coin::Coin<SUI>>(&scenario);
        coin::burn_for_testing(coin1);
        let coin2 = ts::take_from_sender<coin::Coin<SUI>>(&scenario);
        coin::burn_for_testing(coin2);
    };
    ts::next_tx(&mut scenario, RANDO);
    assert!(!ts::has_most_recent_for_sender<coin::Coin<SUI>>(&scenario));

    ts::end(scenario);
}

#[test]
fun cancel_refunds_remainder_to_sender() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    let sid = fund_stream(&mut scenario, 300, 100, 3);

    // Release one tranche (100 to recipient), leaving 200 in escrow.
    ts::next_tx(&mut scenario, WORKER);
    {
        let mut reg = ts::take_shared<StreamRegistry>(&scenario);
        let mut s = ts::take_shared_by_id<Stream<SUI>>(&scenario, sid);
        let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
        clock::set_for_testing(&mut c, START);
        stream::release<SUI>(&mut reg, &mut s, &c, ts::ctx(&mut scenario));
        clock::destroy_for_testing(c);
        ts::return_shared(s);
        ts::return_shared(reg);
    };

    // SENDER cancels and gets the 200 remainder back.
    ts::next_tx(&mut scenario, SENDER);
    {
        let mut s = ts::take_shared_by_id<Stream<SUI>>(&scenario, sid);
        let refund = stream::cancel_and_withdraw<SUI>(&mut s, ts::ctx(&mut scenario));
        assert_eq!(refund.value(), 200);
        assert!(stream::is_cancelled(&s));
        coin::burn_for_testing(refund);
        ts::return_shared(s);
    };

    ts::end(scenario);
}

#[test, expected_failure(abort_code = stream::ECancelled)]
fun release_after_cancel_aborts() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    let sid = fund_stream(&mut scenario, 300, 100, 3);

    ts::next_tx(&mut scenario, SENDER);
    {
        let mut s = ts::take_shared_by_id<Stream<SUI>>(&scenario, sid);
        let refund = stream::cancel_and_withdraw<SUI>(&mut s, ts::ctx(&mut scenario));
        coin::burn_for_testing(refund);
        ts::return_shared(s);
    };

    ts::next_tx(&mut scenario, WORKER);
    let mut reg = ts::take_shared<StreamRegistry>(&scenario);
    let mut s = ts::take_shared_by_id<Stream<SUI>>(&scenario, sid);
    let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut c, START);
    stream::release<SUI>(&mut reg, &mut s, &c, ts::ctx(&mut scenario));
    clock::destroy_for_testing(c);
    ts::return_shared(s);
    ts::return_shared(reg);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// create input validation + overflow-safe schedule guard

#[test, expected_failure(abort_code = stream::EZeroAmount)]
fun create_rejects_zero_funds() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);

    ts::next_tx(&mut scenario, SENDER);
    let mut reg = ts::take_shared<StreamRegistry>(&scenario);
    let c = clock::create_for_testing(ts::ctx(&mut scenario));
    let funds = balance::zero<SUI>();
    let _sid = stream::create<SUI>(
        &mut reg, funds, RECIPIENT, 100, 3, START, INTERVAL, &c, ts::ctx(&mut scenario),
    );
    clock::destroy_for_testing(c);
    ts::return_shared(reg);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = stream::EBadSchedule)]
fun create_rejects_underfunded_schedule() {
    // tranche_amount * (num_tranches - 1) > total: 100 * 4 = 400 > 300.
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);

    ts::next_tx(&mut scenario, SENDER);
    let mut reg = ts::take_shared<StreamRegistry>(&scenario);
    let c = clock::create_for_testing(ts::ctx(&mut scenario));
    let funds = coin::mint_for_testing<SUI>(300, ts::ctx(&mut scenario)).into_balance();
    let _sid = stream::create<SUI>(
        &mut reg, funds, RECIPIENT, 100, 5, START, INTERVAL, &c, ts::ctx(&mut scenario),
    );
    clock::destroy_for_testing(c);
    ts::return_shared(reg);
    ts::end(scenario);
}

#[test]
fun create_accepts_large_tranche_without_overflow() {
    // Overflow-safe guard regression: with the old multiply,
    // tranche_amount * (num_tranches - 1) would wrap. Here a huge
    // tranche_amount with num_tranches=1 must NOT abort: (1-1)=0 <= total/ta.
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);

    ts::next_tx(&mut scenario, SENDER);
    let mut reg = ts::take_shared<StreamRegistry>(&scenario);
    let c = clock::create_for_testing(ts::ctx(&mut scenario));
    let huge = 18_000_000_000_000_000_000; // near u64::MAX
    let funds = coin::mint_for_testing<SUI>(huge, ts::ctx(&mut scenario)).into_balance();
    let sid = stream::create<SUI>(
        &mut reg, funds, RECIPIENT, huge, 1, START, INTERVAL, &c, ts::ctx(&mut scenario),
    );
    clock::destroy_for_testing(c);
    ts::return_shared(reg);

    ts::next_tx(&mut scenario, SENDER);
    let s = ts::take_shared_by_id<Stream<SUI>>(&scenario, sid);
    assert_eq!(stream::escrow_value(&s), huge);
    ts::return_shared(s);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// Worker management

#[test, expected_failure(abort_code = stream::EWorkerAlreadyAdded)]
fun add_worker_twice_aborts() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);

    ts::next_tx(&mut scenario, PUBLISHER);
    let cap = ts::take_from_sender<StreamAdminCap>(&scenario);
    let mut reg = ts::take_shared<StreamRegistry>(&scenario);
    stream::add_worker(&mut reg, &cap, WORKER);
    stream::add_worker(&mut reg, &cap, WORKER); // dup → abort
    ts::return_shared(reg);
    ts::return_to_sender(&scenario, cap);
    ts::end(scenario);
}

#[test]
fun remove_worker_revokes_release_ability() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);

    // Admin revokes the worker.
    ts::next_tx(&mut scenario, PUBLISHER);
    let cap = ts::take_from_sender<StreamAdminCap>(&scenario);
    let mut reg = ts::take_shared<StreamRegistry>(&scenario);
    assert!(stream::is_worker(&reg, WORKER));
    stream::remove_worker(&mut reg, &cap, WORKER);
    assert!(!stream::is_worker(&reg, WORKER));
    ts::return_shared(reg);
    ts::return_to_sender(&scenario, cap);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = stream::EWorkerNotFound)]
fun remove_absent_worker_aborts() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);

    ts::next_tx(&mut scenario, PUBLISHER);
    let cap = ts::take_from_sender<StreamAdminCap>(&scenario);
    let mut reg = ts::take_shared<StreamRegistry>(&scenario);
    stream::remove_worker(&mut reg, &cap, RANDO); // never added → abort
    ts::return_shared(reg);
    ts::return_to_sender(&scenario, cap);
    ts::end(scenario);
}
