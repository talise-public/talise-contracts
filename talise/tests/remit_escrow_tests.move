/// Tests for the trustless off-ramp escrow.
///   • happy path: open → commit → release pays the treasury
///   • trustless refund: open → (timeout) → permissionless reclaim pays SENDER
///   • reclaim before timeout aborts ENotTimedOut
///   • reclaim after commit aborts ECommitted (the race fix)
///   • release without commit aborts ENotCommitted
///   • commit by a non-worker aborts ENotWorker
///   • open by a denied sender aborts (compliance EDenied)
///   • sender cancel (pre-commit) returns funds
///   • a compliance freeze blocks release (EFrozen)
#[test_only]
module talise::remit_escrow_tests;

use std::unit_test::assert_eq;
use sui::{clock, coin, sui::SUI, test_scenario as ts};
use talise::{
    compliance::{Self, ComplianceRegistry, ComplianceAdminCap},
    remit_escrow::{Self as remit, RemitRegistry, RemitAdminCap, RemitEscrow},
};

const PUBLISHER: address = @0xA;
const SENDER: address = @0xB;
const WORKER: address = @0xD;
const RANDO: address = @0xE;
const TREASURY: address = @0x7;

const AMOUNT: u64 = 5_000_000;
const TIMEOUT: u64 = 100_000;

fun setup(s: &mut ts::Scenario) {
    ts::next_tx(s, PUBLISHER);
    compliance::test_init(ts::ctx(s));
    ts::next_tx(s, PUBLISHER);
    remit::test_init(ts::ctx(s));
    ts::next_tx(s, PUBLISHER);
    let cap = ts::take_from_sender<RemitAdminCap>(s);
    let mut reg = ts::take_shared<RemitRegistry>(s);
    remit::add_worker(&mut reg, &cap, WORKER);
    remit::set_treasury(&mut reg, &cap, TREASURY);
    ts::return_shared(reg);
    ts::return_to_sender(s, cap);
}

fun open_escrow(s: &mut ts::Scenario): ID {
    ts::next_tx(s, SENDER);
    let mut reg = ts::take_shared<RemitRegistry>(s);
    let comp = ts::take_shared<ComplianceRegistry>(s);
    let c = clock::create_for_testing(ts::ctx(s)); // ms = 0
    let funds = coin::mint_for_testing<SUI>(AMOUNT, ts::ctx(s)).into_balance();
    let eid = remit::open<SUI>(&mut reg, &comp, funds, b"tx-1", TIMEOUT, &c, ts::ctx(s));
    clock::destroy_for_testing(c);
    ts::return_shared(reg);
    ts::return_shared(comp);
    eid
}

#[test]
fun open_commit_release_pays_treasury() {
    let mut s = ts::begin(PUBLISHER);
    setup(&mut s);
    let eid = open_escrow(&mut s);

    ts::next_tx(&mut s, WORKER);
    {
        let reg = ts::take_shared<RemitRegistry>(&s);
        let mut esc = ts::take_shared_by_id<RemitEscrow<SUI>>(&s, eid);
        remit::commit<SUI>(&reg, &mut esc, ts::ctx(&mut s));
        assert!(remit::is_committed(&esc));
        remit::release<SUI>(&reg, &mut esc, ts::ctx(&mut s));
        assert_eq!(remit::status(&esc), remit::status_released());
        assert_eq!(remit::escrow_value(&esc), 0);
        ts::return_shared(esc);
        ts::return_shared(reg);
    };

    // Treasury holds the funds; sender does not.
    ts::next_tx(&mut s, TREASURY);
    {
        let got = ts::take_from_sender<coin::Coin<SUI>>(&s);
        assert_eq!(got.value(), AMOUNT);
        coin::burn_for_testing(got);
    };
    ts::next_tx(&mut s, SENDER);
    assert!(!ts::has_most_recent_for_sender<coin::Coin<SUI>>(&s));
    ts::end(s);
}

#[test]
fun reclaim_after_timeout_pays_sender() {
    let mut s = ts::begin(PUBLISHER);
    setup(&mut s);
    let eid = open_escrow(&mut s);

    // RANDO (permissionless) reclaims after timeout → funds go to SENDER.
    ts::next_tx(&mut s, RANDO);
    {
        let mut esc = ts::take_shared_by_id<RemitEscrow<SUI>>(&s, eid);
        let mut c = clock::create_for_testing(ts::ctx(&mut s));
        clock::set_for_testing(&mut c, TIMEOUT); // >= timeout
        remit::reclaim<SUI>(&mut esc, &c, ts::ctx(&mut s));
        assert_eq!(remit::status(&esc), remit::status_reclaimed());
        clock::destroy_for_testing(c);
        ts::return_shared(esc);
    };
    ts::next_tx(&mut s, SENDER);
    {
        let got = ts::take_from_sender<coin::Coin<SUI>>(&s);
        assert_eq!(got.value(), AMOUNT);
        coin::burn_for_testing(got);
    };
    ts::end(s);
}

#[test, expected_failure(abort_code = remit::ENotTimedOut)]
fun reclaim_before_timeout_aborts() {
    let mut s = ts::begin(PUBLISHER);
    setup(&mut s);
    let eid = open_escrow(&mut s);
    ts::next_tx(&mut s, RANDO);
    let mut esc = ts::take_shared_by_id<RemitEscrow<SUI>>(&s, eid);
    let mut c = clock::create_for_testing(ts::ctx(&mut s));
    clock::set_for_testing(&mut c, TIMEOUT - 1);
    remit::reclaim<SUI>(&mut esc, &c, ts::ctx(&mut s));
    clock::destroy_for_testing(c);
    ts::return_shared(esc);
    ts::end(s);
}

#[test, expected_failure(abort_code = remit::ECommitted)]
fun reclaim_after_commit_aborts() {
    let mut s = ts::begin(PUBLISHER);
    setup(&mut s);
    let eid = open_escrow(&mut s);
    // worker commits (disables reclaim)
    ts::next_tx(&mut s, WORKER);
    {
        let reg = ts::take_shared<RemitRegistry>(&s);
        let mut esc = ts::take_shared_by_id<RemitEscrow<SUI>>(&s, eid);
        remit::commit<SUI>(&reg, &mut esc, ts::ctx(&mut s));
        ts::return_shared(esc);
        ts::return_shared(reg);
    };
    // even after timeout, a committed escrow cannot be reclaimed
    ts::next_tx(&mut s, RANDO);
    let mut esc = ts::take_shared_by_id<RemitEscrow<SUI>>(&s, eid);
    let mut c = clock::create_for_testing(ts::ctx(&mut s));
    clock::set_for_testing(&mut c, TIMEOUT + 1);
    remit::reclaim<SUI>(&mut esc, &c, ts::ctx(&mut s));
    clock::destroy_for_testing(c);
    ts::return_shared(esc);
    ts::end(s);
}

#[test, expected_failure(abort_code = remit::ENotCommitted)]
fun release_without_commit_aborts() {
    let mut s = ts::begin(PUBLISHER);
    setup(&mut s);
    let eid = open_escrow(&mut s);
    ts::next_tx(&mut s, WORKER);
    let reg = ts::take_shared<RemitRegistry>(&s);
    let mut esc = ts::take_shared_by_id<RemitEscrow<SUI>>(&s, eid);
    remit::release<SUI>(&reg, &mut esc, ts::ctx(&mut s)); // no commit → abort
    ts::return_shared(esc);
    ts::return_shared(reg);
    ts::end(s);
}

#[test, expected_failure(abort_code = remit::ENotWorker)]
fun commit_by_non_worker_aborts() {
    let mut s = ts::begin(PUBLISHER);
    setup(&mut s);
    let eid = open_escrow(&mut s);
    ts::next_tx(&mut s, RANDO);
    let reg = ts::take_shared<RemitRegistry>(&s);
    let mut esc = ts::take_shared_by_id<RemitEscrow<SUI>>(&s, eid);
    remit::commit<SUI>(&reg, &mut esc, ts::ctx(&mut s));
    ts::return_shared(esc);
    ts::return_shared(reg);
    ts::end(s);
}

#[test, expected_failure(abort_code = compliance::EDenied)]
fun open_by_denied_sender_aborts() {
    let mut s = ts::begin(PUBLISHER);
    setup(&mut s);
    // deny SENDER
    ts::next_tx(&mut s, PUBLISHER);
    {
        let cap = ts::take_from_sender<ComplianceAdminCap>(&s);
        let mut comp = ts::take_shared<ComplianceRegistry>(&s);
        compliance::deny(&mut comp, &cap, SENDER);
        ts::return_shared(comp);
        ts::return_to_sender(&s, cap);
    };
    let _eid = open_escrow(&mut s); // aborts EDenied at compliance::assert_clear
    ts::end(s);
}

#[test]
fun sender_cancels_before_commit() {
    let mut s = ts::begin(PUBLISHER);
    setup(&mut s);
    let eid = open_escrow(&mut s);
    ts::next_tx(&mut s, SENDER);
    {
        let mut esc = ts::take_shared_by_id<RemitEscrow<SUI>>(&s, eid);
        let back = remit::cancel<SUI>(&mut esc, ts::ctx(&mut s));
        assert_eq!(back.value(), AMOUNT);
        assert_eq!(remit::status(&esc), remit::status_cancelled());
        coin::burn_for_testing(back);
        ts::return_shared(esc);
    };
    ts::end(s);
}

#[test, expected_failure(abort_code = remit::EFrozen)]
fun frozen_escrow_blocks_release() {
    let mut s = ts::begin(PUBLISHER);
    setup(&mut s);
    let eid = open_escrow(&mut s);
    // compliance admin freezes the escrow
    ts::next_tx(&mut s, PUBLISHER);
    {
        let cap = ts::take_from_sender<ComplianceAdminCap>(&s);
        let mut esc = ts::take_shared_by_id<RemitEscrow<SUI>>(&s, eid);
        remit::compliance_freeze<SUI>(&mut esc, &cap);
        ts::return_shared(esc);
        ts::return_to_sender(&s, cap);
    };
    // worker tries commit+release → release aborts EFrozen (commit also would)
    ts::next_tx(&mut s, WORKER);
    let reg = ts::take_shared<RemitRegistry>(&s);
    let mut esc = ts::take_shared_by_id<RemitEscrow<SUI>>(&s, eid);
    remit::release<SUI>(&reg, &mut esc, ts::ctx(&mut s));
    ts::return_shared(esc);
    ts::return_shared(reg);
    ts::end(s);
}
