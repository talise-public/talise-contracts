/// Tests for the on-chain compliance gate.
///   • a clear address passes `assert_clear`
///   • a denied address aborts EDenied; deny-twice aborts EAlreadyDenied
///   • a global pause fails closed (EPaused) for everyone
///   • allowlist-required blocks an unlisted address (ENotAllowed) but passes
///     an explicitly-allowed one
#[test_only]
module talise::compliance_tests;

use sui::test_scenario as ts;
use talise::compliance::{Self, ComplianceRegistry, ComplianceAdminCap};

const PUBLISHER: address = @0xA;
const ALICE: address = @0xB;
const BAD: address = @0xBAD;

fun setup(s: &mut ts::Scenario) {
    ts::next_tx(s, PUBLISHER);
    compliance::test_init(ts::ctx(s));
}

#[test]
fun clear_address_passes() {
    let mut s = ts::begin(PUBLISHER);
    setup(&mut s);
    ts::next_tx(&mut s, PUBLISHER);
    let reg = ts::take_shared<ComplianceRegistry>(&s);
    compliance::assert_clear(&reg, ALICE); // no abort
    ts::return_shared(reg);
    ts::end(s);
}

#[test, expected_failure(abort_code = compliance::EDenied)]
fun denied_address_aborts() {
    let mut s = ts::begin(PUBLISHER);
    setup(&mut s);
    ts::next_tx(&mut s, PUBLISHER);
    {
        let cap = ts::take_from_sender<ComplianceAdminCap>(&s);
        let mut reg = ts::take_shared<ComplianceRegistry>(&s);
        compliance::deny(&mut reg, &cap, BAD);
        assert!(compliance::is_denied(&reg, BAD));
        compliance::assert_clear(&reg, BAD); // aborts EDenied
        ts::return_shared(reg);
        ts::return_to_sender(&s, cap);
    };
    ts::end(s);
}

#[test, expected_failure(abort_code = compliance::EAlreadyDenied)]
fun deny_twice_aborts() {
    let mut s = ts::begin(PUBLISHER);
    setup(&mut s);
    ts::next_tx(&mut s, PUBLISHER);
    let cap = ts::take_from_sender<ComplianceAdminCap>(&s);
    let mut reg = ts::take_shared<ComplianceRegistry>(&s);
    compliance::deny(&mut reg, &cap, BAD);
    compliance::deny(&mut reg, &cap, BAD);
    ts::return_shared(reg);
    ts::return_to_sender(&s, cap);
    ts::end(s);
}

#[test, expected_failure(abort_code = compliance::EPaused)]
fun pause_fails_closed() {
    let mut s = ts::begin(PUBLISHER);
    setup(&mut s);
    ts::next_tx(&mut s, PUBLISHER);
    {
        let cap = ts::take_from_sender<ComplianceAdminCap>(&s);
        let mut reg = ts::take_shared<ComplianceRegistry>(&s);
        compliance::set_paused(&mut reg, &cap, true);
        compliance::assert_clear(&reg, ALICE); // even a clear addr aborts EPaused
        ts::return_shared(reg);
        ts::return_to_sender(&s, cap);
    };
    ts::end(s);
}

#[test, expected_failure(abort_code = compliance::ENotAllowed)]
fun allowlist_blocks_unlisted() {
    let mut s = ts::begin(PUBLISHER);
    setup(&mut s);
    ts::next_tx(&mut s, PUBLISHER);
    {
        let cap = ts::take_from_sender<ComplianceAdminCap>(&s);
        let mut reg = ts::take_shared<ComplianceRegistry>(&s);
        compliance::set_allowlist_required(&mut reg, &cap, true);
        compliance::assert_clear(&reg, ALICE); // not allowed → aborts
        ts::return_shared(reg);
        ts::return_to_sender(&s, cap);
    };
    ts::end(s);
}

#[test]
fun allowlisted_address_passes() {
    let mut s = ts::begin(PUBLISHER);
    setup(&mut s);
    ts::next_tx(&mut s, PUBLISHER);
    {
        let cap = ts::take_from_sender<ComplianceAdminCap>(&s);
        let mut reg = ts::take_shared<ComplianceRegistry>(&s);
        compliance::set_allowlist_required(&mut reg, &cap, true);
        compliance::allow(&mut reg, &cap, ALICE);
        compliance::assert_clear(&reg, ALICE); // allowed → ok
        ts::return_shared(reg);
        ts::return_to_sender(&s, cap);
    };
    ts::end(s);
}
