/// Tests for atomic batch payroll.
///   • happy path: pay_many splits one coin to N recipients exactly
///   • sum != funds aborts ESumMismatch (no dust / no over-draw)
///   • recipients/amounts length mismatch aborts ELenMismatch
///   • a denied recipient aborts the WHOLE batch (atomic; no one paid)
#[test_only]
module talise::batch_pay_tests;

use std::unit_test::assert_eq;
use sui::{coin, sui::SUI, test_scenario as ts};
use talise::{compliance::{Self, ComplianceRegistry, ComplianceAdminCap}, batch_pay};

const PUBLISHER: address = @0xA;
const PAYER: address = @0xB;
const ALICE: address = @0xC;
const BOB: address = @0xD;

fun setup(s: &mut ts::Scenario) {
    ts::next_tx(s, PUBLISHER);
    compliance::test_init(ts::ctx(s));
}

#[test]
fun pay_many_splits_exactly() {
    let mut s = ts::begin(PUBLISHER);
    setup(&mut s);
    ts::next_tx(&mut s, PAYER);
    {
        let comp = ts::take_shared<ComplianceRegistry>(&s);
        let funds = coin::mint_for_testing<SUI>(5_000_000, ts::ctx(&mut s));
        batch_pay::pay_many<SUI>(
            funds,
            &comp,
            vector[ALICE, BOB],
            vector[3_000_000, 2_000_000],
            b"batch-1",
            ts::ctx(&mut s),
        );
        ts::return_shared(comp);
    };
    ts::next_tx(&mut s, ALICE);
    {
        let a = ts::take_from_sender<coin::Coin<SUI>>(&s);
        assert_eq!(a.value(), 3_000_000);
        coin::burn_for_testing(a);
    };
    ts::next_tx(&mut s, BOB);
    {
        let b = ts::take_from_sender<coin::Coin<SUI>>(&s);
        assert_eq!(b.value(), 2_000_000);
        coin::burn_for_testing(b);
    };
    ts::end(s);
}

#[test, expected_failure(abort_code = batch_pay::ESumMismatch)]
fun sum_mismatch_aborts() {
    let mut s = ts::begin(PUBLISHER);
    setup(&mut s);
    ts::next_tx(&mut s, PAYER);
    let comp = ts::take_shared<ComplianceRegistry>(&s);
    let funds = coin::mint_for_testing<SUI>(5_000_000, ts::ctx(&mut s));
    // 3M + 1M = 4M != 5M funded → abort
    batch_pay::pay_many<SUI>(funds, &comp, vector[ALICE, BOB], vector[3_000_000, 1_000_000], b"b", ts::ctx(&mut s));
    ts::return_shared(comp);
    ts::end(s);
}

#[test, expected_failure(abort_code = batch_pay::ELenMismatch)]
fun length_mismatch_aborts() {
    let mut s = ts::begin(PUBLISHER);
    setup(&mut s);
    ts::next_tx(&mut s, PAYER);
    let comp = ts::take_shared<ComplianceRegistry>(&s);
    let funds = coin::mint_for_testing<SUI>(5_000_000, ts::ctx(&mut s));
    batch_pay::pay_many<SUI>(funds, &comp, vector[ALICE, BOB], vector[5_000_000], b"b", ts::ctx(&mut s));
    ts::return_shared(comp);
    ts::end(s);
}

#[test, expected_failure(abort_code = compliance::EDenied)]
fun denied_recipient_aborts_whole_batch() {
    let mut s = ts::begin(PUBLISHER);
    setup(&mut s);
    // deny BOB
    ts::next_tx(&mut s, PUBLISHER);
    {
        let cap = ts::take_from_sender<ComplianceAdminCap>(&s);
        let mut comp = ts::take_shared<ComplianceRegistry>(&s);
        compliance::deny(&mut comp, &cap, BOB);
        ts::return_shared(comp);
        ts::return_to_sender(&s, cap);
    };
    ts::next_tx(&mut s, PAYER);
    let comp = ts::take_shared<ComplianceRegistry>(&s);
    let funds = coin::mint_for_testing<SUI>(5_000_000, ts::ctx(&mut s));
    batch_pay::pay_many<SUI>(funds, &comp, vector[ALICE, BOB], vector[3_000_000, 2_000_000], b"b", ts::ctx(&mut s));
    ts::return_shared(comp);
    ts::end(s);
}
