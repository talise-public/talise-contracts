#[test_only]
module talise::send_tests;

use std::string;
use sui::{clock, coin, sui::SUI, test_scenario as ts};
use talise::send;

const SENDER: address = @0xA11CE;
const RECIPIENT: address = @0xB0B;

#[test]
fun send_transfers_and_mints_receipt() {
    let mut scenario = ts::begin(SENDER);
    {
        let ctx = scenario.ctx();
        let c = clock::create_for_testing(ctx);
        let coin = coin::mint_for_testing<SUI>(1_000_000_000, ctx);
        send::send<SUI>(
            coin,
            string::utf8(b"SUI"),
            string::utf8(b"for groceries"),
            RECIPIENT,
            &c,
            ctx,
        );
        clock::destroy_for_testing(c);
    };
    ts::end(scenario);
}

#[test, expected_failure(abort_code = ::talise::send::EZeroAmount)]
fun send_rejects_zero_amount() {
    let mut scenario = ts::begin(SENDER);
    {
        let ctx = scenario.ctx();
        let c = clock::create_for_testing(ctx);
        let coin = coin::mint_for_testing<SUI>(0, ctx);
        send::send<SUI>(
            coin,
            string::utf8(b"SUI"),
            string::utf8(b""),
            RECIPIENT,
            &c,
            ctx,
        );
        clock::destroy_for_testing(c);
    };
    ts::end(scenario);
}

#[test, expected_failure(abort_code = ::talise::send::EMemoTooLong)]
fun send_rejects_long_memo() {
    let mut scenario = ts::begin(SENDER);
    {
        let ctx = scenario.ctx();
        let c = clock::create_for_testing(ctx);
        let coin = coin::mint_for_testing<SUI>(1_000, ctx);
        let m = b"012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        send::send<SUI>(
            coin,
            string::utf8(b"SUI"),
            string::utf8(m),
            RECIPIENT,
            &c,
            ctx,
        );
        clock::destroy_for_testing(c);
    };
    ts::end(scenario);
}
