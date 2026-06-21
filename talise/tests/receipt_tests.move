/// Coverage tests for `talise::receipt`.
///
/// `init` is invoked via the `test_init` shim so the Display + Publisher
/// setup is exercised. `mint` is exercised via `test_mint` (the public
/// `mint` is `public(package)` and is already used by `talise::send`,
/// but we want explicit assertions on its outputs here).
#[test_only]
module talise::receipt_tests;

use std::{string, unit_test::assert_eq};
use sui::test_scenario as ts;
use talise::receipt::{Self, PaymentReceipt};

const PUBLISHER: address = @0xA;
const FROM: address = @0xB;
const TO: address = @0xC;

#[test]
fun init_creates_display_and_publisher() {
    // Run the module init; afterwards Publisher and Display<PaymentReceipt>
    // should both belong to the publisher.
    let mut scenario = ts::begin(PUBLISHER);
    receipt::test_init(ts::ctx(&mut scenario));

    ts::next_tx(&mut scenario, PUBLISHER);
    assert!(ts::has_most_recent_for_address<sui::package::Publisher>(PUBLISHER));
    assert!(ts::has_most_recent_for_address<sui::display::Display<PaymentReceipt>>(PUBLISHER));
    ts::end(scenario);
}

#[test]
fun mint_populates_all_fields_and_accessors() {
    let mut scenario = ts::begin(PUBLISHER);
    {
        let r = receipt::test_mint(
            string::utf8(b"USDC"),
            string::utf8(b"hello"),
            FROM,
            TO,
            12_345,
            1_700_000_000_000,
            ts::ctx(&mut scenario),
        );
        assert_eq!(receipt::from(&r), FROM);
        assert_eq!(receipt::to(&r), TO);
        assert_eq!(receipt::amount(&r), 12_345);
        assert_eq!(*string::as_bytes(receipt::asset(&r)), b"USDC");
        assert_eq!(*string::as_bytes(receipt::memo(&r)), b"hello");
        assert_eq!(receipt::ts_ms(&r), 1_700_000_000_000);
        receipt::destroy_for_testing(r);
    };
    ts::end(scenario);
}
