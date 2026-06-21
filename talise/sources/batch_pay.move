/// Atomic batch / payroll disbursement.
///
/// One PTB pays N recipients from a single funded `Coin<T>`, all-or-nothing:
/// either every leg settles or the whole transaction aborts. A server loop can
/// crash at recipient 73 and leave a half-paid, unreconcilable run; on-chain it
/// can't. Emits ONE `BatchPaid` event (with the off-chain `batch_id`) as the
/// tamper-proof reconciliation anchor. Every recipient is screened through
/// `talise::compliance` in the same atomic tx.
///
/// Stateless library entry — no shared object, low gas. The PTB caps how many
/// recipients fit per tx (Sui per-tx object limit); chunk large payrolls
/// off-chain into deterministic `batch_id`+sequence runs. Generic over `T`.
module talise::batch_pay;

use sui::{balance::{Self}, coin::{Self, Coin}, event};
use talise::compliance::{Self, ComplianceRegistry};

const EEmpty: u64 = 760;
const ELenMismatch: u64 = 761;
const ESumMismatch: u64 = 762;

public struct BatchDisbursed has copy, drop {
    batch_id: vector<u8>,
    count: u64,
    total: u64,
    payer: address,
}

/// Pay `amounts[i]` to `recipients[i]` from `funds`, atomically. Asserts the
/// vectors are equal, non-empty, and that `sum(amounts) == funds.value` (no
/// dust stranded, no over-draw). Screens each recipient; if ANY is denied the
/// whole batch aborts and no one is paid. u64 add is overflow-checked by the
/// Move VM (a malicious `amounts` that overflows aborts).
public fun pay_many<T>(
    funds: Coin<T>,
    compliance_reg: &ComplianceRegistry,
    recipients: vector<address>,
    amounts: vector<u64>,
    batch_id: vector<u8>,
    ctx: &mut TxContext,
) {
    let n = recipients.length();
    assert!(n > 0, EEmpty);
    assert!(n == amounts.length(), ELenMismatch);

    let total = funds.value();
    let mut sum = 0u64;
    amounts.do_ref!(|amt| sum = sum + *amt); // VM aborts on overflow
    assert!(sum == total, ESumMismatch);

    let mut bal = funds.into_balance();
    n.do!(|i| {
        let addr = recipients[i];
        let amt = amounts[i];
        compliance::assert_clear(compliance_reg, addr);
        let part = balance::split(&mut bal, amt);
        transfer::public_transfer(coin::from_balance(part, ctx), addr);
    });
    // Exact by the sum==total assert above: nothing is stranded.
    balance::destroy_zero(bal);

    event::emit(BatchDisbursed { batch_id, count: n, total, payer: ctx.sender() });
}
