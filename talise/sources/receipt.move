/// On-chain payment receipts. Every Talise send mints one of these so the
/// transfer leaves a permanent, share-able artifact: a Display-registered NFT
/// that resolves to talise.io/r/<id>.
module talise::receipt;

use std::string::{Self, String};
use sui::{display, event, package};

/// One-time witness for module init.
public struct RECEIPT has drop {}

/// A payment receipt. Issued to the sender as a keepsake of an outbound transfer.
public struct PaymentReceipt has key, store {
    id: UID,
    from: address,
    to: address,
    /// Amount in the asset's smallest unit (e.g. MIST for SUI, 6dp for USDC).
    amount: u64,
    /// Symbol of the asset that landed in the recipient's wallet (e.g. "SUI").
    asset: String,
    /// Optional memo. Capped at 80 chars by the entry function.
    memo: String,
    /// Millisecond timestamp from Clock at send time.
    ts_ms: u64,
}

/// Emitted on every mint; lets indexers stream receipts cheaply.
public struct ReceiptMinted has copy, drop {
    id: ID,
    from: address,
    to: address,
    amount: u64,
    asset: String,
    ts_ms: u64,
}

fun init(otw: RECEIPT, ctx: &mut TxContext) {
    let publisher = package::claim(otw, ctx);

    let mut d = display::new<PaymentReceipt>(&publisher, ctx);
    d.add(
        string::utf8(b"name"),
        string::utf8(b"Talise receipt"),
    );
    d.add(
        string::utf8(b"description"),
        string::utf8(b"On-chain proof of a Talise payment."),
    );
    d.add(
        string::utf8(b"link"),
        string::utf8(b"https://talise.io/r/{id}"),
    );
    d.add(
        string::utf8(b"image_url"),
        string::utf8(b"https://talise.io/r/{id}/og.png"),
    );
    d.add(
        string::utf8(b"project_url"),
        string::utf8(b"https://talise.io"),
    );
    d.update_version();

    transfer::public_transfer(publisher, ctx.sender());
    transfer::public_transfer(d, ctx.sender());
}

/// Mint a receipt and hand it to the sender. Called by talise::send entries
/// inside the same atomic PTB so receipt + transfer are inseparable.
public(package) fun mint(
    from: address,
    to: address,
    amount: u64,
    asset: String,
    memo: String,
    ts_ms: u64,
    ctx: &mut TxContext,
): PaymentReceipt {
    let r = PaymentReceipt {
        id: object::new(ctx),
        from,
        to,
        amount,
        asset,
        memo,
        ts_ms,
    };
    event::emit(ReceiptMinted {
        id: object::id(&r),
        from,
        to,
        amount,
        asset,
        ts_ms,
    });
    r
}

// --- read-only accessors (for tests / external Move callers) ---

public fun from(r: &PaymentReceipt): address { r.from }
public fun to(r: &PaymentReceipt): address { r.to }
public fun amount(r: &PaymentReceipt): u64 { r.amount }
public fun asset(r: &PaymentReceipt): &String { &r.asset }
public fun memo(r: &PaymentReceipt): &String { &r.memo }
public fun ts_ms(r: &PaymentReceipt): u64 { r.ts_ms }

// --- test-only ---

#[test_only]
public fun test_init(ctx: &mut TxContext) {
    init(RECEIPT {}, ctx)
}

#[test_only]
public fun test_mint(
    asset: String,
    memo: String,
    from: address,
    to: address,
    amount: u64,
    ts_ms: u64,
    ctx: &mut TxContext,
): PaymentReceipt {
    mint(from, to, amount, asset, memo, ts_ms, ctx)
}

#[test_only]
public fun destroy_for_testing(r: PaymentReceipt) {
    let PaymentReceipt { id, .. } = r;
    id.delete();
}
