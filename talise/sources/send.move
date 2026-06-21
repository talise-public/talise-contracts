/// Atomic Talise sends. The entry takes a Coin<T>, a recipient, and a memo;
/// it transfers the coin and mints a PaymentReceipt in the same call so the
/// outbound payment is inseparable from its on-chain proof.
module talise::send;

use std::string::String;
use sui::{clock::Clock, coin::{Self, Coin}};
use talise::receipt;

const EZeroAmount: u64 = 1;
const EMemoTooLong: u64 = 2;

const MAX_MEMO_BYTES: u64 = 80;

/// Send a coin of any type. The PTB constructs `coin` (via splitCoin from gas,
/// or by withdrawing from a yield position) and hands it to this function.
/// `asset` is the human-readable symbol stamped into the receipt ("SUI", "USDC").
public fun send<T>(
    coin: Coin<T>,
    asset: String,
    memo: String,
    recipient: address,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let amount = coin.value();
    assert!(amount > 0, EZeroAmount);
    assert!(memo.length() <= MAX_MEMO_BYTES, EMemoTooLong);

    let from = ctx.sender();
    let ts_ms = clock.timestamp_ms();

    let r = receipt::mint(from, recipient, amount, asset, memo, ts_ms, ctx);
    transfer::public_transfer(r, from);
    transfer::public_transfer(coin, recipient);
}
