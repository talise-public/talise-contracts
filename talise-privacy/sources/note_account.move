/// Talise privacy — sponsored shielded-receive account (Workstream A, mirrors
/// `vortex_account`). A `NoteAccount` lets a recipient receive `Coin<CoinType>`
/// to a stable object address and bind a `hashed_secret` into the proof's
/// public inputs (the `transact_with_account` path), so a sponsor/relayer can
/// fund the deposit leg without learning the recipient's spending key.
module talise_privacy::note_account;

use sui::{coin::{Self, Coin}, transfer::Receiving};

/// Local mirror of `errors::EValueExceedsFieldModulus` (809) — a zero/oversized
/// secret is rejected. See `errors.move` for the canonical registry. Declared
/// locally so `assert!` references a same-module named constant (W04005).
const EValueExceedsFieldModulus: u64 = 809;

// === Structs ===

public struct NoteAccount has key {
    id: UID,
    /// Poseidon1(viewing/spending key) — the account-secret binding that the
    /// circuit checks. Never zero.
    hashed_secret: u256,
}

// === Public Mutative Functions ===

public fun new(hashed_secret: u256, ctx: &mut TxContext): NoteAccount {
    assert!(hashed_secret != 0, EValueExceedsFieldModulus);
    NoteAccount { id: object::new(ctx), hashed_secret }
}

public fun share(account: NoteAccount) {
    transfer::share_object(account);
}

/// Merge coins received at this account's address back into a single coin owned
/// by the account address (housekeeping before a spend).
public fun merge_coins<CoinType>(
    account: &mut NoteAccount,
    coins: vector<Receiving<Coin<CoinType>>>,
    ctx: &mut TxContext,
) {
    transfer::public_transfer(account.merge(coins, ctx), account.id.to_address());
}

// === Package Functions ===

public(package) fun hashed_secret(account: &NoteAccount): u256 {
    account.hashed_secret
}

/// Sweep coins received at this account into one coin returned to the caller's
/// PTB (used by `shielded_pool::transact_with_account` as the deposit leg).
public(package) fun receive<CoinType>(
    account: &mut NoteAccount,
    coins: vector<Receiving<Coin<CoinType>>>,
    ctx: &mut TxContext,
): Coin<CoinType> {
    account.merge(coins, ctx)
}

// === Private Functions ===

fun merge<CoinType>(
    account: &mut NoteAccount,
    coins: vector<Receiving<Coin<CoinType>>>,
    ctx: &mut TxContext,
): Coin<CoinType> {
    coins.fold!(coin::zero<CoinType>(ctx), |mut acc, c| {
        acc.join(transfer::public_receive(&mut account.id, c));
        acc
    })
}
