/// Per-goal savings vault — owner-owned, withdraw-anytime, yield-ready.
///
/// A `GoalVault<T>` is an OWNED object (transferred to its creator), so it is
/// only usable in a transaction signed by the owner. That gives the core
/// product guarantee for free: a goal is a vault ONLY the creator controls.
/// Funds are held as a segregated `Balance<T>` (one vault per goal), the owner
/// can `deposit` and `withdraw` ANY time, and `close` drains + deletes it.
///
/// Custody invariants:
///   • The object is owner-owned — no shared access, no worker access. Only a
///     tx the owner signs can touch it.
///   • `withdraw` / `close` additionally assert `sender == owner` (defence in
///     depth, in case the object is ever wrapped/shared by mistake).
///   • Funds in are `Balance<T>` joined into `principal`; funds out are split
///     from `principal`. The object never custodies more than it was given.
///
/// Yield seam (next sub-phase): the vault holds raw `principal: Balance<T>`
/// today. To earn yield, principal is supplied to NAVI and the lending receipt
/// is parked on this object via a dynamic object field (the same pattern as
/// `talise_yield::yield_router::YieldPosition`), keyed by venue. `withdraw`
/// then redeems from the venue first. That integration is intentionally NOT in
/// this module so the custody core stays small and auditable; see
/// docs/goals-vault.md for the staged plan.
module talise_goals::goal_vault;

use sui::{balance::{Self, Balance}, clock::Clock, coin::{Self, Coin}, event, dynamic_object_field as dof};
use std::{string::{Self, String}, type_name, ascii};

// ───────────────────────────────────────────────────────────────────
// Errors

const ENotOwner: u64 = 300;
const EInsufficientBalance: u64 = 301;
const EZeroAmount: u64 = 302;
const ENameTooLong: u64 = 303;
const EVenueNotAllowed: u64 = 304;
const EReceiptParked: u64 = 305;
const ENoReceipt: u64 = 306;

const MAX_NAME_LEN: u64 = 64;

/// Dynamic-object-field key under which the (single) venue yield receipt is
/// parked on a vault. One yield position per goal keeps custody trivial.
const RECEIPT_KEY: u8 = 0;

// ───────────────────────────────────────────────────────────────────
// Object

/// One vault per savings goal. Owned by `owner` (the creator). `store` so it
/// can be held in collections / future wrappers; it is never shared.
public struct GoalVault<phantom T> has key, store {
    id: UID,
    /// The only address that may withdraw or close. Set at creation, immutable.
    owner: address,
    /// Display name ("Singapore Trip"). Capped at MAX_NAME_LEN bytes.
    name: String,
    /// Target amount in T's smallest unit (e.g. USDsui micro-units). 0 = none.
    target: u64,
    /// The segregated IDLE funds this goal holds (not currently supplied to a
    /// yield venue). Supplied funds live as a venue receipt parked under
    /// RECEIPT_KEY (dynamic object field), with `basis` tracking their size.
    principal: Balance<T>,
    /// Venue the parked receipt belongs to (0 = none, 1 = NAVI). The receipt
    /// object itself is held as a dynamic object field, not inline, because
    /// its type varies by venue.
    venue: u8,
    /// Principal (in T's smallest unit) currently supplied to `venue`. The
    /// goal's total value is `balance(principal) + basis` (+ accrued yield,
    /// realised on redeem).
    basis: u64,
    /// `type_name` of the parked receipt `R` (empty when none). Recorded so an
    /// off-chain redeem PTB can ALWAYS reconstruct the exact `R` for
    /// `take_receipt`, even if the venue's receipt type drifts across an
    /// upgrade after a receipt is parked — closes the "unknowable R" strand.
    receipt_type: ascii::String,
    created_at_ms: u64,
    /// Monotonic lifetime totals for telemetry / the activity feed.
    deposits_total: u64,
    withdrawals_total: u64,
}

// ───────────────────────────────────────────────────────────────────
// Events

public struct GoalCreated has copy, drop { vault_id: ID, owner: address, target: u64 }
public struct GoalDeposited has copy, drop { vault_id: ID, owner: address, amount: u64, balance: u64 }
public struct GoalWithdrawn has copy, drop { vault_id: ID, owner: address, amount: u64, balance: u64 }
public struct GoalClosed has copy, drop { vault_id: ID, owner: address, returned: u64 }
public struct GoalUpdated has copy, drop { vault_id: ID, owner: address, target: u64 }
public struct GoalSupplied has copy, drop { vault_id: ID, owner: address, venue: u8, basis: u64 }
public struct GoalRedeemed has copy, drop { vault_id: ID, owner: address, venue: u8, basis: u64 }
public struct GoalRenamed has copy, drop { vault_id: ID, owner: address }

// ───────────────────────────────────────────────────────────────────
// Lifecycle

/// Create an empty goal vault and hand it to the creator. Owner-owned from
/// birth — only the creator can ever touch it.
public fun create<T>(name: vector<u8>, target: u64, clock: &Clock, ctx: &mut TxContext) {
    transfer::public_transfer(new_vault<T>(name, target, balance::zero<T>(), clock, ctx), ctx.sender());
}

/// Create a goal vault AND fund it from `coin` in one transaction.
public fun create_with<T>(
    name: vector<u8>,
    target: u64,
    coin: Coin<T>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    transfer::public_transfer(
        new_vault<T>(name, target, coin.into_balance(), clock, ctx),
        ctx.sender(),
    );
}

fun new_vault<T>(
    name: vector<u8>,
    target: u64,
    principal: Balance<T>,
    clock: &Clock,
    ctx: &mut TxContext,
): GoalVault<T> {
    assert!(name.length() <= MAX_NAME_LEN, ENameTooLong);
    let initial = balance::value(&principal);
    let vault = GoalVault<T> {
        id: object::new(ctx),
        owner: ctx.sender(),
        name: string::utf8(name),
        target,
        principal,
        venue: 0,
        basis: 0,
        receipt_type: ascii::string(b""),
        created_at_ms: clock.timestamp_ms(),
        deposits_total: initial,
        withdrawals_total: 0,
    };
    event::emit(GoalCreated { vault_id: object::id(&vault), owner: vault.owner, target });
    vault
}

// ───────────────────────────────────────────────────────────────────
// Money in / out

/// Add funds to the goal. Implicitly owner-only (owned object), so anyone
/// holding the vault in a tx is the owner.
public fun deposit<T>(vault: &mut GoalVault<T>, coin: Coin<T>) {
    let amount = coin::value(&coin);
    assert!(amount > 0, EZeroAmount);
    balance::join(&mut vault.principal, coin.into_balance());
    vault.deposits_total = vault.deposits_total + amount;
    event::emit(GoalDeposited {
        vault_id: object::id(vault),
        owner: vault.owner,
        amount,
        balance: balance::value(&vault.principal),
    });
}

/// Withdraw `amount` from the goal back to the owner — ANY time, no lockup.
/// Returns the Coin so the caller's PTB can transfer/spend it.
public fun withdraw<T>(vault: &mut GoalVault<T>, amount: u64, ctx: &mut TxContext): Coin<T> {
    assert!(ctx.sender() == vault.owner, ENotOwner);
    assert!(amount > 0, EZeroAmount);
    assert!(balance::value(&vault.principal) >= amount, EInsufficientBalance);
    vault.withdrawals_total = vault.withdrawals_total + amount;
    let out = balance::split(&mut vault.principal, amount);
    event::emit(GoalWithdrawn {
        vault_id: object::id(vault),
        owner: vault.owner,
        amount,
        balance: balance::value(&vault.principal),
    });
    coin::from_balance(out, ctx)
}

/// Withdraw everything and DELETE the vault (use when a goal is finished or
/// abandoned). Returns the full remaining balance as a Coin.
public fun close<T>(vault: GoalVault<T>, ctx: &mut TxContext): Coin<T> {
    assert!(ctx.sender() == vault.owner, ENotOwner);
    // A parked venue receipt is a dynamic object field on `id`; the UID can't
    // be deleted while it holds one. Gate on the dof's ACTUAL presence (not the
    // `venue` flag) so close can never be permanently bricked by a venue field
    // left set in error, and force the owner to redeem the receipt first so
    // venue funds are never orphaned.
    assert!(!dof::exists(&vault.id, RECEIPT_KEY), EReceiptParked);
    let GoalVault {
        id,
        owner,
        name: _,
        target: _,
        principal,
        venue: _,
        basis: _,
        receipt_type: _,
        created_at_ms: _,
        deposits_total: _,
        withdrawals_total: _,
    } = vault;
    let returned = balance::value(&principal);
    event::emit(GoalClosed { vault_id: id.to_inner(), owner, returned });
    id.delete();
    coin::from_balance(principal, ctx)
}

// ───────────────────────────────────────────────────────────────────
// Yield — park a venue lending receipt on the vault (owner-gated).
//
// We do NOT call the venue (NAVI) from Move — it has no Move package here and
// is driven by its SDK at the PTB level. Instead the owner runs a single
// signed PTB that (a) `withdraw`s idle principal from this vault, (b) supplies
// it to the venue via the SDK, obtaining a receipt `R`, then (c) `park_receipt`
// stores that receipt on the vault. Exiting is the mirror: `take_receipt` →
// SDK redeem → `deposit` the coin back. `R: key + store` is the venue receipt
// type (e.g. NAVI account/obligation). One receipt per goal (RECEIPT_KEY).

public fun park_receipt<T, R: key + store>(
    vault: &mut GoalVault<T>,
    receipt: R,
    venue: u8,
    basis: u64,
    ctx: &TxContext,
) {
    assert!(ctx.sender() == vault.owner, ENotOwner);
    assert!(venue != 0, EVenueNotAllowed);
    assert!(vault.venue == 0 && !dof::exists(&vault.id, RECEIPT_KEY), EReceiptParked);
    dof::add(&mut vault.id, RECEIPT_KEY, receipt);
    vault.venue = venue;
    vault.basis = basis;
    // Record R's type so the redeem PTB can always reconstruct it (recovery).
    vault.receipt_type = type_name::with_defining_ids<R>().into_string();
    event::emit(GoalSupplied { vault_id: object::id(vault), owner: vault.owner, venue, basis });
}

/// Pull the parked receipt back out (to run a venue-redeem PTB). Clears the
/// venue/basis tracking; the owner re-`deposit`s the redeemed coin.
public fun take_receipt<T, R: key + store>(vault: &mut GoalVault<T>, ctx: &TxContext): R {
    assert!(ctx.sender() == vault.owner, ENotOwner);
    assert!(dof::exists_with_type<u8, R>(&vault.id, RECEIPT_KEY), ENoReceipt);
    let receipt: R = dof::remove(&mut vault.id, RECEIPT_KEY);
    let venue = vault.venue;
    let basis = vault.basis;
    vault.venue = 0;
    vault.basis = 0;
    vault.receipt_type = ascii::string(b"");
    event::emit(GoalRedeemed { vault_id: object::id(vault), owner: vault.owner, venue, basis });
    receipt
}

// ───────────────────────────────────────────────────────────────────
// Metadata mutators (owner-gated)

public fun set_target<T>(vault: &mut GoalVault<T>, target: u64, ctx: &TxContext) {
    assert!(ctx.sender() == vault.owner, ENotOwner);
    vault.target = target;
    event::emit(GoalUpdated { vault_id: object::id(vault), owner: vault.owner, target });
}

public fun rename<T>(vault: &mut GoalVault<T>, name: vector<u8>, ctx: &TxContext) {
    assert!(ctx.sender() == vault.owner, ENotOwner);
    assert!(name.length() <= MAX_NAME_LEN, ENameTooLong);
    vault.name = string::utf8(name);
    event::emit(GoalRenamed { vault_id: object::id(vault), owner: vault.owner });
}

// ───────────────────────────────────────────────────────────────────
// Views

public fun balance<T>(vault: &GoalVault<T>): u64 { balance::value(&vault.principal) }
public fun target<T>(vault: &GoalVault<T>): u64 { vault.target }
public fun owner<T>(vault: &GoalVault<T>): address { vault.owner }
public fun name<T>(vault: &GoalVault<T>): String { vault.name }
public fun deposits_total<T>(vault: &GoalVault<T>): u64 { vault.deposits_total }
public fun withdrawals_total<T>(vault: &GoalVault<T>): u64 { vault.withdrawals_total }

/// Venue the parked receipt belongs to (0 = none / idle-only).
public fun venue<T>(vault: &GoalVault<T>): u8 { vault.venue }
/// Principal currently supplied to the venue (the parked receipt's basis).
public fun basis<T>(vault: &GoalVault<T>): u64 { vault.basis }
/// Whether the vault currently holds a parked venue receipt.
public fun has_receipt<T>(vault: &GoalVault<T>): bool { vault.venue != 0 }

/// Has the goal reached its target? (A 0 target is never "complete".)
public fun is_complete<T>(vault: &GoalVault<T>): bool {
    vault.target > 0 && total_value(vault) >= vault.target
}

/// Progress toward target in basis points (0..=10000), capped. 0 target → 0.
public fun progress_bps<T>(vault: &GoalVault<T>): u64 {
    if (vault.target == 0) return 0;
    let bal = total_value(vault);
    if (bal >= vault.target) return 10000;
    // bal <= u64::MAX, so the u128 multiply (~1.8e23 max) cannot overflow.
    ((bal as u128) * 10000 / (vault.target as u128)) as u64
}

/// A goal's full value toward its target: idle principal PLUS principal
/// currently supplied to a venue (`basis`). Without `basis` a goal would
/// regress to 0% the moment it started earning yield. (Accrued yield is
/// realised into `principal` on redeem, so it isn't double-counted here.)
public fun total_value<T>(vault: &GoalVault<T>): u64 {
    balance::value(&vault.principal) + vault.basis
}

/// `type_name` of the parked receipt (empty when none) — lets a redeem PTB
/// reconstruct the exact `R` for take_receipt.
public fun receipt_type<T>(vault: &GoalVault<T>): ascii::String { vault.receipt_type }
