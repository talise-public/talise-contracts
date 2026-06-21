/// Per-user TaliseVault.
///
/// A `TaliseVault` is a shared object that holds the user's balances as
/// `Balance<T>` rather than `Coin<T>` objects. It is the destination
/// that a user's `@talise` SuiNS subname resolves to, so any incoming
/// coin lands inside the vault rather than as a free-floating Coin<T>
/// in the user's plain wallet. That's the architectural pivot that
/// makes Path-C auto-swap work: balances inside a shared object can be
/// touched by a worker-signed PTB, gated by an `AutoSwapCap<T>`.
///
/// Custody invariants (after v2 audit pass):
///   • Only `vault.owner` can withdraw. Period.
///   • Only `vault.owner` can mint an `AutoSwapCap<T>` against this
///     vault (asserted in `enable_auto_swap`).
///   • `auto_swap_extract` returns a `SwapTicket` hot potato in
///     addition to the source balance. `auto_swap_deposit` is the
///     only function that consumes it — the PTB cannot type-check
///     unless the extracted balance is deposited back atomically.
///   • The ticket carries the source vault id; deposit asserts the
///     swap output lands in the same vault, so funds can't be
///     siphoned to another vault inside the same PTB.
module talise::vault;

use sui::{bag::{Self, Bag}, balance::{Self, Balance}, clock::Clock, coin::{Self, Coin}, event, transfer::{Self, Receiving}};
use std::{type_name, string::String};

use talise::auto_swap::{Self, AutoSwapRegistry, AutoSwapCap, AutoSwapRegistryV2, AutoSwapCapV2};

// ───────────────────────────────────────────────────────────────────
// Errors

const ENotOwner: u64 = 200;
const EInsufficientBalance: u64 = 201;
const EZeroAmount: u64 = 202;
const ETypeNotHeld: u64 = 203;
const EWrongVault: u64 = 204;

// ───────────────────────────────────────────────────────────────────
// Objects

/// One vault per user. Shared. The user's @talise subname target is
/// set to this object's address.
public struct TaliseVault has key {
    id: UID,
    /// The only address that can withdraw or mint auto-swap caps.
    owner: address,
    /// Map of type-name (vector<u8>) -> Balance<T>. We use a Bag because
    /// we need heterogeneous Balance<T> in one object; sui::table can't
    /// hold mixed-type values.
    balances: Bag,
    /// Monotonic counters for telemetry / activity feed.
    deposits_total: u64,
    auto_swaps_total: u64,
}

/// Hot-potato. Returned by `auto_swap_extract` and consumed by
/// `auto_swap_deposit`. No `drop`, no `store`, no `copy`, no `key` —
/// the only thing the runtime can do with this is hand it to deposit
/// before the transaction ends. Forces the worker to actually deposit
/// the swap output rather than walking away with the source balance.
public struct SwapTicket {
    /// The vault the ticket was issued against. Deposit asserts the
    /// vault it's depositing into is the same one.
    vault_id: ID,
    /// Source-type name captured at extract time, threaded through to
    /// the deposit event so the indexer can show "Auto-swapped 0.5
    /// SUI → 1.20 USDsui" without an extra RPC.
    from_type: vector<u8>,
    /// Source amount that was extracted (in source-coin decimals).
    from_amount: u64,
}

// ───────────────────────────────────────────────────────────────────
// Events

public struct VaultCreated has copy, drop {
    vault_id: ID,
    owner: address,
}

public struct VaultDeposited has copy, drop {
    vault_id: ID,
    coin_type: vector<u8>,
    amount: u64,
    from: address,
}

public struct VaultDebited has copy, drop {
    vault_id: ID,
    coin_type: vector<u8>,
    amount: u64,
    to: address,
}

public struct VaultAutoSwapped has copy, drop {
    vault_id: ID,
    from_type: vector<u8>,
    to_type: vector<u8>,
    from_amount: u64,
    to_amount: u64,
    ts_ms: u64,
}

// ───────────────────────────────────────────────────────────────────
// Vault lifecycle

/// Create a new vault for the calling user. One call per user, post-
/// onboarding. Shared so anyone can `deposit_*`, but only the owner
/// can withdraw or mint auto-swap caps.
public fun create(ctx: &mut TxContext) {
    let vault = TaliseVault {
        id: object::new(ctx),
        owner: ctx.sender(),
        balances: bag::new(ctx),
        deposits_total: 0,
        auto_swaps_total: 0,
    };
    event::emit(VaultCreated {
        vault_id: object::id(&vault),
        owner: ctx.sender(),
    });
    transfer::share_object(vault);
}

// ───────────────────────────────────────────────────────────────────
// Auto-swap enablement — vault-aware so we can assert ownership

/// Mint an `AutoSwapCap<T>` bound to this vault. The vault-owner check
/// happens here, with `&TaliseVault` in scope, which closes the audit-
/// flagged hole where a user could mint a cap targeting someone else's
/// vault id.
///
/// CAP IS SHARED, not user-owned, because the cron-driven auto-swap is
/// signed by the Onara admin keypair — Sui requires the PTB signer to
/// own every owned-object argument, so a user-owned cap means the worker
/// could never actually pass `&cap` into `vault::auto_swap_extract`.
/// Sharing the cap lets any signer reference it; the `validate_for_swap`
/// assert (`sender == registry.admin`) keeps abuse impossible, and the
/// per-op `ctx.sender() == cap.owner` checks in pause/resume/disable
/// keep the user as the only party who can revoke or pause.
public fun enable_auto_swap<T>(
    vault: &TaliseVault,
    max_per_swap: u64,
    expires_at_ms: u64,
    ctx: &mut TxContext,
) {
    assert!(ctx.sender() == vault.owner, ENotOwner);

    let cap = auto_swap::mint_cap<T>(
        object::id(vault),
        vault.owner,
        max_per_swap,
        expires_at_ms,
        ctx,
    );

    transfer::public_share_object(cap);
}

/// One-shot migration for v2-era caps that were minted user-owned
/// before the cron auth model was fully designed. Caller must own the
/// cap (Sui enforces this at the runtime layer — passing a cap you
/// don't own is rejected by the validator) and be its recorded
/// `cap.owner` (the inner assert defends against transferred caps).
///
/// After this call the cap behaves identically to a freshly-enabled
/// v3 cap: shared object, worker can reference it, user retains the
/// owner-gated pause/resume/disable controls.
public fun share_existing_cap<T>(cap: AutoSwapCap<T>, ctx: &TxContext) {
    assert!(ctx.sender() == auto_swap::cap_owner(&cap), ENotOwner);
    transfer::public_share_object(cap);
}

// ───────────────────────────────────────────────────────────────────
// Deposits — anyone can call

/// Deposit a `Coin<T>` into the vault. Anyone can call this — the
/// vault is "your destination address." We accept Coin (not Balance)
/// so the SDK can call `coin::split` upstream.
public fun deposit<T>(
    vault: &mut TaliseVault,
    coin: Coin<T>,
    ctx: &TxContext,
) {
    let amount = coin.value();
    assert!(amount > 0, EZeroAmount);
    let balance = coin.into_balance();
    deposit_balance(vault, balance, ctx.sender());
}

/// Claim a `Coin<T>` that was transferred TO the vault's object
/// address (via `transfer::public_transfer(coin, vault_addr)`) and
/// fold it into the vault's bag.
///
/// Why this exists: when the user's @talise subname resolves to the
/// vault, anyone sending to that handle does a plain
/// `transfer::public_transfer` — which makes the coin "address-owned"
/// by the vault's id. The vault is a shared object, so no signer
/// can spend that coin via the normal owned-object path. Sui's
/// `transfer::public_receive` primitive is the documented escape:
/// the shared object's module presents a `Receiving<T>` capability
/// referring to the orphan, calls `public_receive`, and gets the
/// `Coin<T>` back as a proper input it can deposit into the bag.
///
/// Anyone can call this — there's no fund-extraction risk because
/// the coin's only destination is `vault.balances`. The off-chain
/// cron sweeper scans `getOwnedObjects(vault_addr)` and calls this
/// for every `Coin<T>` it finds before running the auto-swap pass.
/// v5+ companion to `receive_and_deposit`: claim a `Balance<T>` from
/// Sui's address-accumulator system into the vault's bag.
///
/// Why this is separate from `receive_and_deposit`: when a coin is
/// transferred to a shared-object's address via `transfer::public_transfer`,
/// the Sui runtime routes the value through the global accumulator at
/// address `0x000…0acc` rather than parking a fresh `Coin<T>` at the
/// destination address. The accumulator stores the inbound value as
/// `dynamic_field::Field<accumulator::Key<Balance<T>>>` keyed by the
/// destination. There is no `Coin<T>` to call `public_receive` on, so
/// the existing `receive_and_deposit` path returns
/// "Could not find the referenced object at version SequenceNumber(X)".
///
/// `balance::withdraw_funds_from_object` is the framework's accumulator-
/// withdraw primitive: it consumes the address's accumulator slot for
/// type T (by the vault's UID) up to `amount` raw units, returning a
/// `Withdrawal<Balance<T>>` capability. Redeeming the withdrawal gives
/// back a regular `Balance<T>` which is then folded into the bag the
/// same way every other deposit path lands.
///
/// `amount` is intentionally a u64 cap on the claim — callers (the
/// off-chain cron) pass the current balance read from
/// `suix_getAllBalances`. If the accumulator slot value differs (e.g.
/// the user received MORE between the read and this tx), only `amount`
/// is claimed; the leftover sits for the next tick. The framework
/// asserts `amount <= slot_value` so over-pulling is impossible.
///
/// Permissionless — same trust model as `receive_and_deposit`: the
/// only destination is `vault.balances`, no fund-extraction surface.
public fun receive_from_accumulator<T>(
    vault: &mut TaliseVault,
    amount: u64,
    ctx: &TxContext,
) {
    let withdrawal = balance::withdraw_funds_from_object<T>(&mut vault.id, amount);
    let bal = balance::redeem_funds(withdrawal);
    let value = balance::value(&bal);
    assert!(value > 0, EZeroAmount);
    deposit_balance(vault, bal, ctx.sender());
}

/// Companion to receive_from_accumulator for the dest type itself
/// (USDsui). When the user receives USDsui directly at @handle, we
/// don't want it sitting in the bag waiting for an unrelated swap to
/// flush it — pull it from the accumulator and send it straight to
/// vault.owner.
///
/// Permissionless — same trust model as the other claim functions
/// (only destination is vault.owner, hardwired at vault creation).
public fun receive_from_accumulator_to_owner<T>(
    vault: &mut TaliseVault,
    amount: u64,
    ctx: &mut TxContext,
) {
    let withdrawal = balance::withdraw_funds_from_object<T>(&mut vault.id, amount);
    let bal = balance::redeem_funds(withdrawal);
    assert!(balance::value(&bal) > 0, EZeroAmount);
    let coin_out = coin::from_balance(bal, ctx);
    transfer::public_transfer(coin_out, vault.owner);
}

public fun receive_and_deposit<T>(
    vault: &mut TaliseVault,
    receiving: Receiving<Coin<T>>,
    ctx: &TxContext,
) {
    let coin = transfer::public_receive(&mut vault.id, receiving);
    let amount = coin.value();
    assert!(amount > 0, EZeroAmount);
    let balance = coin.into_balance();
    deposit_balance(vault, balance, ctx.sender());
}

/// Lower-level helper used by both `deposit` and the swap entry to
/// re-deposit the swap output. Not entry — internal/composable only.
public(package) fun deposit_balance<T>(
    vault: &mut TaliseVault,
    balance: Balance<T>,
    from: address,
) {
    let amount = balance::value(&balance);
    if (amount == 0) {
        balance::destroy_zero(balance);
        return
    };
    let key = type_name::with_defining_ids<T>().into_string().into_bytes();
    if (vault.balances.contains(key)) {
        let held: &mut Balance<T> = vault.balances.borrow_mut(key);
        balance::join(held, balance);
    } else {
        vault.balances.add(key, balance);
    };
    vault.deposits_total = vault.deposits_total + 1;
    event::emit(VaultDeposited {
        vault_id: object::id(vault),
        coin_type: key,
        amount,
        from,
    });
}

// ───────────────────────────────────────────────────────────────────
// Withdrawals — owner only

/// Withdraw a specific amount of `T` to the caller. Caller must be
/// `vault.owner`. Returns a `Coin<T>` for downstream PTB composition.
public fun withdraw<T>(
    vault: &mut TaliseVault,
    amount: u64,
    ctx: &mut TxContext,
): Coin<T> {
    assert!(ctx.sender() == vault.owner, ENotOwner);
    assert!(amount > 0, EZeroAmount);
    let key = type_name::with_defining_ids<T>().into_string().into_bytes();
    assert!(vault.balances.contains(key), ETypeNotHeld);

    let held: &mut Balance<T> = vault.balances.borrow_mut(key);
    assert!(balance::value(held) >= amount, EInsufficientBalance);
    let out = balance::split(held, amount);

    if (balance::value(held) == 0) {
        let empty: Balance<T> = vault.balances.remove(key);
        balance::destroy_zero(empty);
    };

    event::emit(VaultDebited {
        vault_id: object::id(vault),
        coin_type: key,
        amount,
        to: ctx.sender(),
    });

    coin::from_balance(out, ctx)
}

/// Convenience: withdraw + transfer in one entry call.
public fun withdraw_and_send<T>(
    vault: &mut TaliseVault,
    amount: u64,
    recipient: address,
    ctx: &mut TxContext,
) {
    let coin = withdraw<T>(vault, amount, ctx);
    transfer::public_transfer(coin, recipient);
}

// ───────────────────────────────────────────────────────────────────
// Auto-swap: worker-signed source-balance extraction (with hot potato)

/// Worker calls this to extract a `Balance<Source>` for swapping.
/// Returns the balance AND a `SwapTicket` hot potato that MUST be
/// consumed by `auto_swap_deposit` later in the same PTB. The ticket
/// has no abilities, so the PTB will not type-check if the worker
/// tries to walk away with the source balance.
///
/// Validates inside `auto_swap::validate_for_swap`: sender == admin,
/// cap not paused, cap not expired, amount ≤ cap.max_per_swap. The
/// `Source` type parameter must match the cap's phantom — the type
/// system catches "use a USDC cap to drain SUI."
public fun auto_swap_extract<Source>(
    vault: &mut TaliseVault,
    registry: &mut AutoSwapRegistry,
    cap: &AutoSwapCap<Source>,
    amount: u64,
    clock: &Clock,
    ctx: &TxContext,
): (Balance<Source>, SwapTicket) {
    assert!(auto_swap::cap_vault(cap) == object::id(vault), EWrongVault);
    assert!(amount > 0, EZeroAmount);

    auto_swap::validate_for_swap<Source>(
        registry,
        cap,
        amount,
        clock.timestamp_ms(),
        ctx,
    );

    let key = type_name::with_defining_ids<Source>().into_string().into_bytes();
    assert!(vault.balances.contains(key), ETypeNotHeld);
    let held: &mut Balance<Source> = vault.balances.borrow_mut(key);
    assert!(balance::value(held) >= amount, EInsufficientBalance);
    let extracted = balance::split(held, amount);

    if (balance::value(held) == 0) {
        let empty: Balance<Source> = vault.balances.remove(key);
        balance::destroy_zero(empty);
    };

    let ticket = SwapTicket {
        vault_id: object::id(vault),
        from_type: key,
        from_amount: amount,
    };

    (extracted, ticket)
}

/// Deposit the swap output back into the vault and consume the ticket.
/// Asserts the ticket was issued against THIS vault — funds cannot
/// flow to a different vault inside the same PTB.
///
/// `Dest` is unconstrained at the type level here; the off-chain SDK
/// builds the PTB with `Dest = USDsui`. v2 should add a registry-level
/// allowlist of destination types and assert it (see AUTOSWAP.md).
public fun auto_swap_deposit<Dest>(
    vault: &mut TaliseVault,
    output: Balance<Dest>,
    ticket: SwapTicket,
    clock: &Clock,
) {
    // Destructure the ticket — this is the consumer that satisfies the
    // hot-potato discipline. After this line, the ticket is gone.
    let SwapTicket { vault_id, from_type, from_amount } = ticket;
    assert!(vault_id == object::id(vault), EWrongVault);

    let to_amount = balance::value(&output);
    if (to_amount > 0) {
        let key = type_name::with_defining_ids<Dest>().into_string().into_bytes();
        if (vault.balances.contains(key)) {
            let held: &mut Balance<Dest> = vault.balances.borrow_mut(key);
            balance::join(held, output);
        } else {
            vault.balances.add(key, output);
        };
    } else {
        balance::destroy_zero(output);
    };

    vault.auto_swaps_total = vault.auto_swaps_total + 1;

    event::emit(VaultAutoSwapped {
        vault_id: object::id(vault),
        from_type,
        to_type: type_name::with_defining_ids<Dest>().into_string().into_bytes(),
        from_amount,
        to_amount,
        ts_ms: clock.timestamp_ms(),
    });
}

/// Same shape as `auto_swap_deposit`, but routes the swap output
/// (and any leftover Balance<Dest> sitting in the bag from older bag-
/// deposits) straight to `vault.owner` as a regular `Coin<Dest>`.
/// This is the path the cron worker calls in v4+ so users see their
/// auto-swapped USDsui appear in their plain wallet rather than
/// accumulating invisibly inside the shared vault.
///
/// The "drain existing bag balance" step is the migration-friendly
/// part: any prior swap output still in `vault.balances` for the same
/// `Dest` type gets flushed out alongside the new swap output. So the
/// first tick after v4 deploys clears the historical bag overhang AND
/// delivers the new swap, in one tx, no separate "sweep" call needed.
///
/// Same hot-potato discipline as the bag-deposit variant — the ticket
/// is consumed here, and `auto_swap_extract` cannot type-check unless
/// SOME deposit function (either this one or the bag variant) closes
/// the PTB.
public fun auto_swap_deposit_to_owner<Dest>(
    vault: &mut TaliseVault,
    output: Balance<Dest>,
    ticket: SwapTicket,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let SwapTicket { vault_id, from_type, from_amount } = ticket;
    assert!(vault_id == object::id(vault), EWrongVault);

    let to_amount = balance::value(&output);

    // Combine swap output with any stale Balance<Dest> in the bag so
    // pre-v4 leftovers flush out automatically. `bag::remove` returns
    // the existing balance by value; `balance::join` consumes both.
    let mut total: Balance<Dest> = output;
    let key = type_name::with_defining_ids<Dest>().into_string().into_bytes();
    if (vault.balances.contains(key)) {
        let stale: Balance<Dest> = vault.balances.remove(key);
        balance::join(&mut total, stale);
    };

    if (balance::value(&total) > 0) {
        let coin_out = coin::from_balance(total, ctx);
        // owner is whoever the user authenticated as when they created
        // the vault — the canonical "their wallet" address.
        transfer::public_transfer(coin_out, vault.owner);
    } else {
        balance::destroy_zero(total);
    };

    vault.auto_swaps_total = vault.auto_swaps_total + 1;

    event::emit(VaultAutoSwapped {
        vault_id: object::id(vault),
        from_type,
        to_type: type_name::with_defining_ids<Dest>().into_string().into_bytes(),
        from_amount,
        to_amount,
        ts_ms: clock.timestamp_ms(),
    });
}

// ═══════════════════════════════════════════════════════════════════
// v7: extract + deposit variants that consume `AutoSwapRegistryV2` and
// `AutoSwapCapV2<T>`. New functions (the existing v1 signatures stay
// frozen for `compatible` upgrade compliance) — Onara is updated to
// route through these once v7 is published.
// ═══════════════════════════════════════════════════════════════════

/// v7 variant of `auto_swap_extract`. Calls `validate_for_swap_v2`
/// which adds: registry pause check, multi-worker membership check,
/// per-day throttle, overflow guard.
public fun auto_swap_extract_v2<Source>(
    vault: &mut TaliseVault,
    registry: &mut AutoSwapRegistryV2,
    cap: &mut AutoSwapCapV2<Source>,
    amount: u64,
    clock: &Clock,
    ctx: &TxContext,
): (Balance<Source>, SwapTicket) {
    assert!(auto_swap::cap_v2_vault(cap) == object::id(vault), EWrongVault);
    assert!(amount > 0, EZeroAmount);

    auto_swap::validate_for_swap_v2<Source>(registry, cap, amount, clock, ctx);

    let key = type_name::with_defining_ids<Source>().into_string().into_bytes();
    assert!(vault.balances.contains(key), ETypeNotHeld);
    let held: &mut Balance<Source> = vault.balances.borrow_mut(key);
    assert!(balance::value(held) >= amount, EInsufficientBalance);
    let extracted = balance::split(held, amount);

    if (balance::value(held) == 0) {
        let empty: Balance<Source> = vault.balances.remove(key);
        balance::destroy_zero(empty);
    };

    let ticket = SwapTicket {
        vault_id: object::id(vault),
        from_type: key,
        from_amount: amount,
    };

    (extracted, ticket)
}

/// v7 variant of `auto_swap_deposit`. Asserts that `Dest` is on the
/// registry's `allowed_dest_types` list — a compromised Worker cannot
/// route swap output to an arbitrary coin type.
public fun auto_swap_deposit_v2<Dest>(
    vault: &mut TaliseVault,
    registry: &AutoSwapRegistryV2,
    output: Balance<Dest>,
    ticket: SwapTicket,
    clock: &Clock,
) {
    auto_swap::assert_dest_allowed<Dest>(registry);

    let SwapTicket { vault_id, from_type, from_amount } = ticket;
    assert!(vault_id == object::id(vault), EWrongVault);

    let to_amount = balance::value(&output);
    if (to_amount > 0) {
        let key = type_name::with_defining_ids<Dest>().into_string().into_bytes();
        if (vault.balances.contains(key)) {
            let held: &mut Balance<Dest> = vault.balances.borrow_mut(key);
            balance::join(held, output);
        } else {
            vault.balances.add(key, output);
        };
    } else {
        balance::destroy_zero(output);
    };

    vault.auto_swaps_total = vault.auto_swaps_total + 1;

    event::emit(VaultAutoSwapped {
        vault_id: object::id(vault),
        from_type,
        to_type: type_name::with_defining_ids<Dest>().into_string().into_bytes(),
        from_amount,
        to_amount,
        ts_ms: clock.timestamp_ms(),
    });
}

/// v7 variant of `auto_swap_deposit_to_owner`. Same dest-allowlist
/// assertion as `auto_swap_deposit_v2`, but routes swap output (plus
/// any stale bag balance of the same type) to `vault.owner`.
public fun auto_swap_deposit_to_owner_v2<Dest>(
    vault: &mut TaliseVault,
    registry: &AutoSwapRegistryV2,
    output: Balance<Dest>,
    ticket: SwapTicket,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    auto_swap::assert_dest_allowed<Dest>(registry);

    let SwapTicket { vault_id, from_type, from_amount } = ticket;
    assert!(vault_id == object::id(vault), EWrongVault);

    let to_amount = balance::value(&output);

    let mut total: Balance<Dest> = output;
    let key = type_name::with_defining_ids<Dest>().into_string().into_bytes();
    if (vault.balances.contains(key)) {
        let stale: Balance<Dest> = vault.balances.remove(key);
        balance::join(&mut total, stale);
    };

    if (balance::value(&total) > 0) {
        let coin_out = coin::from_balance(total, ctx);
        transfer::public_transfer(coin_out, vault.owner);
    } else {
        balance::destroy_zero(total);
    };

    vault.auto_swaps_total = vault.auto_swaps_total + 1;

    event::emit(VaultAutoSwapped {
        vault_id: object::id(vault),
        from_type,
        to_type: type_name::with_defining_ids<Dest>().into_string().into_bytes(),
        from_amount,
        to_amount,
        ts_ms: clock.timestamp_ms(),
    });
}

/// v7 cap-enable. Mints an `AutoSwapCapV2<T>` directly (vs the v1 path
/// which mints `AutoSwapCap<T>` then requires `upgrade_cap_to_v2`).
/// Caller must own the vault.
public fun enable_auto_swap_v2<T>(
    vault: &TaliseVault,
    max_per_swap: u64,
    max_per_day: u64,
    expires_at_ms: u64,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(ctx.sender() == vault.owner, ENotOwner);
    let cap = auto_swap::new_cap_v2<T>(
        object::id(vault),
        vault.owner,
        max_per_swap,
        max_per_day,
        expires_at_ms,
        clock,
        ctx,
    );
    transfer::public_share_object(cap);
}

// ───────────────────────────────────────────────────────────────────
// Read accessors

public fun owner(vault: &TaliseVault): address { vault.owner }

public fun deposits_total(vault: &TaliseVault): u64 { vault.deposits_total }

public fun auto_swaps_total(vault: &TaliseVault): u64 { vault.auto_swaps_total }

/// Returns the current balance of type `T`. Returns 0 if the vault
/// holds none of `T`. Used by the off-chain worker to decide whether
/// to schedule an auto-swap.
public fun balance_of<T>(vault: &TaliseVault): u64 {
    let key = type_name::with_defining_ids<T>().into_string().into_bytes();
    if (vault.balances.contains(key)) {
        let held: &Balance<T> = vault.balances.borrow(key);
        balance::value(held)
    } else {
        0
    }
}

/// String form of the held coin type — useful for indexers / SDK that
/// don't speak Move's type system.
public fun type_string<T>(): String {
    type_name::with_defining_ids<T>().into_string().to_string()
}

// ───────────────────────────────────────────────────────────────────
// Test-only shims

#[test_only]
public fun test_deposit_balance<T>(
    vault: &mut TaliseVault,
    balance: Balance<T>,
    from: address,
) {
    deposit_balance(vault, balance, from)
}
