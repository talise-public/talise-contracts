/// Auto-swap authority + per-user opt-in capability.
///
/// Architecture, in one paragraph:
///   Every Talise user who claims an @talise subname gets a `TaliseVault`
///   (see `talise::vault`). The vault is a shared object whose contents
///   only the owner can withdraw — but a separately-minted `AutoSwapCap<T>`
///   grants a globally-known admin address (Talise's Onara-sponsored
///   worker) permission to convert `Balance<T>` already inside the vault
///   into USDsui through a whitelisted DEX. The user keeps custody (they
///   can withdraw or burn the cap any time); the worker only ever sees
///   balances the user explicitly authorized it to touch, capped per
///   swap and per coin type.
///
/// Audit notes (v2, post-review):
///   • Cap minting moved to `talise::vault::enable_auto_swap`, which has
///     `&TaliseVault` in scope and asserts `vault.owner == ctx.sender()`.
///     Closes the "mint a cap pointing at someone else's vault" hole.
///   • `validate_for_swap` is now `public(package)` and derives `sender`
///     from `&TxContext` internally — callers can't spoof it.
///   • Hot-potato: `auto_swap_extract` returns a no-ability `SwapTicket`
///     alongside the extracted balance (defined in `talise::vault`).
///     `auto_swap_deposit` is the only consumer; the PTB will not
///     type-check unless deposit runs in the same tx.
///   • `disable`/`pause`/`resume`/`update_bounds` now assert
///     `ctx.sender() == cap.owner` — the cap is transferable (`store`),
///     but only the original owner can mutate its state.
module talise::auto_swap;

use sui::{event, clock::Clock};
use std::type_name::{Self, TypeName};

// ───────────────────────────────────────────────────────────────────
// Errors

const ECapPaused: u64 = 100;
const ECapExpired: u64 = 101;
const EAmountExceedsCap: u64 = 102;
const EWrongAdmin: u64 = 103;
const EInvalidMax: u64 = 104;
const ENotOwner: u64 = 106;

// v7 errors
const ENotAdmin: u64 = 200;
const ENotAdminOrTreasury: u64 = 201;
const ENotAdminOrOncall: u64 = 202;
const ENotWorker: u64 = 203;
const ERegistryPaused: u64 = 204;
const ENoPendingTransfer: u64 = 205;
const EWrongPendingAcceptor: u64 = 206;
const EDelayNotElapsed: u64 = 207;
const EDelayTooLarge: u64 = 208;
const ENoPendingDelay: u64 = 209;
const EPendingTransferExists: u64 = 210;
const EPendingDelayExists: u64 = 211;
const EDailyBudgetExceeded: u64 = 212;
const EOverflow: u64 = 213;
const EInvalidMaxPerDay: u64 = 214;
const EDestNotAllowed: u64 = 215;
const ERoleAlreadyGranted: u64 = 216;
const ERoleNotGranted: u64 = 217;
const EProviderAlreadyAllowed: u64 = 218;
const EProviderNotAllowed: u64 = 219;
const EDestAlreadyAllowed: u64 = 220;

// Defaults
const DEFAULT_ADMIN_TRANSFER_DELAY_MS: u64 = 48 * 3600 * 1000; // 48h
const MAX_ADMIN_TRANSFER_DELAY_MS: u64 = 60 * 24 * 3600 * 1000; // 60 days
const DAY_MS: u64 = 86_400_000;
const U64_MAX: u64 = 18446744073709551615;

// ───────────────────────────────────────────────────────────────────
// Objects

/// Singleton shared object created at publish time. Holds the global
/// admin address allowed to execute auto-swaps. Future governance can
/// add admin-rotation; for v1 the address is set at init and immutable
/// (rotation requires a `AdminCap`-gated path which we leave for v2).
public struct AutoSwapRegistry has key {
    id: UID,
    /// Address that may execute auto-swaps. Compared to `tx_context::sender()`
    /// inside `validate_for_swap`. This is the Onara-side worker address.
    admin: address,
    /// Monotonic counter for telemetry / SLA reporting. Bumped by
    /// `validate_for_swap`. Not load-bearing for any security check.
    total_validations: u64,
}

/// Admin-only capability minted once at init, transferred to the
/// publisher. Holds reserved rights for future governance moves
/// (admin rotation, registry pause, etc.). The day-to-day worker does
/// NOT need this — it just needs to be the `admin` address recorded in
/// `AutoSwapRegistry`.
public struct AdminCap has key, store { id: UID }

/// Per-user, per-source-coin-type authority. Owned by the user.
/// Existence is necessary-but-not-sufficient for the worker to execute
/// a swap: the worker must also be the recorded admin AND the swap
/// amount must fit inside `max_per_swap`.
///
/// `T` is the SOURCE coin type. Destination is always USDsui (enforced
/// by the swap entry in `talise::vault`).
public struct AutoSwapCap<phantom T> has key, store {
    id: UID,
    /// Vault that this cap authorises the worker to drain `T` from.
    /// Hardwired at mint time by `vault::enable_auto_swap`, which
    /// asserts the minter owns the vault. A leaked cap cannot be
    /// re-targeted, and the original mint cannot point at someone
    /// else's vault.
    vault_id: ID,
    /// The address that minted this cap. The cap has `store` so it can
    /// be transferred — but mutate-/burn-ops in this module check
    /// `ctx.sender() == cap.owner` so a transferred cap is "read-only"
    /// to the new holder.
    owner: address,
    /// Hard cap on the source amount the worker may swap in one call,
    /// expressed in `T`'s native decimals. Defense in depth: even with
    /// a compromised admin, the blast radius per tx is bounded.
    max_per_swap: u64,
    /// Unix ms expiry. After this timestamp, `validate_for_swap` fails.
    /// 0 = no expiry. Encourages users to set sensible windows.
    expires_at_ms: u64,
    /// User can pause without burning. Re-enabling is free; minting a
    /// fresh cap costs a small object-creation fee.
    paused: bool,
}

// ───────────────────────────────────────────────────────────────────
// Events

public struct AutoSwapEnabled has copy, drop {
    owner: address,
    vault_id: ID,
    cap_id: ID,
    coin_type: vector<u8>,
    max_per_swap: u64,
    expires_at_ms: u64,
}

public struct AutoSwapDisabled has copy, drop {
    owner: address,
    cap_id: ID,
    coin_type: vector<u8>,
}

public struct AutoSwapPaused has copy, drop {
    owner: address,
    cap_id: ID,
    paused: bool,
}

public struct AutoSwapValidated has copy, drop {
    admin: address,
    vault_id: ID,
    cap_id: ID,
    amount: u64,
    coin_type: vector<u8>,
}

// ───────────────────────────────────────────────────────────────────
// Init

/// Publish-time initializer. Creates the singleton registry as a shared
/// object so anyone can read `admin`, and mints `AdminCap` to the
/// publisher. The publisher MUST be the address used as `admin` (or
/// pick a different operator address — see `AutoSwapRegistry.admin`).
fun init(ctx: &mut TxContext) {
    let registry = AutoSwapRegistry {
        id: object::new(ctx),
        admin: ctx.sender(),
        total_validations: 0,
    };
    transfer::share_object(registry);

    let admin_cap = AdminCap { id: object::new(ctx) };
    transfer::public_transfer(admin_cap, ctx.sender());
}

// ───────────────────────────────────────────────────────────────────
// Cap construction — package-private, only `talise::vault` calls this
// (after it has asserted vault.owner == ctx.sender()).

/// Mint an `AutoSwapCap<T>` for `owner`, bound to `vault_id`. The
/// vault-ownership check is the caller's responsibility — that's the
/// reason this is `public(package)` and `vault::enable_auto_swap` is
/// the only call site.
public(package) fun mint_cap<T>(
    vault_id: ID,
    owner: address,
    max_per_swap: u64,
    expires_at_ms: u64,
    ctx: &mut TxContext,
): AutoSwapCap<T> {
    assert!(max_per_swap > 0, EInvalidMax);

    let cap = AutoSwapCap<T> {
        id: object::new(ctx),
        vault_id,
        owner,
        max_per_swap,
        expires_at_ms,
        paused: false,
    };

    event::emit(AutoSwapEnabled {
        owner,
        vault_id,
        cap_id: object::id(&cap),
        coin_type: std::type_name::with_defining_ids<T>().into_string().into_bytes(),
        max_per_swap,
        expires_at_ms,
    });

    cap
}

// ───────────────────────────────────────────────────────────────────
// User-facing entry points (the consent surface)

/// Permanently disable auto-swap for `T`. Burns the cap.
/// Caller must be `cap.owner`.
public fun disable<T>(cap: AutoSwapCap<T>, ctx: &TxContext) {
    assert!(ctx.sender() == cap.owner, ENotOwner);
    let AutoSwapCap { id, owner, .. } = cap;
    event::emit(AutoSwapDisabled {
        owner,
        cap_id: id.to_inner(),
        coin_type: std::type_name::with_defining_ids<T>().into_string().into_bytes(),
    });
    id.delete();
}

/// Temporarily pause auto-swap (worker validation fails until resumed).
/// Caller must be `cap.owner`.
public fun pause<T>(cap: &mut AutoSwapCap<T>, ctx: &TxContext) {
    assert!(ctx.sender() == cap.owner, ENotOwner);
    cap.paused = true;
    event::emit(AutoSwapPaused {
        owner: cap.owner,
        cap_id: object::id(cap),
        paused: true,
    });
}

/// Resume after a pause. Caller must be `cap.owner`.
public fun resume<T>(cap: &mut AutoSwapCap<T>, ctx: &TxContext) {
    assert!(ctx.sender() == cap.owner, ENotOwner);
    cap.paused = false;
    event::emit(AutoSwapPaused {
        owner: cap.owner,
        cap_id: object::id(cap),
        paused: false,
    });
}

/// Update bounds without re-minting. Caller must be `cap.owner`.
/// Note: v1 lets the owner raise limits freely. v2 should clamp
/// to `original_max` (see AUTOSWAP.md hardening list).
public fun update_bounds<T>(
    cap: &mut AutoSwapCap<T>,
    max_per_swap: u64,
    expires_at_ms: u64,
    ctx: &TxContext,
) {
    assert!(ctx.sender() == cap.owner, ENotOwner);
    assert!(max_per_swap > 0, EInvalidMax);
    cap.max_per_swap = max_per_swap;
    cap.expires_at_ms = expires_at_ms;
}

// ───────────────────────────────────────────────────────────────────
// Worker-facing validation (called from inside `talise::vault::auto_swap_*`)

/// Called by the swap entry in `talise::vault`. Returns nothing — it
/// either passes (all assertions hold, registry counter bumps, event
/// emits) or aborts the entire PTB.
///
/// `public(package)` so off-chain callers can't bump the counter
/// without going through `vault::auto_swap_extract`. Sender derived
/// from `&TxContext` — caller cannot spoof.
public(package) fun validate_for_swap<T>(
    registry: &mut AutoSwapRegistry,
    cap: &AutoSwapCap<T>,
    amount: u64,
    now_ms: u64,
    ctx: &TxContext,
) {
    let sender = ctx.sender();
    assert!(sender == registry.admin, EWrongAdmin);
    assert!(!cap.paused, ECapPaused);
    if (cap.expires_at_ms != 0) {
        assert!(now_ms <= cap.expires_at_ms, ECapExpired);
    };
    assert!(amount <= cap.max_per_swap, EAmountExceedsCap);

    registry.total_validations = registry.total_validations + 1;

    event::emit(AutoSwapValidated {
        admin: sender,
        vault_id: cap.vault_id,
        cap_id: object::id(cap),
        amount,
        coin_type: std::type_name::with_defining_ids<T>().into_string().into_bytes(),
    });
}

// ───────────────────────────────────────────────────────────────────
// Public read accessors (for SDK / indexer convenience)

public fun admin(registry: &AutoSwapRegistry): address { registry.admin }

public fun total_validations(registry: &AutoSwapRegistry): u64 {
    registry.total_validations
}

public fun cap_owner<T>(cap: &AutoSwapCap<T>): address { cap.owner }
public fun cap_vault<T>(cap: &AutoSwapCap<T>): ID { cap.vault_id }
public fun cap_max<T>(cap: &AutoSwapCap<T>): u64 { cap.max_per_swap }
public fun cap_expiry<T>(cap: &AutoSwapCap<T>): u64 { cap.expires_at_ms }
public fun cap_paused<T>(cap: &AutoSwapCap<T>): bool { cap.paused }

// ───────────────────────────────────────────────────────────────────
// Test-only

#[test_only]
public fun test_init(ctx: &mut TxContext) { init(ctx) }

#[test_only]
public fun test_validate_for_swap<T>(
    registry: &mut AutoSwapRegistry,
    cap: &AutoSwapCap<T>,
    amount: u64,
    now_ms: u64,
    ctx: &TxContext,
) {
    validate_for_swap<T>(registry, cap, amount, now_ms, ctx)
}

// ═══════════════════════════════════════════════════════════════════
// v7: AutoSwapRegistryV2 — role-separated, throttled, allowlisted
// ═══════════════════════════════════════════════════════════════════
//
// Why a parallel registry instead of mutating AutoSwapRegistry:
//   Sui's `compatible` upgrade policy prohibits changing existing
//   public-struct field layouts. The v1 `AutoSwapRegistry` is frozen.
//   v7 introduces a fresh shared object whose construction is driven
//   by `bootstrap_v7` (callable post-upgrade because the package was
//   already published with v1's `init`).
//
// Role model (hand-rolled, see SECURITY-V7.md):
//   Admin (root, cold)          → grant/revoke roles, rotate admin
//                                  (2-step w/ 48h delay), pause, etc.
//   Treasury (cold, multi-sig)  → mutate allowlists
//   Oncall   (warm)             → pause / unpause registry
//   Worker   (hot, Onara)       → call validate_for_swap_v2
//
// Why not OZ AccessControl: OZ AccessControl requires an OTW which can
// only be claimed at module `init`. We're upgrading an already-published
// package — `init` is not reachable. Hand-rolled role bookkeeping is
// the only path. Patterns (2-step transfer, 48h delay, cancel) are
// borrowed from OZ.
//
// Why not OZ math: pulling `openzeppelin_math` produces a Sui-framework
// rev conflict (`framework/testnet` vs OZ's pinned rev) that requires
// an `override = true`. The throttle math is small enough that explicit
// overflow asserts against `U64_MAX` are equivalent in safety.

public struct AutoSwapRegistryV2 has key {
    id: UID,
    /// Current admin (root role holder). Set at bootstrap, rotated via 2-step.
    admin: address,
    /// Pending admin transfer state. None when no rotation in flight.
    pending_admin_transfer: Option<PendingAdminTransfer>,
    /// Delay (ms) between begin_admin_transfer and accept_admin_transfer.
    /// Initialized to 48h. Mutable via begin/accept delay change.
    admin_transfer_delay_ms: u64,
    /// Pending delay change.
    pending_delay_change: Option<PendingDelayChange>,
    /// Address set with WorkerRole — can call validate_for_swap_v2.
    worker_addresses: vector<address>,
    /// Address set with OncallRole — can pause/unpause registry.
    oncall_addresses: vector<address>,
    /// Address set with TreasuryRole — can modify allowlists.
    treasury_addresses: vector<address>,
    /// Allowed destination coin types for auto_swap_deposit_to_owner_v2.
    /// A compromised Worker cannot route to anything outside this set.
    allowed_dest_types: vector<TypeName>,
    /// Allowed Cetus aggregator providers (string keys like "CETUS",
    /// "AFTERMATH"). Currently aspirational — Move can't see the
    /// aggregator's provider field directly. Stored here for off-chain
    /// enforcement consistency.
    allowed_providers: vector<vector<u8>>,
    /// Global kill switch. When true, validate_for_swap_v2 aborts.
    paused: bool,
    /// Monotonic counter of successful validations.
    total_validations: u64,
}

public struct PendingAdminTransfer has store, drop {
    new_admin: address,
    scheduled_at_ms: u64,
    /// Snapshot of `admin_transfer_delay_ms` at initiate time. Prevents
    /// shrink-attacks: if delay is later changed, the in-flight transfer
    /// still requires the original wait.
    delay_at_schedule_ms: u64,
}

public struct PendingDelayChange has store, drop {
    new_delay_ms: u64,
    scheduled_at_ms: u64,
    delay_at_schedule_ms: u64,
}

/// v7 cap with per-day throttle. Cannot be added to v1 AutoSwapCap due
/// to compatible-upgrade rules — this is a fresh struct. v7 functions
/// only accept this type.
public struct AutoSwapCapV2<phantom T> has key, store {
    id: UID,
    vault_id: ID,
    owner: address,
    max_per_swap: u64,
    expires_at_ms: u64,
    paused: bool,
    /// Daily budget in source-coin native units. Rolls over at
    /// `day_reset_at_ms` (24h after last reset).
    max_per_day: u64,
    used_today: u64,
    day_reset_at_ms: u64,
}

// ───────────────────────────────────────────────────────────────────
// v7 events

public struct RegistryBootstrapped has copy, drop {
    registry_id: ID,
    admin: address,
}

public struct WorkerGranted has copy, drop { addr: address, by: address }
public struct WorkerRevoked has copy, drop { addr: address, by: address }
public struct OncallGranted has copy, drop { addr: address, by: address }
public struct OncallRevoked has copy, drop { addr: address, by: address }
public struct TreasuryGranted has copy, drop { addr: address, by: address }
public struct TreasuryRevoked has copy, drop { addr: address, by: address }

public struct AdminTransferStarted has copy, drop {
    current: address,
    pending: address,
    executable_after_ms: u64,
}
public struct AdminTransferAccepted has copy, drop { old: address, new: address }
public struct AdminTransferCancelled has copy, drop {
    current: address,
    was_pending: address,
}

public struct DelayChangeStarted has copy, drop {
    current_delay_ms: u64,
    pending_delay_ms: u64,
    executable_after_ms: u64,
}
public struct DelayChangeAccepted has copy, drop {
    old_delay_ms: u64,
    new_delay_ms: u64,
}
public struct DelayChangeCancelled has copy, drop {
    current_delay_ms: u64,
    was_pending_delay_ms: u64,
}

public struct RegistryPaused has copy, drop { by: address }
public struct RegistryUnpaused has copy, drop { by: address }

public struct AllowedDestAdded has copy, drop { dest_type: TypeName, by: address }
public struct AllowedDestRemoved has copy, drop { dest_type: TypeName, by: address }
public struct AllowedProviderAdded has copy, drop {
    provider: vector<u8>,
    by: address,
}
public struct AllowedProviderRemoved has copy, drop {
    provider: vector<u8>,
    by: address,
}

public struct CapV2Migrated has copy, drop {
    old_cap_id: ID,
    new_cap_id: ID,
    owner: address,
}

public struct AutoSwapV2Validated has copy, drop {
    admin: address,
    vault_id: ID,
    cap_id: ID,
    amount: u64,
    used_today_after: u64,
    day_reset_at_ms: u64,
    coin_type: vector<u8>,
}

// ───────────────────────────────────────────────────────────────────
// Bootstrap (one-shot, post-upgrade)

/// Called ONCE post-upgrade to construct the v7 registry. Anyone can
/// call this, but the deploy runbook ensures the publisher signs the
/// FIRST invocation immediately after the package upgrade tx. There
/// is no on-chain sentinel preventing a second call — each call mints
/// a fresh shared registry — so off-chain readiness depends on env
/// pinning `TALISE_AUTOSWAP_REGISTRY_V2_ID` to the registry created
/// in the runbook's first tx. Subsequent registries are orphan shared
/// objects, harmless but ignored.
///
/// Note: this is the spec's recommended simplification. The spec
/// considered a witness-pattern singleton but landed on "trust the
/// runbook" because witness types in Move can only be claimed via OTW
/// or struct-construction-locality — neither works mid-upgrade. The
/// risk surface is small: an attacker creating a second registry
/// cannot grant themselves access to the canonical one.
public fun bootstrap_v7(ctx: &mut TxContext) {
    let publisher = ctx.sender();
    let registry = AutoSwapRegistryV2 {
        id: object::new(ctx),
        admin: publisher,
        pending_admin_transfer: option::none(),
        admin_transfer_delay_ms: DEFAULT_ADMIN_TRANSFER_DELAY_MS,
        pending_delay_change: option::none(),
        worker_addresses: vector[publisher],
        oncall_addresses: vector[],
        treasury_addresses: vector[],
        allowed_dest_types: vector[],
        // Initial provider allowlist per SECURITY-V7.md.
        allowed_providers: vector[
            b"CETUS",
            b"DEEPBOOKV3",
            b"AFTERMATH",
            b"CETUSDLMM",
        ],
        paused: false,
        total_validations: 0,
    };

    let registry_id = object::id(&registry);
    event::emit(RegistryBootstrapped { registry_id, admin: publisher });

    transfer::share_object(registry);
}

// ───────────────────────────────────────────────────────────────────
// Role-management entries (admin-only)

public fun grant_worker(
    registry: &mut AutoSwapRegistryV2,
    addr: address,
    ctx: &TxContext,
) {
    assert_admin(registry, ctx);
    assert!(!vector::contains(&registry.worker_addresses, &addr), ERoleAlreadyGranted);
    registry.worker_addresses.push_back(addr);
    event::emit(WorkerGranted { addr, by: ctx.sender() });
}

public fun revoke_worker(
    registry: &mut AutoSwapRegistryV2,
    addr: address,
    ctx: &TxContext,
) {
    assert_admin(registry, ctx);
    let (found, idx) = vector::index_of(&registry.worker_addresses, &addr);
    assert!(found, ERoleNotGranted);
    vector::remove(&mut registry.worker_addresses, idx);
    event::emit(WorkerRevoked { addr, by: ctx.sender() });
}

public fun grant_oncall(
    registry: &mut AutoSwapRegistryV2,
    addr: address,
    ctx: &TxContext,
) {
    assert_admin(registry, ctx);
    assert!(!vector::contains(&registry.oncall_addresses, &addr), ERoleAlreadyGranted);
    registry.oncall_addresses.push_back(addr);
    event::emit(OncallGranted { addr, by: ctx.sender() });
}

public fun revoke_oncall(
    registry: &mut AutoSwapRegistryV2,
    addr: address,
    ctx: &TxContext,
) {
    assert_admin(registry, ctx);
    let (found, idx) = vector::index_of(&registry.oncall_addresses, &addr);
    assert!(found, ERoleNotGranted);
    vector::remove(&mut registry.oncall_addresses, idx);
    event::emit(OncallRevoked { addr, by: ctx.sender() });
}

public fun grant_treasury(
    registry: &mut AutoSwapRegistryV2,
    addr: address,
    ctx: &TxContext,
) {
    assert_admin(registry, ctx);
    assert!(!vector::contains(&registry.treasury_addresses, &addr), ERoleAlreadyGranted);
    registry.treasury_addresses.push_back(addr);
    event::emit(TreasuryGranted { addr, by: ctx.sender() });
}

public fun revoke_treasury(
    registry: &mut AutoSwapRegistryV2,
    addr: address,
    ctx: &TxContext,
) {
    assert_admin(registry, ctx);
    let (found, idx) = vector::index_of(&registry.treasury_addresses, &addr);
    assert!(found, ERoleNotGranted);
    vector::remove(&mut registry.treasury_addresses, idx);
    event::emit(TreasuryRevoked { addr, by: ctx.sender() });
}

// ───────────────────────────────────────────────────────────────────
// Admin rotation (2-step + 48h delay + cancel)

public fun begin_admin_transfer(
    registry: &mut AutoSwapRegistryV2,
    new_admin: address,
    clock: &Clock,
    ctx: &TxContext,
) {
    assert_admin(registry, ctx);
    assert!(option::is_none(&registry.pending_admin_transfer), EPendingTransferExists);
    let now = clock.timestamp_ms();
    let delay = registry.admin_transfer_delay_ms;
    option::fill(&mut registry.pending_admin_transfer, PendingAdminTransfer {
        new_admin,
        scheduled_at_ms: now,
        delay_at_schedule_ms: delay,
    });
    event::emit(AdminTransferStarted {
        current: registry.admin,
        pending: new_admin,
        executable_after_ms: now + delay,
    });
}

public fun accept_admin_transfer(
    registry: &mut AutoSwapRegistryV2,
    clock: &Clock,
    ctx: &TxContext,
) {
    assert!(option::is_some(&registry.pending_admin_transfer), ENoPendingTransfer);
    let pending = option::extract(&mut registry.pending_admin_transfer);
    let PendingAdminTransfer { new_admin, scheduled_at_ms, delay_at_schedule_ms } = pending;
    assert!(ctx.sender() == new_admin, EWrongPendingAcceptor);
    assert!(
        clock.timestamp_ms() >= scheduled_at_ms + delay_at_schedule_ms,
        EDelayNotElapsed,
    );
    let old = registry.admin;
    registry.admin = new_admin;
    event::emit(AdminTransferAccepted { old, new: new_admin });
}

public fun cancel_admin_transfer(
    registry: &mut AutoSwapRegistryV2,
    ctx: &TxContext,
) {
    assert_admin(registry, ctx);
    assert!(option::is_some(&registry.pending_admin_transfer), ENoPendingTransfer);
    let pending = option::extract(&mut registry.pending_admin_transfer);
    let PendingAdminTransfer { new_admin, .. } = pending;
    event::emit(AdminTransferCancelled {
        current: registry.admin,
        was_pending: new_admin,
    });
}

public fun begin_delay_change(
    registry: &mut AutoSwapRegistryV2,
    new_delay_ms: u64,
    clock: &Clock,
    ctx: &TxContext,
) {
    assert_admin(registry, ctx);
    assert!(option::is_none(&registry.pending_delay_change), EPendingDelayExists);
    assert!(new_delay_ms <= MAX_ADMIN_TRANSFER_DELAY_MS, EDelayTooLarge);
    let now = clock.timestamp_ms();
    let delay = registry.admin_transfer_delay_ms;
    option::fill(&mut registry.pending_delay_change, PendingDelayChange {
        new_delay_ms,
        scheduled_at_ms: now,
        delay_at_schedule_ms: delay,
    });
    event::emit(DelayChangeStarted {
        current_delay_ms: delay,
        pending_delay_ms: new_delay_ms,
        executable_after_ms: now + delay,
    });
}

public fun accept_delay_change(
    registry: &mut AutoSwapRegistryV2,
    clock: &Clock,
    ctx: &TxContext,
) {
    assert_admin(registry, ctx);
    assert!(option::is_some(&registry.pending_delay_change), ENoPendingDelay);
    let pending = option::extract(&mut registry.pending_delay_change);
    let PendingDelayChange { new_delay_ms, scheduled_at_ms, delay_at_schedule_ms } = pending;
    assert!(
        clock.timestamp_ms() >= scheduled_at_ms + delay_at_schedule_ms,
        EDelayNotElapsed,
    );
    let old = registry.admin_transfer_delay_ms;
    registry.admin_transfer_delay_ms = new_delay_ms;
    event::emit(DelayChangeAccepted { old_delay_ms: old, new_delay_ms });
}

public fun cancel_delay_change(
    registry: &mut AutoSwapRegistryV2,
    ctx: &TxContext,
) {
    assert_admin(registry, ctx);
    assert!(option::is_some(&registry.pending_delay_change), ENoPendingDelay);
    let pending = option::extract(&mut registry.pending_delay_change);
    let PendingDelayChange { new_delay_ms, .. } = pending;
    event::emit(DelayChangeCancelled {
        current_delay_ms: registry.admin_transfer_delay_ms,
        was_pending_delay_ms: new_delay_ms,
    });
}

// ───────────────────────────────────────────────────────────────────
// Pause / unpause (admin OR oncall)

public fun pause_registry(
    registry: &mut AutoSwapRegistryV2,
    ctx: &TxContext,
) {
    assert_admin_or_oncall(registry, ctx);
    registry.paused = true;
    event::emit(RegistryPaused { by: ctx.sender() });
}

public fun unpause_registry(
    registry: &mut AutoSwapRegistryV2,
    ctx: &TxContext,
) {
    assert_admin_or_oncall(registry, ctx);
    registry.paused = false;
    event::emit(RegistryUnpaused { by: ctx.sender() });
}

// ───────────────────────────────────────────────────────────────────
// Allowlist management (admin OR treasury)

public fun add_allowed_dest<Dest>(
    registry: &mut AutoSwapRegistryV2,
    ctx: &TxContext,
) {
    assert_admin_or_treasury(registry, ctx);
    let t = type_name::with_defining_ids<Dest>();
    assert!(!vector::contains(&registry.allowed_dest_types, &t), EDestAlreadyAllowed);
    registry.allowed_dest_types.push_back(t);
    event::emit(AllowedDestAdded { dest_type: t, by: ctx.sender() });
}

public fun remove_allowed_dest<Dest>(
    registry: &mut AutoSwapRegistryV2,
    ctx: &TxContext,
) {
    assert_admin_or_treasury(registry, ctx);
    let t = type_name::with_defining_ids<Dest>();
    let (found, idx) = vector::index_of(&registry.allowed_dest_types, &t);
    assert!(found, EDestNotAllowed);
    vector::remove(&mut registry.allowed_dest_types, idx);
    event::emit(AllowedDestRemoved { dest_type: t, by: ctx.sender() });
}

public fun add_allowed_provider(
    registry: &mut AutoSwapRegistryV2,
    provider: vector<u8>,
    ctx: &TxContext,
) {
    assert_admin_or_treasury(registry, ctx);
    assert!(!vector::contains(&registry.allowed_providers, &provider), EProviderAlreadyAllowed);
    registry.allowed_providers.push_back(provider);
    event::emit(AllowedProviderAdded { provider, by: ctx.sender() });
}

public fun remove_allowed_provider(
    registry: &mut AutoSwapRegistryV2,
    provider: vector<u8>,
    ctx: &TxContext,
) {
    assert_admin_or_treasury(registry, ctx);
    let (found, idx) = vector::index_of(&registry.allowed_providers, &provider);
    assert!(found, EProviderNotAllowed);
    vector::remove(&mut registry.allowed_providers, idx);
    event::emit(AllowedProviderRemoved { provider, by: ctx.sender() });
}

// ───────────────────────────────────────────────────────────────────
// Worker-facing validation v2

public(package) fun validate_for_swap_v2<T>(
    registry: &mut AutoSwapRegistryV2,
    cap: &mut AutoSwapCapV2<T>,
    amount: u64,
    clock: &Clock,
    ctx: &TxContext,
) {
    // 1. Global pause kill switch.
    assert!(!registry.paused, ERegistryPaused);
    // 2. Sender must be a Worker.
    let sender = ctx.sender();
    assert!(vector::contains(&registry.worker_addresses, &sender), ENotWorker);
    // 3. Per-cap pause.
    assert!(!cap.paused, ECapPaused);
    // 4. Expiry (0 = no expiry).
    let now = clock.timestamp_ms();
    if (cap.expires_at_ms != 0) {
        assert!(now <= cap.expires_at_ms, ECapExpired);
    };
    // 5. Per-swap ceiling.
    assert!(amount <= cap.max_per_swap, EAmountExceedsCap);
    // 6. Day rollover: if we've crossed the reset boundary, zero
    // used_today and push the next reset 24h out from `now`.
    if (now >= cap.day_reset_at_ms) {
        cap.used_today = 0;
        cap.day_reset_at_ms = now + DAY_MS;
    };
    // 7. Overflow-safe addition. With u64::MAX as the ceiling, a wrap
    // would require `used_today + amount > 2^64-1` — impossible in
    // honest accounting but cheap to guard.
    assert!(amount <= U64_MAX - cap.used_today, EOverflow);
    let new_used = cap.used_today + amount;
    // 8. Daily budget assertion.
    assert!(new_used <= cap.max_per_day, EDailyBudgetExceeded);
    // 9. Commit + emit.
    cap.used_today = new_used;
    registry.total_validations = registry.total_validations + 1;
    event::emit(AutoSwapV2Validated {
        admin: sender,
        vault_id: cap.vault_id,
        cap_id: object::id(cap),
        amount,
        used_today_after: cap.used_today,
        day_reset_at_ms: cap.day_reset_at_ms,
        coin_type: type_name::with_defining_ids<T>().into_string().into_bytes(),
    });
}

/// Dest-allowlist assertion. Called from `vault::auto_swap_deposit_*_v2`.
public(package) fun assert_dest_allowed<Dest>(registry: &AutoSwapRegistryV2) {
    let t = type_name::with_defining_ids<Dest>();
    assert!(vector::contains(&registry.allowed_dest_types, &t), EDestNotAllowed);
}

/// Registry-paused assertion. Called from `vault::receive_*` v2 if/when
/// those are wired. Exposed for external composability.
public(package) fun assert_not_paused(registry: &AutoSwapRegistryV2) {
    assert!(!registry.paused, ERegistryPaused);
}

// ───────────────────────────────────────────────────────────────────
// Direct v2 cap mint — package-private; only `vault::enable_auto_swap_v2`
// calls this after asserting `ctx.sender() == vault.owner`. Same
// "minter must own the vault" gate as v1 `mint_cap`.

public(package) fun new_cap_v2<T>(
    vault_id: ID,
    owner: address,
    max_per_swap: u64,
    max_per_day: u64,
    expires_at_ms: u64,
    clock: &Clock,
    ctx: &mut TxContext,
): AutoSwapCapV2<T> {
    assert!(max_per_swap > 0, EInvalidMax);
    assert!(max_per_day > 0, EInvalidMaxPerDay);
    assert!(max_per_day >= max_per_swap, EInvalidMaxPerDay);

    let now = clock.timestamp_ms();
    let cap = AutoSwapCapV2<T> {
        id: object::new(ctx),
        vault_id,
        owner,
        max_per_swap,
        expires_at_ms,
        paused: false,
        max_per_day,
        used_today: 0,
        day_reset_at_ms: now + DAY_MS,
    };

    event::emit(AutoSwapEnabled {
        owner,
        vault_id,
        cap_id: object::id(&cap),
        coin_type: type_name::with_defining_ids<T>().into_string().into_bytes(),
        max_per_swap,
        expires_at_ms,
    });

    cap
}

// ───────────────────────────────────────────────────────────────────
// Cap upgrade (user-signed migration v1 → v2)

/// Burn an existing v1 `AutoSwapCap<T>` and mint an equivalent
/// `AutoSwapCapV2<T>` with the v7 throttle fields. Caller must be the
/// recorded `cap.owner` — this is a user-initiated migration; the
/// operator cannot upgrade someone else's cap.
///
/// The new cap is shared so the worker can reference it in a PTB the
/// worker signs (same model as v3+ shared caps).
public fun upgrade_cap_to_v2<T>(
    cap: AutoSwapCap<T>,
    max_per_day: u64,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(ctx.sender() == cap.owner, ENotOwner);
    assert!(max_per_day > 0, EInvalidMaxPerDay);
    assert!(max_per_day >= cap.max_per_swap, EInvalidMaxPerDay);

    let AutoSwapCap {
        id: old_id,
        vault_id,
        owner,
        max_per_swap,
        expires_at_ms,
        paused,
    } = cap;
    let old_cap_id = old_id.to_inner();
    old_id.delete();

    let now = clock.timestamp_ms();
    let new_cap = AutoSwapCapV2<T> {
        id: object::new(ctx),
        vault_id,
        owner,
        max_per_swap,
        expires_at_ms,
        paused,
        max_per_day,
        used_today: 0,
        day_reset_at_ms: now + DAY_MS,
    };
    let new_cap_id = object::id(&new_cap);

    event::emit(CapV2Migrated { old_cap_id, new_cap_id, owner });

    transfer::share_object(new_cap);
}

// ───────────────────────────────────────────────────────────────────
// Internal role-check helpers

fun assert_admin(registry: &AutoSwapRegistryV2, ctx: &TxContext) {
    assert!(ctx.sender() == registry.admin, ENotAdmin);
}

fun assert_admin_or_oncall(registry: &AutoSwapRegistryV2, ctx: &TxContext) {
    let s = ctx.sender();
    let ok = s == registry.admin
        || vector::contains(&registry.oncall_addresses, &s);
    assert!(ok, ENotAdminOrOncall);
}

fun assert_admin_or_treasury(registry: &AutoSwapRegistryV2, ctx: &TxContext) {
    let s = ctx.sender();
    let ok = s == registry.admin
        || vector::contains(&registry.treasury_addresses, &s);
    assert!(ok, ENotAdminOrTreasury);
}

// ───────────────────────────────────────────────────────────────────
// v7 read accessors

public fun v2_admin(r: &AutoSwapRegistryV2): address { r.admin }
public fun v2_paused(r: &AutoSwapRegistryV2): bool { r.paused }
public fun v2_admin_transfer_delay_ms(r: &AutoSwapRegistryV2): u64 {
    r.admin_transfer_delay_ms
}
public fun v2_total_validations(r: &AutoSwapRegistryV2): u64 {
    r.total_validations
}
public fun v2_workers(r: &AutoSwapRegistryV2): &vector<address> {
    &r.worker_addresses
}
public fun v2_oncalls(r: &AutoSwapRegistryV2): &vector<address> {
    &r.oncall_addresses
}
public fun v2_treasuries(r: &AutoSwapRegistryV2): &vector<address> {
    &r.treasury_addresses
}
public fun v2_allowed_dests(r: &AutoSwapRegistryV2): &vector<TypeName> {
    &r.allowed_dest_types
}
public fun v2_allowed_providers(r: &AutoSwapRegistryV2): &vector<vector<u8>> {
    &r.allowed_providers
}
public fun v2_has_pending_admin_transfer(r: &AutoSwapRegistryV2): bool {
    option::is_some(&r.pending_admin_transfer)
}
public fun v2_has_pending_delay_change(r: &AutoSwapRegistryV2): bool {
    option::is_some(&r.pending_delay_change)
}

public fun cap_v2_owner<T>(c: &AutoSwapCapV2<T>): address { c.owner }
public fun cap_v2_vault<T>(c: &AutoSwapCapV2<T>): ID { c.vault_id }
public fun cap_v2_max_per_swap<T>(c: &AutoSwapCapV2<T>): u64 { c.max_per_swap }
public fun cap_v2_max_per_day<T>(c: &AutoSwapCapV2<T>): u64 { c.max_per_day }
public fun cap_v2_used_today<T>(c: &AutoSwapCapV2<T>): u64 { c.used_today }
public fun cap_v2_day_reset_at_ms<T>(c: &AutoSwapCapV2<T>): u64 {
    c.day_reset_at_ms
}
public fun cap_v2_expires_at_ms<T>(c: &AutoSwapCapV2<T>): u64 { c.expires_at_ms }
public fun cap_v2_paused<T>(c: &AutoSwapCapV2<T>): bool { c.paused }

// ───────────────────────────────────────────────────────────────────
// Test-only v7 shims

#[test_only]
public fun test_bootstrap_v7(ctx: &mut TxContext) { bootstrap_v7(ctx) }

#[test_only]
public fun test_validate_for_swap_v2<T>(
    registry: &mut AutoSwapRegistryV2,
    cap: &mut AutoSwapCapV2<T>,
    amount: u64,
    clock: &Clock,
    ctx: &TxContext,
) {
    validate_for_swap_v2<T>(registry, cap, amount, clock, ctx)
}

#[test_only]
public fun test_assert_dest_allowed<Dest>(registry: &AutoSwapRegistryV2) {
    assert_dest_allowed<Dest>(registry)
}
