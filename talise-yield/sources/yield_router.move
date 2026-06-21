/// Talise Yield Router — autonomous, capped, non-custodial rotation across
/// the safest Sui USDC venues (Suilend, NAVI, AlphaLend, Scallop).
///
/// On-chain anchor for the Phase-2 "mint an object that routes through the
/// best venue and rotates" engine (see docs/strategy/YIELD-ROUTER.md). Mirrors
/// the ALREADY-AUDITED trust model of `talise::vault` + `talise::auto_swap`:
///
///   • `YieldPosition` — a shared object the user MINTS (one per user). It
///     custodies each venue's RECEIPT (Suilend `Obligation`, NAVI `AccountCap`,
///     Scallop `sUSDC` coin, AlphaLend position) under a dynamic OBJECT field
///     keyed by venue id. The money therefore always lives inside the audited
///     venue protocol — never as raw cash Talise controls. `basis_usdc` tracks
///     cost basis so earned = value − basis is honest + churn-proof. The
///     CAPPED rebalance authority (per-rotation + rolling-24h limits, expiry,
///     owner pause) lives INLINE on the position — there is no separately
///     shared capability object for anyone to grab.
///
///   • `RebalanceRegistry` — admin-owned set of authorized keeper addresses +
///     a per-venue circuit breaker. Rotation requires the caller to be a
///     registered worker; a paused venue can be rotated OUT of, never INTO.
///
///   • `RotationTicket` — a hot potato (NO abilities) that brackets every
///     rotation. `begin_rotation` hands out the source receipt + the ticket;
///     the keeper's PTB composes `<venueA>::withdraw → USDC → <venueB>::deposit`;
///     `end_rotation` consumes the ticket and stores the new receipt back under
///     the SAME position. The PTB will not type-check unless the rotation closes
///     back into the position — exactly the `SwapTicket` discipline in vault.move.
///
/// TRUST MODEL (identical to auto_swap, stated plainly for the audit):
///   The keeper key is Talise's; the per-rotation + per-day caps bound the
///   worst case; the owner can `pause`/`disable_rebalance` any time; the venue
///   allowlist + circuit breaker live in the registry. The keeper cannot send
///   funds to an arbitrary address (the ticket forces the receipt back into the
///   position), but — as with auto_swap — a *compromised* keeper could rotate
///   into an allowlisted venue sub-optimally; the caps bound that. Trustless
///   hardening (min-output assertion via a per-venue value read) is a documented
///   v2 item and a primary audit focus. NOT FOR MAINNET until audited +
///   testnet-proven.
module talise_yield::yield_router;

use sui::{dynamic_object_field as dof, clock::Clock, event};

// ───────────────────────────────────────────────────────────────────
// Errors
const ENotOwner: u64 = 400;
const EWrongPosition: u64 = 401;
const ERebalancePaused: u64 = 402;
const ERebalanceExpired: u64 = 403;
const EAmountExceedsCap: u64 = 404;
const EDailyCapExceeded: u64 = 405;
const EWrongWorker: u64 = 406;
const EVenueNotAllowed: u64 = 407;
const EVenuePaused: u64 = 408;
const ENoReceipt: u64 = 409;
const ESameVenue: u64 = 410;
const EZeroAmount: u64 = 411;
const ERebalanceDisabled: u64 = 412;

// ───────────────────────────────────────────────────────────────────
// Venue ids — the fixed allowlist (security-ranked; see YIELD-ROUTER.md).
// Adding a venue is a deliberate code change, never config.
const VENUE_SUILEND: u8 = 1;
const VENUE_NAVI: u8 = 2;
const VENUE_ALPHALEND: u8 = 3;
const VENUE_SCALLOP: u8 = 4;

fun is_known_venue(v: u8): bool {
    v == VENUE_SUILEND || v == VENUE_NAVI || v == VENUE_ALPHALEND || v == VENUE_SCALLOP
}

// ───────────────────────────────────────────────────────────────────
// Objects

/// One per user. Shared so the keeper's PTB can reference it, but every state
/// change is gated by either `owner` (deposit/withdraw/config) or a registered
/// worker honoring the inline rebalance caps (rotation). Venue receipts are
/// stored as dynamic OBJECT fields keyed by `venue id (u8)`.
public struct YieldPosition has key {
    id: UID,
    owner: address,
    /// Tracked USDC cost basis across all venues → honest earned accounting.
    basis_usdc: u64,
    /// Bitset of venue ids that currently hold a receipt (cheap "where am I").
    active_venues: u8,
    rotations_total: u64,
    // ── Inline rebalance authority (replaces a shared cap object) ──
    /// Owner opted into keeper rotation. False → `begin_rotation` aborts.
    rebalance_enabled: bool,
    /// Owner kill switch, independent of `rebalance_enabled`.
    rebalance_paused: bool,
    /// Max USDC moved in a single rotation.
    max_per_rotation: u64,
    /// Rolling 24h cap + its accounting window.
    max_per_day: u64,
    used_today: u64,
    day_start_ms: u64,
    /// Authority expiry; the owner re-arms by calling `enable_rebalance` again.
    expires_at_ms: u64,
}

/// Registry of keeper workers + the venue circuit-breaker. Admin-owned.
public struct RebalanceRegistry has key {
    id: UID,
    admin: address,
    /// Authorized keeper addresses (multi-worker, like AutoSwapRegistryV2).
    workers: vector<address>,
    /// Bitset of venue ids that are PAUSED (circuit breaker). A paused venue
    /// may be rotated OUT of, never INTO. Scallop ships breaker-eligible.
    paused_venues: u8,
}

/// Hot potato. Produced by `begin_rotation`, consumed by `end_rotation`.
/// No abilities — the only thing the runtime can do is hand it to
/// `end_rotation` before the tx ends, which forces the keeper to close the
/// rotation back into the same position rather than walk away mid-move.
public struct RotationTicket {
    position_id: ID,
    from_venue: u8,
    to_venue: u8,
    /// USDC notional authorized for this rotation (bounds + event).
    amount: u64,
}

// ───────────────────────────────────────────────────────────────────
// Events
public struct PositionMinted has copy, drop { position_id: ID, owner: address }
public struct ReceiptDeposited has copy, drop { position_id: ID, venue: u8, basis_added: u64 }
public struct ReceiptRemoved has copy, drop { position_id: ID, venue: u8 }
public struct Rotated has copy, drop { position_id: ID, from_venue: u8, to_venue: u8, amount: u64, ts_ms: u64 }

// ───────────────────────────────────────────────────────────────────
// Position lifecycle

/// MINT a position for the caller. This is the object the user creates to
/// opt into routed yield. Shared so the keeper can reference it; owner-gated
/// for every value-moving op. Rebalance authority starts DISABLED — the owner
/// arms it explicitly via `enable_rebalance`.
public fun mint_position(ctx: &mut TxContext) {
    let pos = YieldPosition {
        id: object::new(ctx),
        owner: ctx.sender(),
        basis_usdc: 0,
        active_venues: 0,
        rotations_total: 0,
        rebalance_enabled: false,
        rebalance_paused: false,
        max_per_rotation: 0,
        max_per_day: 0,
        used_today: 0,
        day_start_ms: 0,
        expires_at_ms: 0,
    };
    event::emit(PositionMinted { position_id: object::id(&pos), owner: ctx.sender() });
    transfer::share_object(pos);
}

/// Owner stores a venue receipt under the position after a (user-signed)
/// deposit PTB has supplied USDC into `venue` and obtained `receipt`.
/// `R` is the venue's receipt type (Obligation / sUSDC coin / AccountCap / …).
public fun deposit_receipt<R: key + store>(
    pos: &mut YieldPosition,
    receipt: R,
    venue: u8,
    basis_usdc: u64,
    ctx: &TxContext,
) {
    assert!(ctx.sender() == pos.owner, ENotOwner);
    assert!(is_known_venue(venue), EVenueNotAllowed);
    dof::add(&mut pos.id, venue, receipt);
    pos.active_venues = pos.active_venues | venue_bit(venue);
    pos.basis_usdc = pos.basis_usdc + basis_usdc;
    event::emit(ReceiptDeposited { position_id: object::id(pos), venue, basis_added: basis_usdc });
}

/// Owner pulls a venue receipt back out (to run a user-signed withdraw/exit
/// PTB). Reduces tracked basis by `basis_removed` (the SDK passes the slice
/// being exited). Returns the receipt for downstream PTB composition.
public fun take_receipt<R: key + store>(
    pos: &mut YieldPosition,
    venue: u8,
    basis_removed: u64,
    ctx: &TxContext,
): R {
    assert!(ctx.sender() == pos.owner, ENotOwner);
    assert!(dof::exists_with_type<u8, R>(&pos.id, venue), ENoReceipt);
    let receipt: R = dof::remove(&mut pos.id, venue);
    pos.active_venues = pos.active_venues & (0xFF ^ venue_bit(venue));
    pos.basis_usdc = if (basis_removed >= pos.basis_usdc) 0 else pos.basis_usdc - basis_removed;
    event::emit(ReceiptRemoved { position_id: object::id(pos), venue });
    receipt
}

// ───────────────────────────────────────────────────────────────────
// Rebalance authority — owner controls (inline on the position)

/// Owner arms (or re-arms) keeper rotation with fresh caps + expiry. We have
/// `&mut YieldPosition` and assert `sender == owner`, so the authority can
/// only ever be set on the caller's OWN position — there is no separate cap
/// object that could be minted against, or shared for, someone else's position.
public fun enable_rebalance(
    pos: &mut YieldPosition,
    max_per_rotation: u64,
    max_per_day: u64,
    expires_at_ms: u64,
    clock: &Clock,
    ctx: &TxContext,
) {
    assert!(ctx.sender() == pos.owner, ENotOwner);
    pos.rebalance_enabled = true;
    pos.rebalance_paused = false;
    pos.max_per_rotation = max_per_rotation;
    pos.max_per_day = max_per_day;
    pos.used_today = 0;
    pos.day_start_ms = clock.timestamp_ms();
    pos.expires_at_ms = expires_at_ms;
}

/// Owner-only kill switch + resume + hard disable.
public fun pause(pos: &mut YieldPosition, ctx: &TxContext) {
    assert!(ctx.sender() == pos.owner, ENotOwner);
    pos.rebalance_paused = true;
}
public fun resume(pos: &mut YieldPosition, ctx: &TxContext) {
    assert!(ctx.sender() == pos.owner, ENotOwner);
    pos.rebalance_paused = false;
}
public fun disable_rebalance(pos: &mut YieldPosition, ctx: &TxContext) {
    assert!(ctx.sender() == pos.owner, ENotOwner);
    pos.rebalance_enabled = false;
}

// ───────────────────────────────────────────────────────────────────
// Rotation — keeper-signed, bracketed by the hot potato

/// Begin a rotation: validate worker + the inline caps + venue allowlist,
/// remove the SOURCE receipt, and hand it back alongside a `RotationTicket`.
/// The keeper's PTB then composes `<from>::withdraw → USDC → <to>::deposit`
/// and MUST call `end_rotation` to store the new receipt + consume the ticket.
public fun begin_rotation<R: key + store>(
    pos: &mut YieldPosition,
    registry: &RebalanceRegistry,
    from_venue: u8,
    to_venue: u8,
    amount: u64,
    clock: &Clock,
    ctx: &TxContext,
): (R, RotationTicket) {
    // Authority + bounds (mirrors auto_swap::validate_for_swap_v2).
    assert!(registry.workers.contains(&ctx.sender()), EWrongWorker);
    assert!(pos.rebalance_enabled, ERebalanceDisabled);
    assert!(!pos.rebalance_paused, ERebalancePaused);
    let now = clock.timestamp_ms();
    assert!(now < pos.expires_at_ms, ERebalanceExpired);
    assert!(amount > 0, EZeroAmount);
    assert!(amount <= pos.max_per_rotation, EAmountExceedsCap);

    // Rolling 24h throttle with overflow-safe accounting.
    if (now >= pos.day_start_ms + 86_400_000) {
        pos.day_start_ms = now;
        pos.used_today = 0;
    };
    assert!(pos.used_today <= pos.max_per_day, EDailyCapExceeded);
    assert!(amount <= pos.max_per_day - pos.used_today, EDailyCapExceeded);
    pos.used_today = pos.used_today + amount;

    // Venue allowlist + circuit breaker: may rotate OUT of a paused venue,
    // never INTO one.
    assert!(is_known_venue(from_venue) && is_known_venue(to_venue), EVenueNotAllowed);
    assert!(from_venue != to_venue, ESameVenue);
    assert!(registry.paused_venues & venue_bit(to_venue) == 0, EVenuePaused);
    assert!(dof::exists_with_type<u8, R>(&pos.id, from_venue), ENoReceipt);

    let receipt: R = dof::remove(&mut pos.id, from_venue);
    pos.active_venues = pos.active_venues & (0xFF ^ venue_bit(from_venue));

    let ticket = RotationTicket { position_id: object::id(pos), from_venue, to_venue, amount };
    (receipt, ticket)
}

/// Close a rotation: store the destination receipt and consume the ticket.
/// Asserts the ticket was issued for THIS position — funds cannot land in a
/// different position inside the same PTB (the `SwapTicket` same-vault check).
public fun end_rotation<R2: key + store>(
    pos: &mut YieldPosition,
    new_receipt: R2,
    ticket: RotationTicket,
    clock: &Clock,
) {
    let RotationTicket { position_id, from_venue, to_venue, amount } = ticket;
    assert!(position_id == object::id(pos), EWrongPosition);
    dof::add(&mut pos.id, to_venue, new_receipt);
    pos.active_venues = pos.active_venues | venue_bit(to_venue);
    pos.rotations_total = pos.rotations_total + 1;
    event::emit(Rotated { position_id: object::id(pos), from_venue, to_venue, amount, ts_ms: clock.timestamp_ms() });
}

// ───────────────────────────────────────────────────────────────────
// Registry admin (worker set + circuit breaker)

public fun new_registry(ctx: &mut TxContext) {
    transfer::share_object(RebalanceRegistry {
        id: object::new(ctx), admin: ctx.sender(), workers: vector[], paused_venues: 0,
    });
}
public fun add_worker(reg: &mut RebalanceRegistry, worker: address, ctx: &TxContext) {
    assert!(ctx.sender() == reg.admin, ENotOwner);
    if (!reg.workers.contains(&worker)) reg.workers.push_back(worker);
}
public fun set_venue_paused(reg: &mut RebalanceRegistry, venue: u8, paused: bool, ctx: &TxContext) {
    assert!(ctx.sender() == reg.admin, ENotOwner);
    assert!(is_known_venue(venue), EVenueNotAllowed);
    reg.paused_venues = if (paused) reg.paused_venues | venue_bit(venue)
        else reg.paused_venues & (0xFF ^ venue_bit(venue));
}

// ───────────────────────────────────────────────────────────────────
// Helpers + reads

fun venue_bit(v: u8): u8 { 1u8 << ((v - 1) as u8) }

public fun owner(pos: &YieldPosition): address { pos.owner }
public fun basis_usdc(pos: &YieldPosition): u64 { pos.basis_usdc }
public fun active_venues(pos: &YieldPosition): u8 { pos.active_venues }
public fun rotations_total(pos: &YieldPosition): u64 { pos.rotations_total }
public fun rebalance_enabled(pos: &YieldPosition): bool { pos.rebalance_enabled }
#[allow(deprecated_usage)]
public fun holds(pos: &YieldPosition, venue: u8): bool { dof::exists_(&pos.id, venue) }
