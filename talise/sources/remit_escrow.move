/// Trustless off-ramp / remittance escrow with reclaim-on-timeout.
///
/// THE WEDGE. When a user cashes out USDsui → fiat (NGN via Paga, KES via
/// M-Pesa, …), their funds move into a per-transfer on-chain escrow keyed to
/// an off-ramp `transfer_id` BEFORE Talise dispatches any fiat. Three terminal
/// exits:
///   • worker `release` → Talise treasury (the commit point, once fiat settles)
///   • permissionless `reclaim` after `timeout_ms` → back to the SENDER (the
///     trustless refund: "your dollars come back if the cash-out fails" is a
///     guarantee the user can verify, not a promise)
///   • sender `cancel` before the worker engages
///
/// SAFETY — the release-vs-timeout race (the one place money can leak):
/// `reclaim` is permissionless after timeout, so a worker must NOT dispatch
/// fiat and then race a `release` against a reclaim. The `commit` step fixes
/// this: the worker calls `commit` (which permanently disables `reclaim`)
/// BEFORE dispatching fiat off-chain, then `release`. So once committed, the
/// user can never reclaim; and a user can only reclaim while UNcommitted (i.e.
/// before any fiat was sent). The two outcomes are mutually exclusive by
/// construction.
///
/// Modeled on `talise::cheque`'s registry/worker/escrow pattern. Generic over
/// `T` (the funding PTB picks USDsui). Gates the sender through
/// `talise::compliance` at open, and exposes a compliance-admin `freeze`.
module talise::remit_escrow;

use sui::{balance::{Self, Balance}, clock::Clock, coin::{Self, Coin}, event};
use talise::compliance::{Self, ComplianceRegistry, ComplianceAdminCap};

// ───────────────────────────────────────────────────────────────────
// Status

const STATUS_OPEN: u8 = 0;
const STATUS_RELEASED: u8 = 1;
const STATUS_RECLAIMED: u8 = 2;
const STATUS_CANCELLED: u8 = 3;

// ───────────────────────────────────────────────────────────────────
// Errors

const EZeroAmount: u64 = 720;
const EBadTimeout: u64 = 721;
const ENotWorker: u64 = 722;
const ERegistryPaused: u64 = 723;
const ENotOpen: u64 = 724;
const ECommitted: u64 = 725;
const ENotCommitted: u64 = 726;
const ENotTimedOut: u64 = 727;
const ENotSender: u64 = 728;
const EFrozen: u64 = 729;
const EWorkerAlreadyAdded: u64 = 730;
const EWorkerNotFound: u64 = 731;

// ───────────────────────────────────────────────────────────────────
// Objects

public struct RemitRegistry has key {
    id: UID,
    admin: address,
    /// Where released funds settle (Talise's off-ramp treasury). Set by admin.
    treasury: address,
    worker_addresses: vector<address>,
    paused: bool,
    total_opened: u64,
}

public struct RemitAdminCap has key, store { id: UID }

/// One shared object per cash-out. Holds the funds as `Balance<T>` until a
/// terminal exit. `committed` disables reclaim (set before fiat dispatch);
/// `frozen` is a compliance/court hold that blocks release AND reclaim.
public struct RemitEscrow<phantom T> has key {
    id: UID,
    sender: address,
    escrow: Balance<T>,
    amount: u64,
    /// Ties this on-chain escrow to the off-ramp DB state machine row.
    transfer_id: vector<u8>,
    created_ms: u64,
    timeout_ms: u64,
    status: u8,
    committed: bool,
    frozen: bool,
}

// ───────────────────────────────────────────────────────────────────
// Events

public struct EscrowOpened has copy, drop {
    escrow_id: ID,
    sender: address,
    amount: u64,
    transfer_id: vector<u8>,
    timeout_ms: u64,
}
public struct EscrowCommitted has copy, drop { escrow_id: ID }
public struct EscrowReleased has copy, drop { escrow_id: ID, treasury: address, amount: u64 }
public struct EscrowReclaimed has copy, drop { escrow_id: ID, sender: address, amount: u64 }
public struct EscrowCancelled has copy, drop { escrow_id: ID, sender: address, amount: u64 }
public struct EscrowFrozen has copy, drop { escrow_id: ID }
public struct EscrowUnfrozen has copy, drop { escrow_id: ID }
public struct WorkerAdded has copy, drop { worker: address }
public struct WorkerRemoved has copy, drop { worker: address }
public struct TreasuryChanged has copy, drop { treasury: address }

// ───────────────────────────────────────────────────────────────────
// Bootstrap

fun init(ctx: &mut TxContext) {
    transfer::share_object(RemitRegistry {
        id: object::new(ctx),
        admin: ctx.sender(),
        treasury: ctx.sender(), // placeholder until set_treasury
        worker_addresses: vector[],
        paused: false,
        total_opened: 0,
    });
    transfer::public_transfer(RemitAdminCap { id: object::new(ctx) }, ctx.sender());
}

public fun add_worker(registry: &mut RemitRegistry, _cap: &RemitAdminCap, worker: address) {
    assert!(!registry.worker_addresses.contains(&worker), EWorkerAlreadyAdded);
    registry.worker_addresses.push_back(worker);
    event::emit(WorkerAdded { worker });
}

public fun remove_worker(registry: &mut RemitRegistry, _cap: &RemitAdminCap, worker: address) {
    let (found, idx) = registry.worker_addresses.index_of(&worker);
    assert!(found, EWorkerNotFound);
    registry.worker_addresses.remove(idx);
    event::emit(WorkerRemoved { worker });
}

public fun set_paused(registry: &mut RemitRegistry, _cap: &RemitAdminCap, paused: bool) {
    registry.paused = paused;
}

public fun set_treasury(registry: &mut RemitRegistry, _cap: &RemitAdminCap, treasury: address) {
    registry.treasury = treasury;
    event::emit(TreasuryChanged { treasury });
}

// ───────────────────────────────────────────────────────────────────
// Open (sender-signed funding PTB)

/// Lock `funds` into a new escrow for an off-ramp. Screens the sender through
/// compliance. Returns the escrow id so the server can bind it to the payout
/// row. `timeout_ms` is a wall-clock deadline after which an unclaimed,
/// uncommitted escrow can be reclaimed by anyone back to the sender.
public fun open<T>(
    registry: &mut RemitRegistry,
    compliance_reg: &ComplianceRegistry,
    funds: Balance<T>,
    transfer_id: vector<u8>,
    timeout_ms: u64,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    assert!(!registry.paused, ERegistryPaused);
    let amount = balance::value(&funds);
    assert!(amount > 0, EZeroAmount);
    assert!(timeout_ms > clock.timestamp_ms(), EBadTimeout);
    compliance::assert_clear(compliance_reg, ctx.sender());

    let esc = RemitEscrow<T> {
        id: object::new(ctx),
        sender: ctx.sender(),
        escrow: funds,
        amount,
        transfer_id,
        created_ms: clock.timestamp_ms(),
        timeout_ms,
        status: STATUS_OPEN,
        committed: false,
        frozen: false,
    };
    let eid = object::id(&esc);
    registry.total_opened = registry.total_opened + 1;
    event::emit(EscrowOpened {
        escrow_id: eid,
        sender: esc.sender,
        amount,
        transfer_id: esc.transfer_id,
        timeout_ms,
    });
    transfer::share_object(esc);
    eid
}

// ───────────────────────────────────────────────────────────────────
// Commit → Release (worker-signed)

/// Worker-only. MUST be called before dispatching fiat off-chain. Permanently
/// disables `reclaim` for this escrow, closing the release-vs-timeout race.
public fun commit<T>(registry: &RemitRegistry, esc: &mut RemitEscrow<T>, ctx: &TxContext) {
    assert!(!registry.paused, ERegistryPaused);
    assert!(registry.worker_addresses.contains(&ctx.sender()), ENotWorker);
    assert!(esc.status == STATUS_OPEN, ENotOpen);
    assert!(!esc.frozen, EFrozen);
    assert!(!esc.committed, ECommitted);
    esc.committed = true;
    event::emit(EscrowCommitted { escrow_id: object::id(esc) });
}

/// Worker-only. Settles the escrow to the treasury. Requires a prior `commit`
/// so funds can never both pay fiat AND be reclaimed.
public fun release<T>(registry: &RemitRegistry, esc: &mut RemitEscrow<T>, ctx: &mut TxContext) {
    assert!(!registry.paused, ERegistryPaused);
    assert!(registry.worker_addresses.contains(&ctx.sender()), ENotWorker);
    assert!(esc.status == STATUS_OPEN, ENotOpen);
    assert!(!esc.frozen, EFrozen);
    assert!(esc.committed, ENotCommitted);

    esc.status = STATUS_RELEASED;
    let out = balance::withdraw_all(&mut esc.escrow);
    let amount = balance::value(&out);
    transfer::public_transfer(coin::from_balance(out, ctx), registry.treasury);
    event::emit(EscrowReleased { escrow_id: object::id(esc), treasury: registry.treasury, amount });
}

// ───────────────────────────────────────────────────────────────────
// Reclaim (PERMISSIONLESS, after timeout) / Cancel (sender, pre-commit)

/// Permissionless safety valve: after `timeout_ms`, if the escrow was never
/// committed (so no fiat was dispatched), ANYONE can return the funds to the
/// SENDER. Funds go to `esc.sender`, never to the caller — so a third party
/// can rescue a stuck user but can't steal. This is the trustless refund.
public fun reclaim<T>(esc: &mut RemitEscrow<T>, clock: &Clock, ctx: &mut TxContext) {
    assert!(esc.status == STATUS_OPEN, ENotOpen);
    assert!(!esc.committed, ECommitted);
    assert!(!esc.frozen, EFrozen);
    assert!(clock.timestamp_ms() >= esc.timeout_ms, ENotTimedOut);

    esc.status = STATUS_RECLAIMED;
    let out = balance::withdraw_all(&mut esc.escrow);
    let amount = balance::value(&out);
    transfer::public_transfer(coin::from_balance(out, ctx), esc.sender);
    event::emit(EscrowReclaimed { escrow_id: object::id(esc), sender: esc.sender, amount });
}

/// Sender-only cancel before the worker engages (uncommitted). Returns the
/// `Coin<T>` so the sender's PTB can route it.
public fun cancel<T>(esc: &mut RemitEscrow<T>, ctx: &mut TxContext): Coin<T> {
    assert!(ctx.sender() == esc.sender, ENotSender);
    assert!(esc.status == STATUS_OPEN, ENotOpen);
    assert!(!esc.committed, ECommitted);
    assert!(!esc.frozen, EFrozen);

    esc.status = STATUS_CANCELLED;
    let out = balance::withdraw_all(&mut esc.escrow);
    let amount = balance::value(&out);
    event::emit(EscrowCancelled { escrow_id: object::id(esc), sender: esc.sender, amount });
    coin::from_balance(out, ctx)
}

// ───────────────────────────────────────────────────────────────────
// Compliance freeze (court order) — blocks release AND reclaim

public fun compliance_freeze<T>(esc: &mut RemitEscrow<T>, _cap: &ComplianceAdminCap) {
    esc.frozen = true;
    event::emit(EscrowFrozen { escrow_id: object::id(esc) });
}

public fun compliance_unfreeze<T>(esc: &mut RemitEscrow<T>, _cap: &ComplianceAdminCap) {
    esc.frozen = false;
    event::emit(EscrowUnfrozen { escrow_id: object::id(esc) });
}

// ───────────────────────────────────────────────────────────────────
// Read-only views

public fun status<T>(esc: &RemitEscrow<T>): u8 { esc.status }
public fun is_committed<T>(esc: &RemitEscrow<T>): bool { esc.committed }
public fun is_frozen<T>(esc: &RemitEscrow<T>): bool { esc.frozen }
public fun amount<T>(esc: &RemitEscrow<T>): u64 { esc.amount }
public fun sender<T>(esc: &RemitEscrow<T>): address { esc.sender }
public fun escrow_value<T>(esc: &RemitEscrow<T>): u64 { balance::value(&esc.escrow) }
public fun treasury(registry: &RemitRegistry): address { registry.treasury }
public fun registry_paused(registry: &RemitRegistry): bool { registry.paused }
public fun is_worker(registry: &RemitRegistry, addr: address): bool {
    registry.worker_addresses.contains(&addr)
}

// status constant accessors (for off-chain / tests)
public fun status_open(): u8 { STATUS_OPEN }
public fun status_released(): u8 { STATUS_RELEASED }
public fun status_reclaimed(): u8 { STATUS_RECLAIMED }
public fun status_cancelled(): u8 { STATUS_CANCELLED }

// ───────────────────────────────────────────────────────────────────
// Test-only

#[test_only]
public fun test_init(ctx: &mut TxContext) { init(ctx) }
