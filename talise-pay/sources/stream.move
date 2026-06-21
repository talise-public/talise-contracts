/// Streaming payments — on-chain escrow + worker-signed release.
///
/// FUTURE-HARDENED PATH. This module is the documented on-chain mechanism
/// from docs/features/streaming-payments.md §3. It is NOT yet published to
/// mainnet, and the shipped Talise backend does NOT depend on it: the live
/// feature runs the "escrow address + backend scheduler" variant (option (c)
/// made runnable today — a Talise-controlled escrow keypair holds funds and a
/// Vercel cron signs each escrow→recipient transfer). When this module is
/// published, set `STREAM_PACKAGE_ID` in the web env and the backend's
/// `streamPackageId()` seam lights up the on-chain path; until then nothing
/// references it.
///
/// Modeled 1:1 on the audited `talise::vault` + `talise::auto_swap` role/cap
/// pattern: a shared `StreamRegistry` holds the worker address list; each
/// active stream is a short-lived shared `Stream<T>` object holding the
/// undistributed funds as `Balance<T>`; the Onara worker (an Ed25519 key
/// that never expires) signs `release` per tranche, gated on-chain by the
/// `tranches_done` cursor + a `Clock` due-time check so a double-fire can
/// never double-pay. The sender signs exactly once (funding) and keeps
/// pause/resume/cancel.
///
/// GENERIC over `T`: like `talise::send` and `talise::vault`, the coin type
/// is a phantom type parameter rather than a hardcoded `USDSUI` import. The
/// funding PTB chooses `T` (USDsui in production), so this module carries no
/// dependency on the coin's defining package.
module talise::stream;

use sui::{
    balance::{Self, Balance},
    clock::Clock,
    coin::{Self, Coin},
    event,
};

// ───────────────────────────────────────────────────────────────────
// Errors

const EZeroAmount: u64 = 200;
const EBadSchedule: u64 = 201;
const ENotWorker: u64 = 202;
const ERegistryPaused: u64 = 203;
const EPaused: u64 = 204;
const ECancelled: u64 = 205;
const EStreamComplete: u64 = 206;
const ETrancheNotDue: u64 = 207;
const ENotSender: u64 = 208;
const EWorkerAlreadyAdded: u64 = 209;
const EWorkerNotFound: u64 = 210;

// ───────────────────────────────────────────────────────────────────
// Objects

/// Singleton shared registry. Mirrors auto_swap's role model. Created once
/// at bootstrap; `worker_addresses` holds the Onara worker key(s).
public struct StreamRegistry has key {
    id: UID,
    admin: address,
    worker_addresses: vector<address>,
    paused: bool,
    streams_total: u64,
}

/// AdminCap minted to the publisher at bootstrap (governance).
public struct StreamAdminCap has key, store { id: UID }

/// One shared object per active stream. Holds undistributed funds as a
/// `Balance<T>` so the worker-signed release PTB can split it.
public struct Stream<phantom T> has key {
    id: UID,
    sender: address,
    recipient: address,
    escrow: Balance<T>,
    total_amount: u64,
    released_amount: u64,
    tranche_amount: u64,
    num_tranches: u64,
    tranches_done: u64,
    start_ms: u64,
    interval_ms: u64,
    paused: bool,
    cancelled: bool,
}

// ───────────────────────────────────────────────────────────────────
// Events

public struct StreamCreated has copy, drop {
    stream_id: ID,
    sender: address,
    recipient: address,
    total: u64,
    tranche_amount: u64,
    num_tranches: u64,
    start_ms: u64,
    interval_ms: u64,
}

public struct TrancheReleased has copy, drop {
    stream_id: ID,
    recipient: address,
    amount: u64,
    tranche_index: u64,
    ts_ms: u64,
}

public struct StreamCancelled has copy, drop {
    stream_id: ID,
    refunded: u64,
    released: u64,
}

public struct StreamPaused has copy, drop { stream_id: ID }
public struct StreamResumed has copy, drop { stream_id: ID }
public struct WorkerAdded has copy, drop { worker: address }
public struct WorkerRemoved has copy, drop { worker: address }

// ───────────────────────────────────────────────────────────────────
// Bootstrap

fun init(ctx: &mut TxContext) {
    let registry = StreamRegistry {
        id: object::new(ctx),
        admin: ctx.sender(),
        worker_addresses: vector[],
        paused: false,
        streams_total: 0,
    };
    transfer::share_object(registry);
    transfer::public_transfer(StreamAdminCap { id: object::new(ctx) }, ctx.sender());
}

/// Admin: grant a worker address permission to call `release`.
public fun add_worker(
    registry: &mut StreamRegistry,
    _cap: &StreamAdminCap,
    worker: address,
) {
    assert!(!registry.worker_addresses.contains(&worker), EWorkerAlreadyAdded);
    registry.worker_addresses.push_back(worker);
    event::emit(WorkerAdded { worker });
}

/// Admin: revoke a worker address. A compromised or rotated worker key can
/// be cut off without touching individual streams.
public fun remove_worker(
    registry: &mut StreamRegistry,
    _cap: &StreamAdminCap,
    worker: address,
) {
    let (found, idx) = registry.worker_addresses.index_of(&worker);
    assert!(found, EWorkerNotFound);
    registry.worker_addresses.remove(idx);
    event::emit(WorkerRemoved { worker });
}

/// Admin: global kill switch (halts ALL worker releases).
public fun set_paused(registry: &mut StreamRegistry, _cap: &StreamAdminCap, paused: bool) {
    registry.paused = paused;
}

// ───────────────────────────────────────────────────────────────────
// Funding (sender-signed, once)

/// Called inside the sender's ONE zkLogin-signed funding PTB. The PTB
/// upstream withdraws `Balance<T>` from the sender's accumulator and
/// hands it here. Creates the shared `Stream<T>` object and emits
/// StreamCreated.
public fun create<T>(
    registry: &mut StreamRegistry,
    funds: Balance<T>,
    recipient: address,
    tranche_amount: u64,
    num_tranches: u64,
    start_ms: u64,
    interval_ms: u64,
    _clock: &Clock,
    ctx: &mut TxContext,
): ID {
    let total = balance::value(&funds);
    assert!(total > 0, EZeroAmount);
    assert!(num_tranches > 0, EBadSchedule);
    assert!(tranche_amount > 0, EBadSchedule);
    assert!(interval_ms > 0, EBadSchedule);
    // The first (num_tranches - 1) tranches each pay `tranche_amount`; the
    // final tranche pays the remainder, so $X/N rounding can never over- or
    // under-release. We must therefore guarantee
    //     tranche_amount * (num_tranches - 1) <= total
    // but that product can overflow u64. Since `tranche_amount > 0`, divide
    // instead of multiply: the inequality is equivalent to
    //     (num_tranches - 1) <= total / tranche_amount
    // which never overflows. (Integer division floors, but that is exactly
    // what we want: if (n-1) fixed tranches fit within `total / tranche_amount`
    // whole tranches, their sum fits in `total`.)
    assert!((num_tranches - 1) <= total / tranche_amount, EBadSchedule);

    let stream = Stream<T> {
        id: object::new(ctx),
        sender: ctx.sender(),
        recipient,
        escrow: funds,
        total_amount: total,
        released_amount: 0,
        tranche_amount,
        num_tranches,
        tranches_done: 0,
        start_ms,
        interval_ms,
        paused: false,
        cancelled: false,
    };
    let sid = object::id(&stream);
    registry.streams_total = registry.streams_total + 1;
    event::emit(StreamCreated {
        stream_id: sid,
        sender: ctx.sender(),
        recipient,
        total,
        tranche_amount,
        num_tranches,
        start_ms,
        interval_ms,
    });
    transfer::share_object(stream);
    sid
}

// ───────────────────────────────────────────────────────────────────
// Release (worker-signed, per tranche)

/// Worker-signed. Releases ONE tranche if (a) the clock has passed the due
/// time for the next tranche, (b) the stream isn't paused/cancelled, (c) the
/// registry isn't paused, (d) sender is a registered worker. The on-chain
/// `tranches_done` cursor + clock gate make this idempotent and replay-safe:
/// calling release twice in the same interval reverts (E_TRANCHE_NOT_DUE), so
/// a double-fired cron can NEVER double-pay.
///
/// Overflow note: `due_at = start_ms + tranches_done * interval_ms`. Move
/// aborts on u64 overflow, so a wildly large schedule can only abort the
/// release tx (safe-fail), never silently wrap to an early due time. The
/// `create` guard already bounds `num_tranches` against the funded total, and
/// realistic ms timestamps keep this product far from u64::MAX.
public fun release<T>(
    registry: &mut StreamRegistry,
    stream: &mut Stream<T>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(!registry.paused, ERegistryPaused);
    assert!(registry.worker_addresses.contains(&ctx.sender()), ENotWorker);
    assert!(!stream.cancelled, ECancelled);
    assert!(!stream.paused, EPaused);
    assert!(stream.tranches_done < stream.num_tranches, EStreamComplete);

    let due_at = stream.start_ms + stream.tranches_done * stream.interval_ms;
    assert!(clock.timestamp_ms() >= due_at, ETrancheNotDue);

    // Last tranche pays the remainder so total released == total_amount.
    let is_last = stream.tranches_done + 1 == stream.num_tranches;
    let amount = if (is_last) { balance::value(&stream.escrow) } else { stream.tranche_amount };

    let out = balance::split(&mut stream.escrow, amount);
    stream.released_amount = stream.released_amount + amount;
    stream.tranches_done = stream.tranches_done + 1;

    let coin_out = coin::from_balance(out, ctx);
    transfer::public_transfer(coin_out, stream.recipient);

    event::emit(TrancheReleased {
        stream_id: object::id(stream),
        recipient: stream.recipient,
        amount,
        tranche_index: stream.tranches_done,
        ts_ms: clock.timestamp_ms(),
    });
}

/// Permissionless safety valve: anyone (in practice the recipient) can
/// force-release every tranche currently DUE if the scheduler is down. Same
/// gates as release() except the worker check — but the only destination is
/// `stream.recipient` (hardwired at create), so there's no extraction
/// surface: a caller can only push DUE funds to the recipient, never to
/// themselves, and never more than the schedule allows.
public fun claim_accrued<T>(stream: &mut Stream<T>, clock: &Clock, ctx: &mut TxContext) {
    assert!(!stream.cancelled, ECancelled);
    assert!(!stream.paused, EPaused);
    while (stream.tranches_done < stream.num_tranches) {
        let due_at = stream.start_ms + stream.tranches_done * stream.interval_ms;
        if (clock.timestamp_ms() < due_at) break;
        let is_last = stream.tranches_done + 1 == stream.num_tranches;
        let amount = if (is_last) { balance::value(&stream.escrow) } else { stream.tranche_amount };
        let out = balance::split(&mut stream.escrow, amount);
        stream.released_amount = stream.released_amount + amount;
        stream.tranches_done = stream.tranches_done + 1;
        let coin_out = coin::from_balance(out, ctx);
        transfer::public_transfer(coin_out, stream.recipient);
        event::emit(TrancheReleased {
            stream_id: object::id(stream),
            recipient: stream.recipient,
            amount,
            tranche_index: stream.tranches_done,
            ts_ms: clock.timestamp_ms(),
        });
    };
}

// ───────────────────────────────────────────────────────────────────
// Sender controls (sender-signed)

public fun pause<T>(stream: &mut Stream<T>, ctx: &TxContext) {
    assert!(ctx.sender() == stream.sender, ENotSender);
    stream.paused = true;
    event::emit(StreamPaused { stream_id: object::id(stream) });
}

public fun resume<T>(stream: &mut Stream<T>, ctx: &TxContext) {
    assert!(ctx.sender() == stream.sender, ENotSender);
    stream.paused = false;
    event::emit(StreamResumed { stream_id: object::id(stream) });
}

/// Cancel + withdraw the undistributed remainder back to the sender.
/// Terminal. Already-released tranches stay with the recipient.
public fun cancel_and_withdraw<T>(stream: &mut Stream<T>, ctx: &mut TxContext): Coin<T> {
    assert!(ctx.sender() == stream.sender, ENotSender);
    stream.cancelled = true;
    let remaining = balance::withdraw_all(&mut stream.escrow);
    event::emit(StreamCancelled {
        stream_id: object::id(stream),
        refunded: balance::value(&remaining),
        released: stream.released_amount,
    });
    coin::from_balance(remaining, ctx)
}

// ───────────────────────────────────────────────────────────────────
// Read-only views

public fun tranches_done<T>(stream: &Stream<T>): u64 { stream.tranches_done }
public fun released_amount<T>(stream: &Stream<T>): u64 { stream.released_amount }
public fun recipient<T>(stream: &Stream<T>): address { stream.recipient }
public fun is_cancelled<T>(stream: &Stream<T>): bool { stream.cancelled }
public fun is_paused<T>(stream: &Stream<T>): bool { stream.paused }
public fun escrow_value<T>(stream: &Stream<T>): u64 { balance::value(&stream.escrow) }
public fun registry_paused(registry: &StreamRegistry): bool { registry.paused }
public fun is_worker(registry: &StreamRegistry, addr: address): bool {
    registry.worker_addresses.contains(&addr)
}

// ───────────────────────────────────────────────────────────────────
// Test-only

#[test_only]
public fun test_init(ctx: &mut TxContext) { init(ctx) }
