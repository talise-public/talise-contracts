/// Talise automations — an on-chain, NON-CUSTODIAL standing order ("rule").
///
/// A "rule" like *"pay rent $1,200 on the 1st"* or *"send mum $50 every week"*
/// is a `StandingOrder<T>`: a shared object that custodies the rule's pot as a
/// `Balance<T>` and the schedule. `execute_due` is PERMISSIONLESS — ANYONE may
/// call it once an interval comes due (the owner's own app, the recipient, a
/// public keeper). It releases exactly `amount_per` to the **hardwired**
/// `recipient` (set by the owner at creation) and advances the cursor. The
/// caller can NEVER send elsewhere, never more than the schedule allows, never
/// before `next_due_ms`, and never touch funds the owner hasn't deposited — the
/// contract itself is the guarantee, so no privileged scheduler key exists.
///
/// The owner keeps full control: `pause` / `resume`, `top_up` (add funds), and
/// `cancel` (stop + refund the entire remaining pot). When the pot can't cover
/// the next release the order simply idles until topped up or cancelled — funds
/// are never stranded (cancel always refunds the remainder).
///
/// Release is Clock-gated on `next_due_ms` and generalized from a fixed tranche
/// count to an open-ended schedule. The registry keeps only a global admin pause
/// (a circuit-breaker); `execute_due` needs no allowlist because the caller has
/// zero discretion over destination or amount.
///
/// GENERIC over `T` (USDsui in production) — the coin type is a phantom param,
/// so this package carries no dependency on the coin's defining package.
module talise_automations::standing_order;

use sui::{
    balance::{Self, Balance},
    clock::Clock,
    coin::{Self, Coin},
    event,
};

// ───────────────────────────────────────────────────────────────────
// Errors

const ERegistryPaused: u64 = 401;
const ENotOwner: u64 = 402;
const EPaused: u64 = 403;
const ECancelled: u64 = 404;
const EBadSchedule: u64 = 405;
const ENotDue: u64 = 406;
const EInsufficientPot: u64 = 407;
const EZeroAmount: u64 = 408;
const EWorkerExists: u64 = 409;
const EWorkerMissing: u64 = 410;
const ESelfPay: u64 = 411;

// ───────────────────────────────────────────────────────────────────
// Objects

/// Singleton shared registry — holds the worker allowlist + a global pause.
/// Mirrors `talise::stream::StreamRegistry`.
public struct AutomationRegistry has key {
    id: UID,
    admin: address,
    worker_addresses: vector<address>,
    paused: bool,
    orders_total: u64,
}

/// AdminCap minted to the publisher at bootstrap (governance).
public struct AutomationAdminCap has key, store { id: UID }

/// One shared object per rule. Holds the rule's undistributed pot as a
/// `Balance<T>`. `next_due_ms` is the cursor the worker checks against the Clock.
public struct StandingOrder<phantom T> has key {
    id: UID,
    owner: address,
    recipient: address,
    pot: Balance<T>,
    amount_per: u64,
    interval_ms: u64,
    next_due_ms: u64,
    released_total: u64,
    releases_done: u64,
    paused: bool,
    cancelled: bool,
}

// ───────────────────────────────────────────────────────────────────
// Events

public struct OrderCreated has copy, drop {
    order_id: ID,
    owner: address,
    recipient: address,
    amount_per: u64,
    interval_ms: u64,
    first_due_ms: u64,
    funded: u64,
}
public struct OrderExecuted has copy, drop {
    order_id: ID,
    recipient: address,
    amount: u64,
    release_index: u64,
    ts_ms: u64,
}
public struct OrderToppedUp has copy, drop { order_id: ID, added: u64, pot: u64 }
public struct OrderPaused has copy, drop { order_id: ID }
public struct OrderResumed has copy, drop { order_id: ID }
public struct OrderCancelled has copy, drop { order_id: ID, refunded: u64, released_total: u64 }
public struct WorkerAdded has copy, drop { worker: address }
public struct WorkerRemoved has copy, drop { worker: address }

// ───────────────────────────────────────────────────────────────────
// Bootstrap

fun init(ctx: &mut TxContext) {
    let registry = AutomationRegistry {
        id: object::new(ctx),
        admin: ctx.sender(),
        worker_addresses: vector[],
        paused: false,
        orders_total: 0,
    };
    transfer::share_object(registry);
    transfer::public_transfer(AutomationAdminCap { id: object::new(ctx) }, ctx.sender());
}

// ───────────────────────────────────────────────────────────────────
// Admin (cap-gated)

public fun add_worker(registry: &mut AutomationRegistry, _cap: &AutomationAdminCap, worker: address) {
    assert!(!registry.worker_addresses.contains(&worker), EWorkerExists);
    registry.worker_addresses.push_back(worker);
    event::emit(WorkerAdded { worker });
}

public fun remove_worker(registry: &mut AutomationRegistry, _cap: &AutomationAdminCap, worker: address) {
    let (found, i) = registry.worker_addresses.index_of(&worker);
    assert!(found, EWorkerMissing);
    registry.worker_addresses.remove(i);
    event::emit(WorkerRemoved { worker });
}

public fun set_paused(registry: &mut AutomationRegistry, _cap: &AutomationAdminCap, paused: bool) {
    registry.paused = paused;
}

// ───────────────────────────────────────────────────────────────────
// Create (owner-signed)

/// Create + fund a standing order and share it. `funds` is the initial pot
/// (may hold several releases' worth). The first release is due at
/// `first_due_ms` (the funding tx's sender becomes the immutable `owner`).
/// Returns the new order id; the server parses it from the tx's object changes.
public fun create<T>(
    registry: &mut AutomationRegistry,
    funds: Balance<T>,
    recipient: address,
    amount_per: u64,
    interval_ms: u64,
    first_due_ms: u64,
    ctx: &mut TxContext,
): ID {
    assert!(amount_per > 0, EZeroAmount);
    assert!(interval_ms > 0, EBadSchedule);
    assert!(recipient != ctx.sender(), ESelfPay);
    // Must fund at least one release so the order can ever fire.
    assert!(balance::value(&funds) >= amount_per, EInsufficientPot);

    let funded = balance::value(&funds);
    let order = StandingOrder<T> {
        id: object::new(ctx),
        owner: ctx.sender(),
        recipient,
        pot: funds,
        amount_per,
        interval_ms,
        next_due_ms: first_due_ms,
        released_total: 0,
        releases_done: 0,
        paused: false,
        cancelled: false,
    };
    let oid = object::id(&order);
    registry.orders_total = registry.orders_total + 1;
    event::emit(OrderCreated {
        order_id: oid,
        owner: order.owner,
        recipient,
        amount_per,
        interval_ms,
        first_due_ms,
        funded,
    });
    transfer::share_object(order);
    oid
}

// ───────────────────────────────────────────────────────────────────
// Execute (PERMISSIONLESS, Clock-gated)

/// Release one due payment. Callable by ANYONE — gated only on: registry not
/// paused, order active, now >= next_due_ms, and the pot can cover `amount_per`.
/// Advances `next_due_ms` by exactly one interval so cadence never drifts. The
/// ONLY destination is the hardwired `recipient` and the ONLY amount is the
/// owner-set `amount_per`, so the caller has zero discretion: triggering a due
/// release just executes what the owner already authorized. No scheduler key.
public fun execute_due<T>(
    registry: &AutomationRegistry,
    order: &mut StandingOrder<T>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(!registry.paused, ERegistryPaused);
    assert!(!order.cancelled, ECancelled);
    assert!(!order.paused, EPaused);
    assert!(clock.timestamp_ms() >= order.next_due_ms, ENotDue);
    assert!(balance::value(&order.pot) >= order.amount_per, EInsufficientPot);

    let amount = order.amount_per;
    let out = balance::split(&mut order.pot, amount);
    order.released_total = order.released_total + amount;
    order.releases_done = order.releases_done + 1;
    order.next_due_ms = order.next_due_ms + order.interval_ms;

    transfer::public_transfer(coin::from_balance(out, ctx), order.recipient);
    event::emit(OrderExecuted {
        order_id: object::id(order),
        recipient: order.recipient,
        amount,
        release_index: order.releases_done,
        ts_ms: clock.timestamp_ms(),
    });
}

// ───────────────────────────────────────────────────────────────────
// Owner controls (owner-signed)

/// Add funds to the pot (keep the rule running).
public fun top_up<T>(order: &mut StandingOrder<T>, funds: Balance<T>, ctx: &TxContext) {
    assert!(ctx.sender() == order.owner, ENotOwner);
    assert!(!order.cancelled, ECancelled);
    let added = balance::value(&funds);
    balance::join(&mut order.pot, funds);
    event::emit(OrderToppedUp { order_id: object::id(order), added, pot: balance::value(&order.pot) });
}

public fun pause<T>(order: &mut StandingOrder<T>, ctx: &TxContext) {
    assert!(ctx.sender() == order.owner, ENotOwner);
    order.paused = true;
    event::emit(OrderPaused { order_id: object::id(order) });
}

public fun resume<T>(order: &mut StandingOrder<T>, ctx: &TxContext) {
    assert!(ctx.sender() == order.owner, ENotOwner);
    order.paused = false;
    event::emit(OrderResumed { order_id: object::id(order) });
}

/// Cancel the rule and refund the ENTIRE remaining pot to the owner. Returns the
/// refund coin (the caller routes it; the owner-gating means only the owner can
/// trigger this). Idempotent-safe: a cancelled order can't be cancelled again.
public fun cancel<T>(order: &mut StandingOrder<T>, ctx: &mut TxContext): Coin<T> {
    assert!(ctx.sender() == order.owner, ENotOwner);
    assert!(!order.cancelled, ECancelled);
    order.cancelled = true;
    let refunded = balance::value(&order.pot);
    let out = balance::withdraw_all(&mut order.pot);
    event::emit(OrderCancelled {
        order_id: object::id(order),
        refunded,
        released_total: order.released_total,
    });
    coin::from_balance(out, ctx)
}

// ───────────────────────────────────────────────────────────────────
// Read accessors

public fun owner<T>(o: &StandingOrder<T>): address { o.owner }
public fun recipient<T>(o: &StandingOrder<T>): address { o.recipient }
public fun pot_value<T>(o: &StandingOrder<T>): u64 { balance::value(&o.pot) }
public fun amount_per<T>(o: &StandingOrder<T>): u64 { o.amount_per }
public fun next_due_ms<T>(o: &StandingOrder<T>): u64 { o.next_due_ms }
public fun releases_done<T>(o: &StandingOrder<T>): u64 { o.releases_done }
public fun is_paused<T>(o: &StandingOrder<T>): bool { o.paused }
public fun is_cancelled<T>(o: &StandingOrder<T>): bool { o.cancelled }

// ───────────────────────────────────────────────────────────────────
#[test_only]
use sui::test_scenario as ts;
#[test_only]
use sui::sui::SUI;
#[test_only]
use sui::clock;

#[test_only]
fun mint<T>(amount: u64): Balance<T> { balance::create_for_testing<T>(amount) }

#[test]
fun create_execute_topup_cancel() {
    let admin = @0xA;
    let owner = @0x0;          // ts default sender for the funding tx
    let recipient = @0xBEEF;

    let mut sc = ts::begin(admin);
    // bootstrap
    {
        init(sc.ctx());
    };
    // owner creates + funds an order: 100/interval, fund 250 (2 releases + change)
    sc.next_tx(owner);
    {
        let mut reg = sc.take_shared<AutomationRegistry>();
        let mut clk = clock::create_for_testing(sc.ctx());
        clock::set_for_testing(&mut clk, 1_000);
        let _oid = create<SUI>(&mut reg, mint<SUI>(250), recipient, 100, 1_000, 1_000, sc.ctx());
        ts::return_shared(reg);
        clock::destroy_for_testing(clk);
    };
    // a STRANGER (not owner, not a worker) executes the first due release at
    // t=1000 — execute_due is permissionless; the contract still pays only the
    // hardwired recipient the hardwired amount.
    sc.next_tx(@0xCAFE);
    {
        let reg = sc.take_shared<AutomationRegistry>();
        let mut order = sc.take_shared<StandingOrder<SUI>>();
        let mut clk = clock::create_for_testing(sc.ctx());
        clock::set_for_testing(&mut clk, 1_000);
        execute_due<SUI>(&reg, &mut order, &clk, sc.ctx());
        assert!(releases_done(&order) == 1, 0);
        assert!(pot_value(&order) == 150, 1);
        assert!(next_due_ms(&order) == 2_000, 2);
        ts::return_shared(reg);
        ts::return_shared(order);
        clock::destroy_for_testing(clk);
    };
    // owner cancels → refund remaining 150
    sc.next_tx(owner);
    {
        let mut order = sc.take_shared<StandingOrder<SUI>>();
        let refund = cancel<SUI>(&mut order, sc.ctx());
        assert!(coin::value(&refund) == 150, 3);
        assert!(is_cancelled(&order), 4);
        transfer::public_transfer(refund, owner);
        ts::return_shared(order);
    };
    sc.end();
}

#[test, expected_failure(abort_code = ENotDue)]
fun cannot_execute_before_due() {
    let admin = @0xA;
    let mut sc = ts::begin(admin);
    { init(sc.ctx()); };
    sc.next_tx(@0x0);
    {
        let mut reg = sc.take_shared<AutomationRegistry>();
        create<SUI>(&mut reg, mint<SUI>(250), @0xBEEF, 100, 1_000, 5_000, sc.ctx());
        ts::return_shared(reg);
    };
    // anyone tries at t=1000 but first_due is 5000 → ENotDue (Clock gate holds
    // even though execute_due is permissionless)
    sc.next_tx(@0xCAFE);
    {
        let reg = sc.take_shared<AutomationRegistry>();
        let mut order = sc.take_shared<StandingOrder<SUI>>();
        let mut clk = clock::create_for_testing(sc.ctx());
        clock::set_for_testing(&mut clk, 1_000);
        execute_due<SUI>(&reg, &mut order, &clk, sc.ctx());
        ts::return_shared(reg);
        ts::return_shared(order);
        clock::destroy_for_testing(clk);
    };
    sc.end();
}

#[test]
fun anyone_can_execute_when_due() {
    let admin = @0xA;
    let recipient = @0xBEEF;
    let mut sc = ts::begin(admin);
    { init(sc.ctx()); };
    sc.next_tx(@0x0);
    {
        let mut reg = sc.take_shared<AutomationRegistry>();
        create<SUI>(&mut reg, mint<SUI>(250), recipient, 100, 1_000, 1_000, sc.ctx());
        ts::return_shared(reg);
    };
    // @0xBAD is neither owner nor a registered worker, yet CAN trigger a due
    // release — the contract pays the hardwired recipient the hardwired amount.
    sc.next_tx(@0xBAD);
    {
        let reg = sc.take_shared<AutomationRegistry>();
        let mut order = sc.take_shared<StandingOrder<SUI>>();
        let mut clk = clock::create_for_testing(sc.ctx());
        clock::set_for_testing(&mut clk, 2_000);
        execute_due<SUI>(&reg, &mut order, &clk, sc.ctx());
        assert!(releases_done(&order) == 1, 0);
        assert!(pot_value(&order) == 150, 1);
        assert!(recipient<SUI>(&order) == recipient, 2);
        ts::return_shared(reg);
        ts::return_shared(order);
        clock::destroy_for_testing(clk);
    };
    sc.end();
}

#[test, expected_failure(abort_code = ENotOwner)]
fun stranger_cannot_cancel() {
    let admin = @0xA;
    let mut sc = ts::begin(admin);
    { init(sc.ctx()); };
    sc.next_tx(@0x0);
    {
        let mut reg = sc.take_shared<AutomationRegistry>();
        create<SUI>(&mut reg, mint<SUI>(250), @0xBEEF, 100, 1_000, 1_000, sc.ctx());
        ts::return_shared(reg);
    };
    sc.next_tx(@0xBAD);
    {
        let mut order = sc.take_shared<StandingOrder<SUI>>();
        let refund = cancel<SUI>(&mut order, sc.ctx());
        transfer::public_transfer(refund, @0xBAD);
        ts::return_shared(order);
    };
    sc.end();
}
