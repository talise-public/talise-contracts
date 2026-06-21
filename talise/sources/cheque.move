/// On-chain claimable escrow for Talise cheques.
///
/// A Talise "cheque" is a link/code the sender shares out-of-band; whoever
/// presents it (and passes Talise's off-chain gates — captcha, VPN check,
/// country allowlist) can claim the funds. Those gates stay SERVER-SIDE: the
/// backend verifies the claimer, resolves their on-chain address, and only
/// then signs `claim` from the Onara worker key. On-chain this module is a
/// pure escrow with two terminal exits:
///   • worker-released `claim` → funds go to the verified recipient, or
///   • creator-initiated `reclaim` → funds return to the sender (void).
///
/// Modeled 1:1 on `talise::stream`'s role/cap pattern: a shared
/// `ChequeRegistry` holds the worker address list + a global kill switch;
/// each outstanding cheque is a shared `Cheque<T>` holding the funds as
/// `Balance<T>`. The `claimed` flag is the one-shot guard: `claim` asserts
/// `!claimed` then sets it, and `reclaim` asserts `!claimed`, so claim and
/// reclaim can never both succeed for the same cheque.
///
/// GENERIC over `T`: like `talise::stream` and `talise::send`, the coin type
/// is a phantom parameter; the funding PTB picks `T` (USDsui in production).
module talise::cheque;

use std::hash::sha2_256;
use sui::{
    balance::{Self, Balance},
    clock::Clock,
    coin::{Self, Coin},
    event,
};

// ───────────────────────────────────────────────────────────────────
// Errors

const EZeroAmount: u64 = 300;
const EBadExpiry: u64 = 301;
const ENotWorker: u64 = 302;
const ERegistryPaused: u64 = 303;
const EAlreadyClaimed: u64 = 304;
const EExpired: u64 = 305;
const ENotCreator: u64 = 306;
const EWorkerAlreadyAdded: u64 = 307;
const EWorkerNotFound: u64 = 308;
// v2 trust-minimized claim conditions:
const ENoClaimCondition: u64 = 309; // create with neither a binding nor a hashlock
const ERecipientNotBound: u64 = 310; // claim recipient ≠ the address the cheque is bound to
const EBadSecret: u64 = 311; // hashlock preimage mismatch / malformed digest
const ENotExpired: u64 = 312; // permissionless reclaim attempted before expiry

// ───────────────────────────────────────────────────────────────────
// Objects

/// Singleton shared registry. Its OWN admin/worker set, deliberately NOT
/// reusing `stream`'s — a worker authorized to release streams is not
/// implicitly authorized to release cheques, and vice versa.
public struct ChequeRegistry has key {
    id: UID,
    admin: address,
    worker_addresses: vector<address>,
    paused: bool,
    cheques_total: u64,
}

/// AdminCap minted to the publisher at bootstrap (governance). Distinct
/// type from `stream::StreamAdminCap`.
public struct ChequeAdminCap has key, store { id: UID }

/// One shared object per outstanding cheque. Holds the funds as
/// `Balance<T>`. Terminal once `claimed` is true (paid to recipient) or
/// once `reclaim` has consumed the escrow (returned to creator).
public struct Cheque<phantom T> has key {
    id: UID,
    creator: address,
    escrow: Balance<T>,
    amount: u64,
    expiry_ms: u64,
    claimed: bool,
    // ── v2 trust-minimized claim conditions ──
    // The contract — NOT the server — decides who can take the funds. Every
    // cheque carries at least one of these (asserted at `create`):
    //   • bound_recipient: Some(a) → `claim` may only pay address `a`. Even a
    //     compromised worker key cannot redirect the money elsewhere.
    //   • hashlock: Some(h) → `claim` must present a `secret` with
    //     `sha2_256(secret) == h`. The worker key alone (without the per-cheque
    //     secret that lives in the claim link) cannot drain the cheque.
    // The worker stays in the loop only as a gas-relayer + off-chain compliance
    // gate; it can no longer choose the destination or claim without the code.
    bound_recipient: Option<address>,
    hashlock: Option<vector<u8>>,
}

// ───────────────────────────────────────────────────────────────────
// Events

public struct ChequeCreated has copy, drop {
    cheque_id: ID,
    creator: address,
    amount: u64,
    expiry_ms: u64,
}

public struct ChequeClaimed has copy, drop {
    cheque_id: ID,
    recipient: address,
    amount: u64,
    ts_ms: u64,
}

public struct ChequeReclaimed has copy, drop {
    cheque_id: ID,
    creator: address,
    amount: u64,
}

public struct WorkerAdded has copy, drop { worker: address }
public struct WorkerRemoved has copy, drop { worker: address }

// ───────────────────────────────────────────────────────────────────
// Bootstrap

fun init(ctx: &mut TxContext) {
    let registry = ChequeRegistry {
        id: object::new(ctx),
        admin: ctx.sender(),
        worker_addresses: vector[],
        paused: false,
        cheques_total: 0,
    };
    transfer::share_object(registry);
    transfer::public_transfer(ChequeAdminCap { id: object::new(ctx) }, ctx.sender());
}

/// Admin: grant a worker address permission to call `claim`.
public fun add_worker(
    registry: &mut ChequeRegistry,
    _cap: &ChequeAdminCap,
    worker: address,
) {
    assert!(!registry.worker_addresses.contains(&worker), EWorkerAlreadyAdded);
    registry.worker_addresses.push_back(worker);
    event::emit(WorkerAdded { worker });
}

/// Admin: revoke a worker address (cut off a rotated/compromised key).
public fun remove_worker(
    registry: &mut ChequeRegistry,
    _cap: &ChequeAdminCap,
    worker: address,
) {
    let (found, idx) = registry.worker_addresses.index_of(&worker);
    assert!(found, EWorkerNotFound);
    registry.worker_addresses.remove(idx);
    event::emit(WorkerRemoved { worker });
}

/// Admin: global kill switch (halts ALL worker claims).
public fun set_paused(registry: &mut ChequeRegistry, _cap: &ChequeAdminCap, paused: bool) {
    registry.paused = paused;
}

// ───────────────────────────────────────────────────────────────────
// Funding (creator-signed, once)

/// Called inside the creator's ONE signed funding PTB. The PTB upstream
/// produces `Balance<T>` and hands it here. Shares a `Cheque<T>` and emits
/// ChequeCreated. `expiry_ms` is a wall-clock (Clock) timestamp after which
/// a worker can no longer `claim` — past that, only the creator's `reclaim`
/// (any time) or anyone's `reclaim_expired` (permissionless, post-expiry)
/// can move the funds.
///
/// v2 — the cheque MUST carry at least one on-chain claim condition:
///   • `bound_recipient` Some(a): `claim` can only pay `a` (the sender knows
///     the recipient up front — e.g. a cheque to a resolved @handle).
///   • `hashlock` Some(h): a 32-byte `sha2_256(secret)` digest; `claim` must
///     present the matching secret (the bearer-link case — the secret lives in
///     the claim URL, not on our servers).
/// Both may be set (recipient-bound AND code-gated). Neither → abort: a cheque
/// with no on-chain condition would let the worker pay anyone, which is exactly
/// the trust we're removing.
public fun create<T>(
    registry: &mut ChequeRegistry,
    funds: Balance<T>,
    expiry_ms: u64,
    bound_recipient: Option<address>,
    hashlock: Option<vector<u8>>,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    let amount = balance::value(&funds);
    assert!(amount > 0, EZeroAmount);
    // Expiry must be in the future relative to creation, otherwise the
    // cheque is born already-unclaimable.
    assert!(expiry_ms > clock.timestamp_ms(), EBadExpiry);
    // v2: refuse a condition-less cheque (no binding AND no hashlock).
    assert!(bound_recipient.is_some() || hashlock.is_some(), ENoClaimCondition);
    // A hashlock, when present, must be a well-formed sha2-256 digest (32 bytes)
    // — otherwise it could never be satisfied and the funds would be stranded
    // until expiry.
    if (hashlock.is_some()) {
        assert!(hashlock.borrow().length() == 32, EBadSecret);
    };

    let cheque = Cheque<T> {
        id: object::new(ctx),
        creator: ctx.sender(),
        escrow: funds,
        amount,
        expiry_ms,
        claimed: false,
        bound_recipient,
        hashlock,
    };
    let cid = object::id(&cheque);
    registry.cheques_total = registry.cheques_total + 1;
    event::emit(ChequeCreated {
        cheque_id: cid,
        creator: ctx.sender(),
        amount,
        expiry_ms,
    });
    transfer::share_object(cheque);
    cid
}

// ───────────────────────────────────────────────────────────────────
// Claim (worker-signed)

/// Worker-relayed. The backend calls this AFTER its off-chain gates pass
/// (captcha / country); `recipient` is the verified claimer's resolved
/// on-chain address and `secret` is the claim-code preimage (empty when the
/// cheque has no hashlock). Gates, in order:
///   (a) registry not paused, (b) sender is a registered worker,
///   (c) not already claimed, (d) not past expiry,
///   (e) v2 — if bound, `recipient` MUST equal the bound address,
///   (f) v2 — if hashlocked, `sha2_256(secret)` MUST equal the hashlock.
/// Sets `claimed = true` BEFORE moving funds and transfers the WHOLE escrow as
/// `Coin<T>` to `recipient`. The one-shot `claimed` flag makes a double-fired
/// worker call abort (E_ALREADY_CLAIMED), so a cheque can never pay twice.
///
/// The worker is now a pure relayer: conditions (e)/(f) are enforced ON CHAIN,
/// so even a fully-compromised worker key can neither redirect a bound cheque
/// nor drain a hashlocked one without the secret.
public fun claim<T>(
    registry: &mut ChequeRegistry,
    cheque: &mut Cheque<T>,
    recipient: address,
    secret: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(!registry.paused, ERegistryPaused);
    assert!(registry.worker_addresses.contains(&ctx.sender()), ENotWorker);
    assert!(!cheque.claimed, EAlreadyClaimed);
    assert!(clock.timestamp_ms() < cheque.expiry_ms, EExpired);
    // (e) address binding — funds can only go where the creator committed.
    if (cheque.bound_recipient.is_some()) {
        assert!(recipient == *cheque.bound_recipient.borrow(), ERecipientNotBound);
    };
    // (f) hashlock — the claimer must present the secret from the link.
    if (cheque.hashlock.is_some()) {
        assert!(sha2_256(secret) == *cheque.hashlock.borrow(), EBadSecret);
    };

    cheque.claimed = true;
    let out = balance::withdraw_all(&mut cheque.escrow);
    let amount = balance::value(&out);
    let coin_out = coin::from_balance(out, ctx);
    transfer::public_transfer(coin_out, recipient);

    event::emit(ChequeClaimed {
        cheque_id: object::id(cheque),
        recipient,
        amount,
        ts_ms: clock.timestamp_ms(),
    });
}

// ───────────────────────────────────────────────────────────────────
// Reclaim (creator-signed)

/// Creator-only void. The creator can pull the funds back any time the
/// cheque is still unclaimed — no expiry wait — e.g. the recipient never
/// claims, or the creator cancels. Asserts `!claimed`, so once a worker has
/// claimed, reclaim is impossible (and vice versa): the two exits are
/// mutually exclusive. Returns `Coin<T>` so the funding PTB's reverse can
/// route it wherever the creator wants.
public fun reclaim<T>(cheque: &mut Cheque<T>, _clock: &Clock, ctx: &mut TxContext): Coin<T> {
    assert!(ctx.sender() == cheque.creator, ENotCreator);
    assert!(!cheque.claimed, EAlreadyClaimed);

    // Mark claimed so the cheque is terminal: prevents any second reclaim
    // and keeps the claim/reclaim exits mutually exclusive.
    cheque.claimed = true;
    let out = balance::withdraw_all(&mut cheque.escrow);
    let amount = balance::value(&out);

    event::emit(ChequeReclaimed {
        cheque_id: object::id(cheque),
        creator: cheque.creator,
        amount,
    });
    coin::from_balance(out, ctx)
}

// ───────────────────────────────────────────────────────────────────
// Reclaim-expired (permissionless)

/// Permissionless settlement of an UNCLAIMED, EXPIRED cheque: return the funds
/// to the creator. ANYONE may crank this (a Talise cron, the recipient, a
/// well-wisher) — the funds can only ever go to `cheque.creator`, so there's
/// nothing to redirect and no key to trust. Two assertions: not already
/// claimed, and now ≥ expiry. This is what lets the server sweep expired
/// on-chain cheques WITHOUT the creator's signature and WITHOUT the worker
/// being able to choose a destination — the trust-minimized refund path.
/// Mutually exclusive with `claim`/`reclaim` via the one-shot `claimed` flag.
public fun reclaim_expired<T>(
    cheque: &mut Cheque<T>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(!cheque.claimed, EAlreadyClaimed);
    assert!(clock.timestamp_ms() >= cheque.expiry_ms, ENotExpired);

    cheque.claimed = true;
    let out = balance::withdraw_all(&mut cheque.escrow);
    let amount = balance::value(&out);
    let coin_out = coin::from_balance(out, ctx);
    transfer::public_transfer(coin_out, cheque.creator);

    event::emit(ChequeReclaimed {
        cheque_id: object::id(cheque),
        creator: cheque.creator,
        amount,
    });
}

// ───────────────────────────────────────────────────────────────────
// Read-only views

public fun is_claimed<T>(cheque: &Cheque<T>): bool { cheque.claimed }
public fun amount<T>(cheque: &Cheque<T>): u64 { cheque.amount }
public fun creator<T>(cheque: &Cheque<T>): address { cheque.creator }
public fun expiry_ms<T>(cheque: &Cheque<T>): u64 { cheque.expiry_ms }
public fun escrow_value<T>(cheque: &Cheque<T>): u64 { balance::value(&cheque.escrow) }
public fun is_bound<T>(cheque: &Cheque<T>): bool { cheque.bound_recipient.is_some() }
public fun has_hashlock<T>(cheque: &Cheque<T>): bool { cheque.hashlock.is_some() }
public fun registry_paused(registry: &ChequeRegistry): bool { registry.paused }
public fun is_worker(registry: &ChequeRegistry, addr: address): bool {
    registry.worker_addresses.contains(&addr)
}

// ───────────────────────────────────────────────────────────────────
// Test-only

#[test_only]
public fun test_init(ctx: &mut TxContext) { init(ctx) }
