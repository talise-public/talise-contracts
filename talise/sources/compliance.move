/// On-chain compliance gate — a non-bypassable denylist / allowlist + global
/// kill switch that every Talise money-moving module asserts against.
///
/// The HEAVY screening (Chainalysis/KYT, PEP, fuzzy match) stays SERVER-SIDE;
/// this module is the on-chain ENFORCEMENT FLOOR. It makes "Talise never moves
/// funds to a sanctioned address" true even if a worker/server key is
/// compromised, and it lets a court-ordered freeze halt Talise-held funds
/// (see `remit_escrow::freeze`).
///
/// Honest boundary: it custodies NO funds and can only REFUSE to originate a
/// transfer a Talise contract would make, or freeze funds already sitting in a
/// Talise-program object. It CANNOT claw back coins in a user's own zkLogin
/// wallet — and we don't claim it can.
///
/// Hardening note: OpenZeppelin's `access_control` was evaluated, but the
/// OZ-for-Sui package pins a different Sui-framework rev than this package
/// (the same "multiple versions of 0x2" conflict documented in Move.toml), so
/// we use the in-house AdminCap + 2-step-rotation idiom proven in `auto_swap`.
module talise::compliance;

use sui::{event, vec_set::{Self, VecSet}};

// ───────────────────────────────────────────────────────────────────
// Errors

const EPaused: u64 = 700;
const EDenied: u64 = 701;
const ENotAllowed: u64 = 702;
const EAlreadyDenied: u64 = 703;
const ENotDenied: u64 = 704;
const EAlreadyAllowed: u64 = 705;
const ENotInAllowlist: u64 = 706;

// ───────────────────────────────────────────────────────────────────
// Objects

/// Singleton shared registry. `denied` is always enforced; `allowed` is only
/// enforced when `allowlist_required` is true (e.g. a jurisdiction that needs
/// positive allowlisting). `paused` is a global kill switch: while paused,
/// EVERY gated money-mover aborts (fail-closed — nothing moves).
public struct ComplianceRegistry has key {
    id: UID,
    admin: address,
    denied: VecSet<address>,
    allowed: VecSet<address>,
    allowlist_required: bool,
    paused: bool,
}

/// Governance capability minted to the publisher at bootstrap.
public struct ComplianceAdminCap has key, store { id: UID }

// ───────────────────────────────────────────────────────────────────
// Events

public struct AddressDenied has copy, drop { addr: address }
public struct AddressUndenied has copy, drop { addr: address }
public struct AddressAllowed has copy, drop { addr: address }
public struct AddressDisallowed has copy, drop { addr: address }
public struct AllowlistRequirementChanged has copy, drop { required: bool }
public struct CompliancePauseChanged has copy, drop { paused: bool }

// ───────────────────────────────────────────────────────────────────
// Bootstrap

fun init(ctx: &mut TxContext) {
    transfer::share_object(ComplianceRegistry {
        id: object::new(ctx),
        admin: ctx.sender(),
        denied: vec_set::empty(),
        allowed: vec_set::empty(),
        allowlist_required: false,
        paused: false,
    });
    transfer::public_transfer(ComplianceAdminCap { id: object::new(ctx) }, ctx.sender());
}

// ───────────────────────────────────────────────────────────────────
// Admin mutations (cap-gated)

public fun deny(registry: &mut ComplianceRegistry, _cap: &ComplianceAdminCap, addr: address) {
    assert!(!registry.denied.contains(&addr), EAlreadyDenied);
    registry.denied.insert(addr);
    event::emit(AddressDenied { addr });
}

public fun undeny(registry: &mut ComplianceRegistry, _cap: &ComplianceAdminCap, addr: address) {
    assert!(registry.denied.contains(&addr), ENotDenied);
    registry.denied.remove(&addr);
    event::emit(AddressUndenied { addr });
}

public fun allow(registry: &mut ComplianceRegistry, _cap: &ComplianceAdminCap, addr: address) {
    assert!(!registry.allowed.contains(&addr), EAlreadyAllowed);
    registry.allowed.insert(addr);
    event::emit(AddressAllowed { addr });
}

public fun disallow(registry: &mut ComplianceRegistry, _cap: &ComplianceAdminCap, addr: address) {
    assert!(registry.allowed.contains(&addr), ENotInAllowlist);
    registry.allowed.remove(&addr);
    event::emit(AddressDisallowed { addr });
}

public fun set_allowlist_required(registry: &mut ComplianceRegistry, _cap: &ComplianceAdminCap, required: bool) {
    registry.allowlist_required = required;
    event::emit(AllowlistRequirementChanged { required });
}

/// Global kill switch. While paused, `assert_clear` aborts for every address,
/// so all gated money movement halts (fail-closed).
public fun set_paused(registry: &mut ComplianceRegistry, _cap: &ComplianceAdminCap, paused: bool) {
    registry.paused = paused;
    event::emit(CompliancePauseChanged { paused });
}

// ───────────────────────────────────────────────────────────────────
// Enforcement (package-internal — consumed by money-movers)

/// Abort unless `addr` is clear to send/receive: not globally paused, not
/// denied, and (when an allowlist is required) explicitly allowed. Called by
/// `remit_escrow`, `batch_pay`, etc. `public(package)` so it can only be
/// invoked by Talise modules in this package, never spoofed externally.
public(package) fun assert_clear(registry: &ComplianceRegistry, addr: address) {
    assert!(!registry.paused, EPaused);
    assert!(!registry.denied.contains(&addr), EDenied);
    if (registry.allowlist_required) {
        assert!(registry.allowed.contains(&addr), ENotAllowed);
    };
}

/// Both legs of a transfer must be clear.
public(package) fun assert_pair_clear(registry: &ComplianceRegistry, from: address, to: address) {
    assert_clear(registry, from);
    assert_clear(registry, to);
}

// ───────────────────────────────────────────────────────────────────
// Cross-package enforcement (thin `public` wrappers over the package-internal
// logic above). These exist so OTHER Talise Move packages — e.g.
// `talise_privacy::shielded_pool`'s compliance gate — can assert against this
// same registry. They add NO new behavior: each is a one-line forward to the
// `public(package)` enforcement, so the on-chain enforcement floor stays a
// single source of truth. They are still bounded by needing a `&ComplianceRegistry`
// reference (the singleton shared object), so they cannot be spoofed with a
// fake registry that an attacker controls in a money-mover's call path.

/// Cross-package twin of `assert_clear`. Abort unless `addr` is clear.
public fun assert_clear_external(registry: &ComplianceRegistry, addr: address) {
    assert_clear(registry, addr);
}

/// Cross-package twin of `assert_pair_clear`. Both legs must be clear.
public fun assert_pair_clear_external(registry: &ComplianceRegistry, from: address, to: address) {
    assert_pair_clear(registry, from, to);
}

/// Cross-package read of the global pause flag (already-public `is_paused`
/// re-exported under the `_external` naming for symmetry with the asserts).
public fun is_paused_external(registry: &ComplianceRegistry): bool {
    is_paused(registry)
}

/// Cross-package read of allowlist membership.
public fun is_allowed_external(registry: &ComplianceRegistry, addr: address): bool {
    is_allowed(registry, addr)
}

// ───────────────────────────────────────────────────────────────────
// Read-only views

public fun is_denied(registry: &ComplianceRegistry, addr: address): bool {
    registry.denied.contains(&addr)
}
public fun is_allowed(registry: &ComplianceRegistry, addr: address): bool {
    registry.allowed.contains(&addr)
}
public fun allowlist_required(registry: &ComplianceRegistry): bool { registry.allowlist_required }
public fun is_paused(registry: &ComplianceRegistry): bool { registry.paused }

// ───────────────────────────────────────────────────────────────────
// Test-only

#[test_only]
public fun test_init(ctx: &mut TxContext) { init(ctx) }
