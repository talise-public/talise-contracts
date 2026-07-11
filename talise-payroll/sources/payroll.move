/// On-chain payroll TEAM — a reusable, owner-gated roster.
///
/// A `Team` is a shared object holding "who you pay together": a name plus a
/// list of `Member`s (recipient address + an optional default amount + a
/// label). It carries NO money and screens nothing itself — paying the team
/// still goes through Talise's server prepare, which re-resolves + compliance-
/// screens every recipient + checks send limits, then disburses atomically via
/// `talise::batch_pay::pay_many`. This object is just the saved, composable,
/// on-chain source of truth for the roster.
///
/// Self-contained by design: no central registry and no `init`. Each Team
/// stamps its creator as `owner` and gates every mutation on
/// `ctx.sender() == owner`, so the package publishes clean as a fresh, low-
/// surface package rather than an upgrade of the production `talise` package
/// (whose new-module `init` would never run on an upgrade anyway).
///
/// The transaction is Onara-sponsored (gasless): `setGasOwner` moves the gas
/// payer to the sponsor, but `ctx.sender()` stays the user's zkLogin address,
/// so owner-gating is unaffected.
module talise_payroll::payroll;

use std::string::String;
use sui::event;

// ───────────────────────────────────────────────────────────────────
// Errors

const ENotOwner: u64 = 800;
const ELenMismatch: u64 = 801;
const ETooMany: u64 = 802;

/// PTB object/size caps make very large rosters impractical anyway; this is a
/// generous guard against an accidental unbounded vector. Large payrolls are
/// chunked off-chain (the pay path already chunks `pay_many`).
const MAX_MEMBERS: u64 = 256;

// ───────────────────────────────────────────────────────────────────
// Objects

/// One person on the team. `amount_micro` is an optional saved default in
/// 1e-6 USD units (0 = "ask me at pay time"); `label` is a free memo. These
/// are conveniences the pay screen pre-fills — the server still confirms the
/// real amounts before building the disbursement.
public struct Member has store, copy, drop {
    recipient: address,
    amount_micro: u64,
    label: String,
}

/// A reusable team roster. Shared so the owner can edit it from any session
/// (and so the server can read it when building a pay). `seq` bumps on every
/// edit — a monotonic cursor for cache-busting / ordering off-chain.
public struct Team has key {
    id: UID,
    owner: address,
    name: String,
    members: vector<Member>,
    seq: u64,
}

// ───────────────────────────────────────────────────────────────────
// Events

public struct TeamCreated has copy, drop {
    team_id: ID,
    owner: address,
    name: String,
    count: u64,
}

public struct TeamUpdated has copy, drop {
    team_id: ID,
    owner: address,
    name: String,
    count: u64,
    seq: u64,
}

public struct TeamDeleted has copy, drop {
    team_id: ID,
    owner: address,
}

// ───────────────────────────────────────────────────────────────────
// Internal

/// Zip three parallel vectors into `Member`s. Asserts equal length and the
/// `MAX_MEMBERS` bound. Consumes the inputs.
fun build_members(
    recipients: vector<address>,
    amounts: vector<u64>,
    labels: vector<String>,
): vector<Member> {
    let n = recipients.length();
    assert!(n == amounts.length(), ELenMismatch);
    assert!(n == labels.length(), ELenMismatch);
    assert!(n <= MAX_MEMBERS, ETooMany);

    let mut out = vector<Member>[];
    let mut i = 0;
    while (i < n) {
        out.push_back(Member {
            recipient: recipients[i],
            amount_micro: amounts[i],
            label: labels[i],
        });
        i = i + 1;
    };
    out
}

// ───────────────────────────────────────────────────────────────────
// Entry points

/// Create a team and share it. `ctx.sender()` becomes the owner. Returns the
/// new `Team` object id; the PTB can ignore it (the server parses the created
/// object id from the transaction's object changes, exactly like streams).
public fun create(
    name: String,
    recipients: vector<address>,
    amounts: vector<u64>,
    labels: vector<String>,
    ctx: &mut TxContext,
): ID {
    let members = build_members(recipients, amounts, labels);
    let count = members.length();
    let team = Team {
        id: object::new(ctx),
        owner: ctx.sender(),
        name,
        members,
        seq: 0,
    };
    let tid = object::id(&team);
    event::emit(TeamCreated { team_id: tid, owner: team.owner, name: team.name, count });
    transfer::share_object(team);
    tid
}

/// Replace a team's whole roster (and name) in one call — the edit path.
/// Owner-only. Bumps `seq`.
public fun set_roster(
    team: &mut Team,
    name: String,
    recipients: vector<address>,
    amounts: vector<u64>,
    labels: vector<String>,
    ctx: &mut TxContext,
) {
    assert!(team.owner == ctx.sender(), ENotOwner);
    let members = build_members(recipients, amounts, labels);
    let count = members.length();
    team.name = name;
    team.members = members;
    team.seq = team.seq + 1;
    event::emit(TeamUpdated {
        team_id: object::id(team),
        owner: team.owner,
        name: team.name,
        count,
        seq: team.seq,
    });
}

/// Delete a team. Owner-only. Unwraps the shared object and frees its id.
public fun delete(team: Team, ctx: &mut TxContext) {
    assert!(team.owner == ctx.sender(), ENotOwner);
    let tid = object::id(&team);
    let owner = team.owner;
    let Team { id, owner: _, name: _, members: _, seq: _ } = team;
    object::delete(id);
    event::emit(TeamDeleted { team_id: tid, owner });
}

// ───────────────────────────────────────────────────────────────────
// Read accessors (server reads object fields directly, but these keep the
// shape explicit and give tests a handle).

public fun owner(team: &Team): address { team.owner }
public fun name(team: &Team): String { team.name }
public fun size(team: &Team): u64 { team.members.length() }
public fun seq(team: &Team): u64 { team.seq }

public fun member_at(team: &Team, i: u64): (address, u64, String) {
    let m = &team.members[i];
    (m.recipient, m.amount_micro, m.label)
}

// ───────────────────────────────────────────────────────────────────
#[test_only]
use sui::test_scenario as ts;
#[test_only]
use std::string;

#[test]
fun create_edit_delete_roundtrip() {
    let owner = @0xA11CE;
    let bob = @0xB0B;
    let carol = @0xCEC11;

    let mut sc = ts::begin(owner);

    // create
    {
        let id = create(
            string::utf8(b"Design team"),
            vector[bob, carol],
            vector[1_000000, 2_500000],
            vector[string::utf8(b"lead"), string::utf8(b"")],
            sc.ctx(),
        );
        let _ = id;
    };

    // read back the shared Team
    sc.next_tx(owner);
    {
        let team = sc.take_shared<Team>();
        assert!(owner(&team) == owner, 0);
        assert!(size(&team) == 2, 1);
        assert!(seq(&team) == 0, 2);
        let (r0, a0, _l0) = member_at(&team, 0);
        assert!(r0 == bob, 3);
        assert!(a0 == 1_000000, 4);
        ts::return_shared(team);
    };

    // edit (owner): replace roster
    sc.next_tx(owner);
    {
        let mut team = sc.take_shared<Team>();
        set_roster(
            &mut team,
            string::utf8(b"Design team v2"),
            vector[carol],
            vector[5_000000],
            vector[string::utf8(b"all")],
            sc.ctx(),
        );
        assert!(size(&team) == 1, 5);
        assert!(seq(&team) == 1, 6);
        ts::return_shared(team);
    };

    // delete (owner)
    sc.next_tx(owner);
    {
        let team = sc.take_shared<Team>();
        delete(team, sc.ctx());
    };

    sc.end();
}

#[test, expected_failure(abort_code = ENotOwner)]
fun stranger_cannot_edit() {
    let owner = @0xA11CE;
    let mallory = @0xBAD;
    let bob = @0xB0B;

    let mut sc = ts::begin(owner);
    {
        let _ = create(
            string::utf8(b"T"),
            vector[bob],
            vector[1_000000],
            vector[string::utf8(b"")],
            sc.ctx(),
        );
    };
    sc.next_tx(mallory);
    {
        let mut team = sc.take_shared<Team>();
        set_roster(
            &mut team,
            string::utf8(b"hijacked"),
            vector[mallory],
            vector[9_000000],
            vector[string::utf8(b"")],
            sc.ctx(),
        );
        ts::return_shared(team);
    };
    sc.end();
}

#[test, expected_failure(abort_code = ELenMismatch)]
fun mismatched_vectors_abort() {
    let owner = @0xA11CE;
    let bob = @0xB0B;
    let mut sc = ts::begin(owner);
    {
        let _ = create(
            string::utf8(b"T"),
            vector[bob],
            vector[1_000000, 2_000000], // 2 amounts for 1 recipient
            vector[string::utf8(b"")],
            sc.ctx(),
        );
    };
    sc.end();
}
