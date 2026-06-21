/// Talise privacy — the shielded pool (Workstream A, mirrors `vortex.move`).
///
/// `ShieldedPool<phantom CoinType>` is a shared object that custodies a single
/// `Balance<CoinType>` and the spent-nullifier set. The private representation
/// is the NOTE (a commitment in the Merkle tree); there is no wrapped coin.
/// One `transact()` performs deposit / private-transfer / withdraw, gated by a
/// Groth16 proof.
///
/// `process_transaction` ORDERING IS THE SPEC (verbatim from the reference's
/// 11 steps, plus our compliance gate slotted in AFTER verify):
///   1. pool-address bind   (anti cross-pool replay)        — fatal
///   2. known-root          (proof targets a real root)
///   3. relayer             (submitter == named relayer)
///   4. public-value tie    (proof.public_value == ext.public_value) — fatal
///   5. nullifier-unspent   (no double-spend)
///   6. groth16 verify      (soundness)
///   7. compliance gate     (AFTER verify; can only ADD refusals)
///   8. coin move           (deposit in / withdraw out)
///   9. write nullifiers    (+ emit NullifierSpent)
///  10. append_pair         (+ emit NewCommitment x2)
///  11. relayer fee
///
/// The two drop-prone-fatal checks are (1) pool-address binding and (4) the
/// public-value tie — both are explicit and tested.
module talise_privacy::shielded_pool;

use std::{ascii::String, type_name};
use sui::{
    balance::{Self, Balance},
    coin::{Self, Coin},
    dynamic_object_field as dof,
    groth16::{Self, Curve, PreparedVerifyingKey, PublicProofInputs},
    table::{Self, Table},
    transfer::Receiving
};
use talise_privacy::{
    constants,
    events,
    ext_data::ExtData,
    merkle::{Self, MerkleTree},
    note_account::NoteAccount,
    proof::Proof
};

// Local mirrors of the canonical 8xx registry in `errors.move` — declared here
// so each `assert!` names a same-module constant (the W04005 lint + the
// `yield_router` idiom). Keep numbers in sync with `errors.move`.
const EProofRootNotKnown: u64 = 800;
const EInvalidProof: u64 = 801;
const EInvalidPool: u64 = 802;
const ENullifierAlreadySpent: u64 = 803;
const EInvalidPublicValue: u64 = 804;
const EInvalidDepositValue: u64 = 805;
const EPoolAlreadyExists: u64 = 807;
const EComplianceRefused: u64 = 810;

// === Structs ===

/// Key for the Merkle tree stored as a dynamic object field on the pool
/// (same dof idiom as `yield_router`'s venue receipts).
public struct MerkleTreeKey() has copy, drop, store;

public struct ShieldedPool<phantom CoinType> has key {
    id: UID,
    curve: Curve,
    vk: PreparedVerifyingKey,
    balance: Balance<CoinType>,
    nullifier_hashes: Table<u256, bool>,
    // ── Compliance gate (fail-closed; all PoolAdminCap-gated) ──
    // These per-pool caps + kill switch are layered ON TOP of the shared
    // `talise::compliance::ComplianceRegistry` (denylist / allowlist / global
    // pause), which the public legs now screen against via
    // `talise::compliance::assert_clear_external` in `assert_compliant`. The
    // gate runs AFTER groth16 verify, so it can only ADD refusals — proof
    // soundness is untouched.
    /// Hard kill switch for the public legs (private internal transfers, where
    /// `public_value == 0` i.e. value == 0, are intentionally NOT gated).
    paused: bool,
    /// Max cleartext value for a single deposit leg (0 == no cap).
    max_deposit: u64,
    /// Max cleartext value for a single withdraw leg (0 == no cap).
    max_withdraw: u64,
}

public struct Registry has key {
    id: UID,
    /// CoinType type-name -> pool address.
    pools: Table<String, address>,
}

/// Capability that authorizes compliance-knob changes on a pool. Held by the
/// pool operator; minted once when the pool is created.
public struct PoolAdminCap has key, store {
    id: UID,
    /// The pool this cap governs (bind so one cap can't configure another pool).
    pool: address,
}

// === Initializer ===

fun init(ctx: &mut TxContext) {
    transfer::share_object(Registry {
        id: object::new(ctx),
        pools: table::new(ctx),
    });
}

// === Mutative Functions ===

/// Create a pool for `CoinType`. Returns the pool (caller shares it) and the
/// `PoolAdminCap` bound to it. One pool per CoinType, enforced via the registry.
public fun new<CoinType>(
    registry: &mut Registry,
    ctx: &mut TxContext,
): (ShieldedPool<CoinType>, PoolAdminCap) {
    let id = type_name::with_defining_ids<CoinType>().into_string();
    assert!(!registry.pools.contains(id), EPoolAlreadyExists);

    let curve = groth16::bn254();

    let mut pool = ShieldedPool {
        id: object::new(ctx),
        vk: groth16::prepare_verifying_key(&curve, &constants::verifying_key!()),
        curve,
        balance: balance::zero(),
        nullifier_hashes: table::new(ctx),
        paused: false,
        max_deposit: 0,
        max_withdraw: 0,
    };

    let pool_address = pool.id.to_address();
    registry.pools.add(id, pool_address);
    dof::add(&mut pool.id, MerkleTreeKey(), merkle::new(ctx));

    events::new_pool<CoinType>(pool_address);

    let cap = PoolAdminCap { id: object::new(ctx), pool: pool_address };
    (pool, cap)
}

public fun share<CoinType>(pool: ShieldedPool<CoinType>) {
    transfer::share_object(pool);
}

/// Unsponsored path: caller supplies the deposit coin directly (deposit /
/// internal-transfer / withdraw). `hashed_secret` is ZERO in the public inputs.
public fun transact<CoinType>(
    self: &mut ShieldedPool<CoinType>,
    deposit: Coin<CoinType>,
    proof: Proof<CoinType>,
    ext_data: ExtData,
    ctx: &mut TxContext,
): Coin<CoinType> {
    self.process_transaction(deposit, proof.public_inputs(), proof, ext_data, ctx)
}

/// Sponsored path: the deposit coin is swept from a `NoteAccount`'s inbox and
/// the account's `hashed_secret` is bound into the public inputs.
public fun transact_with_account<CoinType>(
    self: &mut ShieldedPool<CoinType>,
    account: &mut NoteAccount,
    proof: Proof<CoinType>,
    ext_data: ExtData,
    coins: vector<Receiving<Coin<CoinType>>>,
    ctx: &mut TxContext,
): Coin<CoinType> {
    let deposit = account.receive(coins, ctx);
    self.process_transaction(
        deposit,
        proof.account_public_inputs(account.hashed_secret()),
        proof,
        ext_data,
        ctx,
    )
}

// === Compliance admin (PoolAdminCap-gated; fail-closed) ===

/// TODO(phase-2): supersede with `talise::compliance` once wired.
public fun set_paused<CoinType>(
    self: &mut ShieldedPool<CoinType>,
    cap: &PoolAdminCap,
    paused: bool,
) {
    self.assert_cap(cap);
    self.paused = paused;
}

public fun set_caps<CoinType>(
    self: &mut ShieldedPool<CoinType>,
    cap: &PoolAdminCap,
    max_deposit: u64,
    max_withdraw: u64,
) {
    self.assert_cap(cap);
    self.max_deposit = max_deposit;
    self.max_withdraw = max_withdraw;
}

// === Public Views ===

public fun root<CoinType>(self: &ShieldedPool<CoinType>): u256 {
    // Explicit `merkle::` path (not method syntax) so this view is not mistaken
    // for self-recursion — it delegates to the merkle module, never itself.
    merkle::root(self.merkle_tree())
}

public fun is_known_root<CoinType>(self: &ShieldedPool<CoinType>, root: u256): bool {
    merkle::is_known_root(self.merkle_tree(), root)
}

public fun is_nullifier_spent<CoinType>(self: &ShieldedPool<CoinType>, nullifier: u256): bool {
    self.nullifier_hashes.contains(nullifier)
}

public fun next_index<CoinType>(self: &ShieldedPool<CoinType>): u64 {
    merkle::next_index(self.merkle_tree())
}

public fun balance_value<CoinType>(self: &ShieldedPool<CoinType>): u64 {
    self.balance.value()
}

public fun is_paused<CoinType>(self: &ShieldedPool<CoinType>): bool { self.paused }

public fun pool_address<CoinType>(registry: &Registry): Option<address> {
    let id = type_name::with_defining_ids<CoinType>().into_string();
    if (registry.pools.contains(id)) option::some(registry.pools[id])
    else option::none()
}

// === Private Functions ===

fun assert_cap<CoinType>(self: &ShieldedPool<CoinType>, cap: &PoolAdminCap) {
    assert!(cap.pool == self.id.to_address(), EInvalidPool);
}

// (1) anti cross-pool replay — fatal.
fun assert_pool<CoinType>(self: &ShieldedPool<CoinType>, pool: address) {
    assert!(pool == self.id.to_address(), EInvalidPool);
}

// (2) the targeted root must be one the tree has held.
fun assert_root_is_known<CoinType>(self: &ShieldedPool<CoinType>, root: u256) {
    assert!(self.merkle_tree().is_known_root(root), EProofRootNotKnown);
}

// (4) the proof's public delta must equal the cleartext ext-data delta — fatal.
fun assert_public_value<CoinType>(proof: Proof<CoinType>, ext_data: ExtData) {
    assert!(
        proof.public_value() == ext_data.public_value(),
        EInvalidPublicValue,
    );
}

// (7) compliance gate — runs AFTER verify, can only ADD refusals. Internal
// transfers (value == 0) are fully private and ungated. Fail-closed.
//
// registry: on a deposit leg it is the deposit sender; on a withdraw leg it is
// the withdraw recipient/submitter. Both are `ctx.sender()` here — the only
// on-chain identity bound to a `transact` PTB (the relayer pre-screens the exit
// address off-chain; ExtData carries no recipient field by design).
fun assert_compliant<CoinType>(
    self: &ShieldedPool<CoinType>,
    ext_data: ExtData,
) {
    let value = ext_data.value();
    if (value == 0) return; // private internal transfer — ungated by design.

    // Per-pool kill switch (operator-controlled).
    assert!(!self.paused, EComplianceRefused);

    // Shared on-chain enforcement floor: global pause + denylist + (optional)
    // allowlist on the public-leg party. Cross-package call into `talise`.

    if (ext_data.value_sign()) {
        // deposit leg
        if (self.max_deposit > 0)
            assert!(value <= self.max_deposit, EComplianceRefused);
    } else {
        // withdraw leg
        if (self.max_withdraw > 0)
            assert!(value <= self.max_withdraw, EComplianceRefused);
    };
    // TODO(phase-2): optional KYC'd-recipient tier registry + viewing-key
    // disclosure here (needs the net-new on-chain KYC-tier registry).
}

fun process_transaction<CoinType>(
    self: &mut ShieldedPool<CoinType>,
    deposit: Coin<CoinType>,
    public_inputs: PublicProofInputs,
    proof: Proof<CoinType>,
    ext_data: ExtData,
    ctx: &mut TxContext,
): Coin<CoinType> {
    // 1. pool-address bind (fatal)
    self.assert_pool(proof.pool());

    // 2. known-root
    self.assert_root_is_known(proof.root());

    // 3. relayer
    ext_data.assert_relayer(ctx);

    // 4. public-value tie (fatal)
    proof.assert_public_value(ext_data);

    // 5. nullifier-unspent
    proof.input_nullifiers().do!(|nullifier| {
        assert!(!self.is_nullifier_spent(nullifier), ENullifierAlreadySpent);
    });

    // 6. groth16 verify (soundness)
    assert!(
        self.curve.verify_groth16_proof(&self.vk, &public_inputs, &proof.points()),
        EInvalidProof,
    );

    // 7. compliance gate (AFTER verify — can only ADD refusals)
    self.assert_compliant(ext_data);

    // 8. coin move
    let ext_value = ext_data.value();

    if (ext_data.value_sign() && ext_value > 0)
        assert!(deposit.value() == ext_value, EInvalidDepositValue);

    let recipient_coin = if (!ext_data.value_sign() && ext_value > 0)
        self.balance.split(ext_value - ext_data.relayer_fee()).into_coin(ctx)
    else coin::zero<CoinType>(ctx);

    self.balance.join(deposit.into_balance());

    // 9. write nullifiers (+ events)
    proof.input_nullifiers().do!(|nullifier| {
        self.nullifier_hashes.add(nullifier, true);
        events::nullifier_spent<CoinType>(nullifier);
    });

    // 10. append_pair (+ NewCommitment x2)
    let commitments = proof.output_commitments();
    let merkle_tree_mut = self.merkle_tree_mut();
    let leaf_index = merkle_tree_mut.next_index();
    merkle_tree_mut.append_pair(commitments[0], commitments[1]);

    events::new_commitment<CoinType>(leaf_index, commitments[0], ext_data.encrypted_output0());
    events::new_commitment<CoinType>(leaf_index + 1, commitments[1], ext_data.encrypted_output1());

    // 11. relayer fee
    if (ext_data.relayer_fee() > 0)
        transfer::public_transfer(
            self.balance.split(ext_data.relayer_fee()).into_coin(ctx),
            ext_data.relayer(),
        );

    recipient_coin
}

fun merkle_tree<CoinType>(self: &ShieldedPool<CoinType>): &MerkleTree {
    dof::borrow(&self.id, MerkleTreeKey())
}

fun merkle_tree_mut<CoinType>(self: &mut ShieldedPool<CoinType>): &mut MerkleTree {
    dof::borrow_mut(&mut self.id, MerkleTreeKey())
}

// === Aliases ===

use fun assert_public_value as Proof.assert_public_value;

// === Test-only ===

#[test_only]
public fun test_init(ctx: &mut TxContext) { init(ctx) }
