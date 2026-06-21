/// Tests for the claimable-escrow cheque module.
///
/// Coverage:
///   • happy path: create → worker claim pays the verified recipient
///   • access control: non-worker claim aborts E_NOT_WORKER
///   • registry kill switch: paused registry blocks claim (E_REGISTRY_PAUSED)
///   • expiry gate: claim at/after expiry aborts E_EXPIRED
///   • double-claim prevention: second claim aborts E_ALREADY_CLAIMED
///   • reclaim: creator voids an unclaimed cheque and gets funds back
///   • mutual exclusion: reclaim-after-claim aborts E_ALREADY_CLAIMED, and
///     claim-after-reclaim aborts E_ALREADY_CLAIMED
///   • non-creator reclaim aborts E_NOT_CREATOR
///   • create input validation (zero funds, past expiry, no condition, bad hashlock)
///   • v2 address binding: claim to the wrong recipient aborts E_RECIPIENT_NOT_BOUND
///   • v2 hashlock: wrong secret aborts E_BAD_SECRET; correct secret pays
///   • v2 permissionless reclaim_expired: before-expiry aborts E_NOT_EXPIRED;
///     after-expiry ANYONE returns the funds to the creator; post-claim aborts
///   • worker add/remove
///
/// Dummy coin type `T = SUI` via `coin::mint_for_testing` → `into_balance`.
#[test_only]
module talise::cheque_tests;

use std::hash::sha2_256;
use std::unit_test::assert_eq;
use sui::{balance, clock, coin, sui::SUI, test_scenario as ts};
use talise::cheque::{Self, ChequeRegistry, ChequeAdminCap, Cheque};

const PUBLISHER: address = @0xA;
const CREATOR: address = @0xB;
const CLAIMER: address = @0xC;
const WORKER: address = @0xD;
const RANDO: address = @0xE;

const AMOUNT: u64 = 5_000_000;
const EXPIRY: u64 = 100_000;

/// The bearer claim-code preimage for the hashlock tests.
const SECRET: vector<u8> = b"open-sesame-claim-code-0123456789";

// ───────────────────────────────────────────────────────────────────
// Helpers

fun setup_registry(scenario: &mut ts::Scenario) {
    ts::next_tx(scenario, PUBLISHER);
    cheque::test_init(ts::ctx(scenario));
}

fun grant_worker(scenario: &mut ts::Scenario) {
    ts::next_tx(scenario, PUBLISHER);
    let cap = ts::take_from_sender<ChequeAdminCap>(scenario);
    let mut reg = ts::take_shared<ChequeRegistry>(scenario);
    cheque::add_worker(&mut reg, &cap, WORKER);
    ts::return_shared(reg);
    ts::return_to_sender(scenario, cap);
}

/// CREATOR funds a cheque bound to `recipient` (no hashlock), `AMOUNT`,
/// expiry `EXPIRY`, clock at ms=0. This is the default rail the access /
/// expiry / double-claim tests use — the recipient is committed on-chain.
fun fund_bound(scenario: &mut ts::Scenario, recipient: address): ID {
    ts::next_tx(scenario, CREATOR);
    let mut reg = ts::take_shared<ChequeRegistry>(scenario);
    let c = clock::create_for_testing(ts::ctx(scenario)); // ms = 0
    let funds = coin::mint_for_testing<SUI>(AMOUNT, ts::ctx(scenario)).into_balance();
    let cid = cheque::create<SUI>(
        &mut reg,
        funds,
        EXPIRY,
        option::some(recipient),
        option::none(),
        &c,
        ts::ctx(scenario),
    );
    clock::destroy_for_testing(c);
    ts::return_shared(reg);
    cid
}

/// CREATOR funds a hashlocked (bearer) cheque: no address binding, the claim
/// is gated by `sha2_256(SECRET)`.
fun fund_hashlock(scenario: &mut ts::Scenario): ID {
    ts::next_tx(scenario, CREATOR);
    let mut reg = ts::take_shared<ChequeRegistry>(scenario);
    let c = clock::create_for_testing(ts::ctx(scenario));
    let funds = coin::mint_for_testing<SUI>(AMOUNT, ts::ctx(scenario)).into_balance();
    let cid = cheque::create<SUI>(
        &mut reg,
        funds,
        EXPIRY,
        option::none(),
        option::some(sha2_256(SECRET)),
        &c,
        ts::ctx(scenario),
    );
    clock::destroy_for_testing(c);
    ts::return_shared(reg);
    cid
}

// ───────────────────────────────────────────────────────────────────
// Happy path

#[test]
fun create_then_claim_pays_recipient() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    let cid = fund_bound(&mut scenario, CLAIMER);

    ts::next_tx(&mut scenario, WORKER);
    {
        let mut reg = ts::take_shared<ChequeRegistry>(&scenario);
        let mut ch = ts::take_shared_by_id<Cheque<SUI>>(&scenario, cid);
        let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
        clock::set_for_testing(&mut c, EXPIRY - 1); // before expiry
        cheque::claim<SUI>(&mut reg, &mut ch, CLAIMER, b"", &c, ts::ctx(&mut scenario));
        assert!(cheque::is_claimed(&ch));
        assert_eq!(cheque::escrow_value(&ch), 0);
        clock::destroy_for_testing(c);
        ts::return_shared(ch);
        ts::return_shared(reg);
    };

    // CLAIMER holds the funds; nobody else does.
    ts::next_tx(&mut scenario, CLAIMER);
    {
        let got = ts::take_from_sender<coin::Coin<SUI>>(&scenario);
        assert_eq!(got.value(), AMOUNT);
        coin::burn_for_testing(got);
    };
    ts::next_tx(&mut scenario, CREATOR);
    assert!(!ts::has_most_recent_for_sender<coin::Coin<SUI>>(&scenario));

    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// Access control

#[test, expected_failure(abort_code = cheque::ENotWorker)]
fun non_worker_claim_aborts() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    let cid = fund_bound(&mut scenario, CLAIMER);

    // RANDO is not a worker.
    ts::next_tx(&mut scenario, RANDO);
    let mut reg = ts::take_shared<ChequeRegistry>(&scenario);
    let mut ch = ts::take_shared_by_id<Cheque<SUI>>(&scenario, cid);
    let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut c, EXPIRY - 1);
    cheque::claim<SUI>(&mut reg, &mut ch, RANDO, b"", &c, ts::ctx(&mut scenario));
    clock::destroy_for_testing(c);
    ts::return_shared(ch);
    ts::return_shared(reg);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = cheque::ERegistryPaused)]
fun paused_registry_blocks_claim() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    let cid = fund_bound(&mut scenario, CLAIMER);

    ts::next_tx(&mut scenario, PUBLISHER);
    {
        let cap = ts::take_from_sender<ChequeAdminCap>(&scenario);
        let mut reg = ts::take_shared<ChequeRegistry>(&scenario);
        cheque::set_paused(&mut reg, &cap, true);
        ts::return_shared(reg);
        ts::return_to_sender(&scenario, cap);
    };

    ts::next_tx(&mut scenario, WORKER);
    let mut reg = ts::take_shared<ChequeRegistry>(&scenario);
    let mut ch = ts::take_shared_by_id<Cheque<SUI>>(&scenario, cid);
    let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut c, EXPIRY - 1);
    cheque::claim<SUI>(&mut reg, &mut ch, CLAIMER, b"", &c, ts::ctx(&mut scenario));
    clock::destroy_for_testing(c);
    ts::return_shared(ch);
    ts::return_shared(reg);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// Expiry gate

#[test, expected_failure(abort_code = cheque::EExpired)]
fun claim_at_expiry_aborts() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    let cid = fund_bound(&mut scenario, CLAIMER);

    ts::next_tx(&mut scenario, WORKER);
    let mut reg = ts::take_shared<ChequeRegistry>(&scenario);
    let mut ch = ts::take_shared_by_id<Cheque<SUI>>(&scenario, cid);
    let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut c, EXPIRY); // exactly at expiry → not < expiry
    cheque::claim<SUI>(&mut reg, &mut ch, CLAIMER, b"", &c, ts::ctx(&mut scenario));
    clock::destroy_for_testing(c);
    ts::return_shared(ch);
    ts::return_shared(reg);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// Double-claim prevention

#[test, expected_failure(abort_code = cheque::EAlreadyClaimed)]
fun double_claim_aborts() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    let cid = fund_bound(&mut scenario, CLAIMER);

    ts::next_tx(&mut scenario, WORKER);
    let mut reg = ts::take_shared<ChequeRegistry>(&scenario);
    let mut ch = ts::take_shared_by_id<Cheque<SUI>>(&scenario, cid);
    let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut c, EXPIRY - 1);
    cheque::claim<SUI>(&mut reg, &mut ch, CLAIMER, b"", &c, ts::ctx(&mut scenario));
    // Double-fired worker call → abort.
    cheque::claim<SUI>(&mut reg, &mut ch, CLAIMER, b"", &c, ts::ctx(&mut scenario));
    clock::destroy_for_testing(c);
    ts::return_shared(ch);
    ts::return_shared(reg);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// v2 — address binding

#[test, expected_failure(abort_code = cheque::ERecipientNotBound)]
fun bound_claim_to_wrong_recipient_aborts() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    // Bound to CLAIMER…
    let cid = fund_bound(&mut scenario, CLAIMER);

    // …but the worker tries to pay RANDO. The CONTRACT refuses, even though
    // the caller is a valid worker — this is the trust-minimized guarantee.
    ts::next_tx(&mut scenario, WORKER);
    let mut reg = ts::take_shared<ChequeRegistry>(&scenario);
    let mut ch = ts::take_shared_by_id<Cheque<SUI>>(&scenario, cid);
    let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut c, EXPIRY - 1);
    cheque::claim<SUI>(&mut reg, &mut ch, RANDO, b"", &c, ts::ctx(&mut scenario));
    clock::destroy_for_testing(c);
    ts::return_shared(ch);
    ts::return_shared(reg);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// v2 — hashlock (bearer claim code)

#[test]
fun hashlock_claim_with_correct_secret_pays() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    let cid = fund_hashlock(&mut scenario);

    ts::next_tx(&mut scenario, WORKER);
    {
        let mut reg = ts::take_shared<ChequeRegistry>(&scenario);
        let mut ch = ts::take_shared_by_id<Cheque<SUI>>(&scenario, cid);
        let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
        clock::set_for_testing(&mut c, EXPIRY - 1);
        // No binding → any recipient, but the secret must match the hashlock.
        cheque::claim<SUI>(&mut reg, &mut ch, CLAIMER, SECRET, &c, ts::ctx(&mut scenario));
        assert!(cheque::is_claimed(&ch));
        clock::destroy_for_testing(c);
        ts::return_shared(ch);
        ts::return_shared(reg);
    };

    ts::next_tx(&mut scenario, CLAIMER);
    let got = ts::take_from_sender<coin::Coin<SUI>>(&scenario);
    assert_eq!(got.value(), AMOUNT);
    coin::burn_for_testing(got);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = cheque::EBadSecret)]
fun hashlock_claim_with_wrong_secret_aborts() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    let cid = fund_hashlock(&mut scenario);

    ts::next_tx(&mut scenario, WORKER);
    let mut reg = ts::take_shared<ChequeRegistry>(&scenario);
    let mut ch = ts::take_shared_by_id<Cheque<SUI>>(&scenario, cid);
    let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut c, EXPIRY - 1);
    // A worker WITHOUT the claim code cannot drain the cheque.
    cheque::claim<SUI>(&mut reg, &mut ch, CLAIMER, b"wrong-code", &c, ts::ctx(&mut scenario));
    clock::destroy_for_testing(c);
    ts::return_shared(ch);
    ts::return_shared(reg);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// Reclaim (creator void) + mutual exclusion

#[test]
fun creator_reclaims_unclaimed_cheque() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    let cid = fund_bound(&mut scenario, CLAIMER);

    ts::next_tx(&mut scenario, CREATOR);
    {
        let mut ch = ts::take_shared_by_id<Cheque<SUI>>(&scenario, cid);
        let c = clock::create_for_testing(ts::ctx(&mut scenario));
        let back = cheque::reclaim<SUI>(&mut ch, &c, ts::ctx(&mut scenario));
        assert_eq!(back.value(), AMOUNT);
        assert!(cheque::is_claimed(&ch)); // terminal
        coin::burn_for_testing(back);
        clock::destroy_for_testing(c);
        ts::return_shared(ch);
    };
    ts::end(scenario);
}

#[test, expected_failure(abort_code = cheque::ENotCreator)]
fun non_creator_reclaim_aborts() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    let cid = fund_bound(&mut scenario, CLAIMER);

    ts::next_tx(&mut scenario, RANDO);
    let mut ch = ts::take_shared_by_id<Cheque<SUI>>(&scenario, cid);
    let c = clock::create_for_testing(ts::ctx(&mut scenario));
    let stolen = cheque::reclaim<SUI>(&mut ch, &c, ts::ctx(&mut scenario));
    coin::burn_for_testing(stolen);
    clock::destroy_for_testing(c);
    ts::return_shared(ch);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = cheque::EAlreadyClaimed)]
fun reclaim_after_claim_aborts() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    let cid = fund_bound(&mut scenario, CLAIMER);

    // Worker claims first.
    ts::next_tx(&mut scenario, WORKER);
    {
        let mut reg = ts::take_shared<ChequeRegistry>(&scenario);
        let mut ch = ts::take_shared_by_id<Cheque<SUI>>(&scenario, cid);
        let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
        clock::set_for_testing(&mut c, EXPIRY - 1);
        cheque::claim<SUI>(&mut reg, &mut ch, CLAIMER, b"", &c, ts::ctx(&mut scenario));
        clock::destroy_for_testing(c);
        ts::return_shared(ch);
        ts::return_shared(reg);
    };

    // Creator's reclaim must now abort — funds already went to CLAIMER.
    ts::next_tx(&mut scenario, CREATOR);
    let mut ch = ts::take_shared_by_id<Cheque<SUI>>(&scenario, cid);
    let c = clock::create_for_testing(ts::ctx(&mut scenario));
    let dbl = cheque::reclaim<SUI>(&mut ch, &c, ts::ctx(&mut scenario));
    coin::burn_for_testing(dbl);
    clock::destroy_for_testing(c);
    ts::return_shared(ch);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = cheque::EAlreadyClaimed)]
fun claim_after_reclaim_aborts() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    let cid = fund_bound(&mut scenario, CLAIMER);

    // Creator voids it first.
    ts::next_tx(&mut scenario, CREATOR);
    {
        let mut ch = ts::take_shared_by_id<Cheque<SUI>>(&scenario, cid);
        let c = clock::create_for_testing(ts::ctx(&mut scenario));
        let back = cheque::reclaim<SUI>(&mut ch, &c, ts::ctx(&mut scenario));
        coin::burn_for_testing(back);
        clock::destroy_for_testing(c);
        ts::return_shared(ch);
    };

    // Worker claim must now abort — cheque is terminal.
    ts::next_tx(&mut scenario, WORKER);
    let mut reg = ts::take_shared<ChequeRegistry>(&scenario);
    let mut ch = ts::take_shared_by_id<Cheque<SUI>>(&scenario, cid);
    let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut c, EXPIRY - 1);
    cheque::claim<SUI>(&mut reg, &mut ch, CLAIMER, b"", &c, ts::ctx(&mut scenario));
    clock::destroy_for_testing(c);
    ts::return_shared(ch);
    ts::return_shared(reg);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// v2 — permissionless reclaim_expired

#[test]
fun reclaim_expired_returns_to_creator_permissionlessly() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    let cid = fund_bound(&mut scenario, CLAIMER);

    // RANDO (no role at all) cranks the expired cheque.
    ts::next_tx(&mut scenario, RANDO);
    {
        let mut ch = ts::take_shared_by_id<Cheque<SUI>>(&scenario, cid);
        let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
        clock::set_for_testing(&mut c, EXPIRY); // at expiry → reclaimable
        cheque::reclaim_expired<SUI>(&mut ch, &c, ts::ctx(&mut scenario));
        assert!(cheque::is_claimed(&ch));
        assert_eq!(cheque::escrow_value(&ch), 0);
        clock::destroy_for_testing(c);
        ts::return_shared(ch);
    };

    // Funds landed with CREATOR — not RANDO, not CLAIMER.
    ts::next_tx(&mut scenario, CREATOR);
    {
        let got = ts::take_from_sender<coin::Coin<SUI>>(&scenario);
        assert_eq!(got.value(), AMOUNT);
        coin::burn_for_testing(got);
    };
    ts::next_tx(&mut scenario, RANDO);
    assert!(!ts::has_most_recent_for_sender<coin::Coin<SUI>>(&scenario));
    ts::end(scenario);
}

#[test, expected_failure(abort_code = cheque::ENotExpired)]
fun reclaim_expired_before_expiry_aborts() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    let cid = fund_bound(&mut scenario, CLAIMER);

    ts::next_tx(&mut scenario, RANDO);
    let mut ch = ts::take_shared_by_id<Cheque<SUI>>(&scenario, cid);
    let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut c, EXPIRY - 1); // not yet expired
    cheque::reclaim_expired<SUI>(&mut ch, &c, ts::ctx(&mut scenario));
    clock::destroy_for_testing(c);
    ts::return_shared(ch);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = cheque::EAlreadyClaimed)]
fun reclaim_expired_after_claim_aborts() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);
    let cid = fund_bound(&mut scenario, CLAIMER);

    // Worker claims before expiry.
    ts::next_tx(&mut scenario, WORKER);
    {
        let mut reg = ts::take_shared<ChequeRegistry>(&scenario);
        let mut ch = ts::take_shared_by_id<Cheque<SUI>>(&scenario, cid);
        let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
        clock::set_for_testing(&mut c, EXPIRY - 1);
        cheque::claim<SUI>(&mut reg, &mut ch, CLAIMER, b"", &c, ts::ctx(&mut scenario));
        clock::destroy_for_testing(c);
        ts::return_shared(ch);
        ts::return_shared(reg);
    };

    // Then someone tries reclaim_expired after expiry — already terminal.
    ts::next_tx(&mut scenario, RANDO);
    let mut ch = ts::take_shared_by_id<Cheque<SUI>>(&scenario, cid);
    let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut c, EXPIRY + 1);
    cheque::reclaim_expired<SUI>(&mut ch, &c, ts::ctx(&mut scenario));
    clock::destroy_for_testing(c);
    ts::return_shared(ch);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// create input validation

#[test, expected_failure(abort_code = cheque::EZeroAmount)]
fun create_rejects_zero_funds() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);

    ts::next_tx(&mut scenario, CREATOR);
    let mut reg = ts::take_shared<ChequeRegistry>(&scenario);
    let c = clock::create_for_testing(ts::ctx(&mut scenario));
    let funds = balance::zero<SUI>();
    let _cid = cheque::create<SUI>(
        &mut reg, funds, EXPIRY, option::some(CLAIMER), option::none(), &c, ts::ctx(&mut scenario),
    );
    clock::destroy_for_testing(c);
    ts::return_shared(reg);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = cheque::EBadExpiry)]
fun create_rejects_past_expiry() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);

    ts::next_tx(&mut scenario, CREATOR);
    let mut reg = ts::take_shared<ChequeRegistry>(&scenario);
    let mut c = clock::create_for_testing(ts::ctx(&mut scenario));
    clock::set_for_testing(&mut c, 50_000);
    let funds = coin::mint_for_testing<SUI>(AMOUNT, ts::ctx(&mut scenario)).into_balance();
    // expiry 40_000 < now 50_000 → abort.
    let _cid = cheque::create<SUI>(
        &mut reg, funds, 40_000, option::some(CLAIMER), option::none(), &c, ts::ctx(&mut scenario),
    );
    clock::destroy_for_testing(c);
    ts::return_shared(reg);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = cheque::ENoClaimCondition)]
fun create_rejects_no_condition() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);

    ts::next_tx(&mut scenario, CREATOR);
    let mut reg = ts::take_shared<ChequeRegistry>(&scenario);
    let c = clock::create_for_testing(ts::ctx(&mut scenario));
    let funds = coin::mint_for_testing<SUI>(AMOUNT, ts::ctx(&mut scenario)).into_balance();
    // Neither a binding nor a hashlock → refused.
    let _cid = cheque::create<SUI>(
        &mut reg, funds, EXPIRY, option::none(), option::none(), &c, ts::ctx(&mut scenario),
    );
    clock::destroy_for_testing(c);
    ts::return_shared(reg);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = cheque::EBadSecret)]
fun create_rejects_malformed_hashlock() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);

    ts::next_tx(&mut scenario, CREATOR);
    let mut reg = ts::take_shared<ChequeRegistry>(&scenario);
    let c = clock::create_for_testing(ts::ctx(&mut scenario));
    let funds = coin::mint_for_testing<SUI>(AMOUNT, ts::ctx(&mut scenario)).into_balance();
    // A 3-byte "hashlock" is not a sha2-256 digest → refused.
    let _cid = cheque::create<SUI>(
        &mut reg, funds, EXPIRY, option::none(), option::some(b"abc"), &c, ts::ctx(&mut scenario),
    );
    clock::destroy_for_testing(c);
    ts::return_shared(reg);
    ts::end(scenario);
}

// ───────────────────────────────────────────────────────────────────
// Worker management

#[test]
fun remove_worker_revokes_claim_ability() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);
    grant_worker(&mut scenario);

    ts::next_tx(&mut scenario, PUBLISHER);
    let cap = ts::take_from_sender<ChequeAdminCap>(&scenario);
    let mut reg = ts::take_shared<ChequeRegistry>(&scenario);
    assert!(cheque::is_worker(&reg, WORKER));
    cheque::remove_worker(&mut reg, &cap, WORKER);
    assert!(!cheque::is_worker(&reg, WORKER));
    ts::return_shared(reg);
    ts::return_to_sender(&scenario, cap);
    ts::end(scenario);
}

#[test, expected_failure(abort_code = cheque::EWorkerAlreadyAdded)]
fun add_worker_twice_aborts() {
    let mut scenario = ts::begin(PUBLISHER);
    setup_registry(&mut scenario);

    ts::next_tx(&mut scenario, PUBLISHER);
    let cap = ts::take_from_sender<ChequeAdminCap>(&scenario);
    let mut reg = ts::take_shared<ChequeRegistry>(&scenario);
    cheque::add_worker(&mut reg, &cap, WORKER);
    cheque::add_worker(&mut reg, &cap, WORKER);
    ts::return_shared(reg);
    ts::return_to_sender(&scenario, cap);
    ts::end(scenario);
}
