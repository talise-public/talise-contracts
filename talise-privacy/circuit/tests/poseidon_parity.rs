//! Poseidon arity-1/3/4 PARITY GATE (Workstream B).
//!
//! The shielded-pool SDK assembles note witnesses in JS using
//! `@mysten/sui/zklogin`'s `poseidonHash` (pubkey = Poseidon1, nullifier =
//! Poseidon3, commitment = Poseidon4). The on-chain verifier checks a proof made
//! by the circuit's `poseidon_opt`. If the two Poseidons disagree at ANY arity
//! the SDK-built witness won't satisfy the circuit and no deposit is spendable.
//!
//! Arity-2 (the Merkle hash) was already proven equal to `sui::poseidon_bn254`
//! on-chain (poseidon_root_tests). These are the arity-1/3/4 known-answer
//! vectors, VERIFIED byte-identical to `@mysten` poseidonHash on 2026-06-17:
//!   poseidonHash([1])        == hash1
//!   poseidonHash([1,2,3])    == hash3
//!   poseidonHash([1,2,3,4])  == hash4
//! (poseidonHash([1]) is also the canonical circomlib poseidon([1]).)
use ark_bn254::Fr;
use ark_ff::PrimeField;
use talise_privacy_circuit::poseidon_opt::{hash1, hash3, hash4};

#[test]
fn arity_1_3_4_match_mysten_poseidon() {
    assert_eq!(
        format!("{}", hash1(&Fr::from(1u64)).into_bigint()),
        "18586133768512220936620570745912940619677854269274689475585506675881198879027",
        "hash1 diverged from @mysten poseidonHash([1])"
    );
    assert_eq!(
        format!("{}", hash3(&Fr::from(1u64), &Fr::from(2u64), &Fr::from(3u64)).into_bigint()),
        "6542985608222806190361240322586112750744169038454362455181422643027100751666",
        "hash3 diverged from @mysten poseidonHash([1,2,3])"
    );
    assert_eq!(
        format!("{}", hash4(&Fr::from(1u64), &Fr::from(2u64), &Fr::from(3u64), &Fr::from(4u64)).into_bigint()),
        "18821383157269793795438455681495246036402687001665670618754263018637548127333",
        "hash4 diverged from @mysten poseidonHash([1,2,3,4])"
    );
}
