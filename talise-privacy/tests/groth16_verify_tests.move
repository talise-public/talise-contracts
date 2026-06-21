/// Talise privacy — the on-chain Groth16 verify gate (Workstream A).
///
/// This is the "test a shielded tx" VERIFY path in isolation: it exercises the
/// exact native call `shielded_pool::process_transaction` makes in step 6 —
///
///   curve.verify_groth16_proof(&pvk, &public_inputs, &proof_points)
///
/// — against the BN254 curve, the package verifying key, a 128-byte proof
/// (A32‖B64‖C32), and the 8 ordered 32-byte LE public inputs
/// ([pool, root, public_value, null0, null1, comm0, comm1, hashed_secret]).
///
/// ── ONE-PASTE ACTIVATION ──────────────────────────────────────────────────
/// A parallel agent is producing the real Rust/arkworks-generated triple
/// (VK + proof + public inputs) that satisfies the circuit. When it lands:
///
///   1. paste the three hex blobs into VK_HEX / PROOF_HEX / PUBLIC_INPUTS_HEX,
///   2. flip `PROOF_AVAILABLE` to `true`.
///
/// That ONE flag turns the real on-chain verify assertion on. Until then the
/// real-proof test SKIPS its assertion (it does NOT fail) so the suite stays
/// green without a placeholder masquerading as a passing proof.
///
/// The WRONG-proof guard (`verify_rejects_zero_proof`) needs no real triple and
/// is enabled now: it feeds 128 zero bytes against the same VK + public inputs
/// and proves the native verifier returns `false`.
#[test_only]
module talise_privacy::groth16_verify_tests;

use sui::groth16;
use talise_privacy::constants;

// ── THE REAL TRIPLE (paste here) ───────────────────────────────────────────
// Flip this to `true` once the three hex constants below carry the real
// Rust-generated values. While `false`, `verify_accepts_real_proof` skips its
// assertion so CI stays green.
// ACTIVATED — real deposit proof (1000 = 600+400) from the talise-privacy
// circuit crate (dev keys, OsRng entropy). The on-chain sui::groth16 verify
// now asserts this proof is ACCEPTED — a real shielded-tx verify, end to end.
const PROOF_AVAILABLE: bool = true;

/// Verifying key bytes — the format `groth16::prepare_verifying_key` parses.
/// MATCHED PAIR with PROOF_HEX (same dev keygen run).
const VK_HEX: vector<u8> =
    x"520a8b864b70eb8d801f32760562754f1d7e4e38cbdb28d668b2be9277ba7c022a5eebe30f82ace3fcb4955a860bb52aedc4ca114c2b68dadebb36488220540a5d055500150abf8260a8a7bd467299e9cbd55c4fd80df4bc6a9d22df1dbe1f2f6758de37a6c3e9885c7f14eaa5d622ee3077a5b9419b14ff8fbbebed56210a1fe1297cedbc3021bb963c89788adeb23efc53edfd081e8ace1efd8d3c290f8f82522c865ccd1e8b34deb063d428aca44a2b1c54bccfd97dd59cf42e7944731a23e26b37b2fa7e07b0f41f2cdd070ee5526aa4111dbf1752bf6d1959dbcb3ce6280900000000000000739afa7f7a2184f0c52fa88614ed0eda540da9c5f8a1198418dfd995924a3ea058aa615a6b58482a8f2dfe1092ba13cc059909473452e2bf75d9157232767c002f5e6da8d3992c3dcc5733d6e7a5de71d88018a5ac136686a70c9001d6cb183014871ac6ee6c8c4eefa5675d458561f3a98ce16027160915ce38a93d31e8f6ae243f6470f923577afcc87cbd255c18b49c9ff2a416c6288d5db8a83c08b73c9ef49d4191d643d9dda4ee35d5924a1701e19e28ab99e3e42c2e61230ffe93a50b6e9f5ae3885fbac0163099bad9fc9414e2cb2c0b03df8e51f0f1efcf1286b3127a058e5bfade299b0d4af628979d6f53b8c701027c202b40d629dc9adbb66f045e91da91eb8ff37f04fe006c7045c0b6b92b4522107c7a4d7e715114f34ce91d";

/// Proof points: 128 bytes == A(32) ‖ B(64) ‖ C(32), arkworks-compressed.
const PROOF_HEX: vector<u8> =
    x"00b043b23c0ecd869564f1da1c9d1b69ceeefeaf323dfd1de45899613a4726067f87e852810fa670116a5da702d48c25bf5d3ac2543c0693150738a6a97d04076d486d097811c7fdf2197f9ffb5ec19b2a9e836baf585582e5ede40026d71f132dc4b054605b44f0348d1a72ebc52730af9773f696992c6802c7edbbfbdb410d";

/// Public inputs: 8 × 32-byte little-endian field elements, in the fixed order
/// [pool, root, public_value, null0, null1, comm0, comm1, hashed_secret].
/// public_value = 1000 (0x3e8) confirms the deposit amount in the clear.
const PUBLIC_INPUTS_HEX: vector<u8> =
    x"01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e80300000000000000000000000000000000000000000000000000000000000068b59b5fc66d054e1d339dce435e50b8e1525d7c0b30c34bdaa67a3c7bc23425e768d3af10f791ea50d1cbc9ffd770ef6805ce05e748d6d571f98665dd99600ff7a09a217f9c58811c8a03387e65e5a56e0675b7f6bd4656be6144c68495de2c935e2af009e2e7403f54ca670f378eaa4b36aa8ab6ee3e4bec57af64172f34054327c5b27e5de1dd5cbe8085f170fd65d03be5b19983387108dfedebaf8d401b";

// 128 zero bytes — a structurally-valid but cryptographically-bogus proof.
const ZERO_PROOF: vector<u8> =
    x"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/// Real-proof test. SKIPPED (assertion not run) while `PROOF_AVAILABLE` is
/// `false`. Flip the flag + paste the real triple to turn the on-chain verify
/// assertion on.
#[test]
fun verify_accepts_real_proof() {
    if (!PROOF_AVAILABLE) return; // skip — no real triple yet (CI stays green).

    let curve = groth16::bn254();
    let pvk = groth16::prepare_verifying_key(&curve, &VK_HEX);
    let proof_points = groth16::proof_points_from_bytes(PROOF_HEX);
    let public_inputs = groth16::public_proof_inputs_from_bytes(PUBLIC_INPUTS_HEX);

    assert!(
        curve.verify_groth16_proof(&pvk, &public_inputs, &proof_points),
        0,
    );
}

/// WRONG-proof guard — enabled now (no real triple required). Feeds 128 zero
/// bytes as the proof against the package VK + 8 zero public inputs and proves
/// the native verifier REJECTS it (returns `false`). This is the soundness
/// floor: a bogus proof must never verify.
#[test]
fun verify_rejects_zero_proof() {
    let curve = groth16::bn254();
    let pvk = groth16::prepare_verifying_key(&curve, &constants::verifying_key!());
    let proof_points = groth16::proof_points_from_bytes(ZERO_PROOF);

    // 8 × 32-byte zero field elements (256 bytes), the same input arity the
    // circuit uses.
    let public_inputs = groth16::public_proof_inputs_from_bytes(
        x"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    );

    assert!(
        !curve.verify_groth16_proof(&pvk, &public_inputs, &proof_points),
        1,
    );
}
