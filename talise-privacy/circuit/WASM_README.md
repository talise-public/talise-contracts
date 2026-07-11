# Talise privacy circuit — browser (WASM) prover

The arkworks BN254 Groth16 circuit in this crate proves IN THE BROWSER via a
WebAssembly build, wired into the web SDK and run off the main thread in a Web
Worker.

## What's exported (WASM)

`src/wasm/mod.rs` (compiled only for `target_arch = "wasm32"`, gated in
`lib.rs`, so the native crate — `prove_deposit`, `cargo test` — is untouched):

- `prove(input_json: string, proving_key_hex: string) -> string`
  Returns JSON `{ proofA, proofB, proofC, publicInputs, proofSerializedHex,
  publicInputsSerializedHex }`.
  - `proofA`/`proofB`/`proofC` — compressed G1/G2/G1 (32/64/32 bytes).
  - `proofSerializedHex` — `proofA‖proofB‖proofC` (128 bytes), exactly what the
    Move verifier (`groth16::proof_points_from_bytes`) consumes.
  - `publicInputs` — 8 decimal strings, allocation order
    `[pool, root, public_value, null0, null1, comm0, comm1, hashed_secret]`.
  - `publicInputsSerializedHex` — 8 × 32-byte LITTLE-ENDIAN field elements
    (256 bytes), the Move `bcs::to_bytes(&u256)` layout.
- `verify(proof_json: string, verifying_key_hex: string) -> bool`
  In-wasm Groth16 verify (self-check before submitting to chain).
- `build_deposit_input(pool_hex, root_dec, amount, out0, out1) -> string`
  Assembles a valid DEPOSIT `ProofInput` JSON (dummy zero input notes + two
  output notes summing to `amount`), so JS doesn't reimplement Poseidon.

### Entropy

Proof randomness uses `rand::rngs::OsRng`, which on wasm32 is backed by
`getrandom` with the **`js`** feature (`crypto.getRandomValues`). This is REAL
entropy — NOT the fixed `ChaCha20Rng::from_seed([0u8; 32])` the upstream Vortex
wasm prover used. Two proofs of the same witness differ (the test asserts this).

## Build

```bash
# one-time: rustup target add wasm32-unknown-unknown; cargo install wasm-pack
./build-wasm.sh
```

Produces:
- `pkg/web/`    — `--target web` glue + `*_bg.wasm` (browser / worker)
- `pkg/nodejs/` — `--target nodejs` glue (test harness)

and copies the web artifacts + dev keys into `web/public/shield/`.
`pkg/` is git-ignored (regenerate from source).

## Where the proving key is hosted

The web app serves everything as static assets from **`web/public/shield/`**:

| asset | size | purpose |
|-------|------|---------|
| `talise_privacy_circuit.js` | ~18 KB | wasm-bindgen web glue |
| `talise_privacy_circuit_bg.wasm` | ~1.4 MB | circuit binary |
| `proving_key.bin` | ~3.8 MB | arkworks compressed proving key |
| `vk_sui.hex` | ~1 KB | verifying key (Sui format) |

The client (`web/lib/shield/sdk/prover.ts`) fetches `proving_key.bin` ONCE and
caches it in **IndexedDB** (`talise-shield`/`keys`, key `proving_key:v1`) plus an
in-memory copy, so repeat sessions skip the 3.8 MB download. Bump `PK_CACHE_VER`
in `prover.ts` whenever the dev keys are regenerated.

> These are DEV/TEST keys (locally generated, not a trusted-setup ceremony).
> Do NOT secure real funds with them.

## SDK wiring (web/lib/shield/sdk/)

- `prover.worker.ts` — Web Worker: loads the wasm glue, instantiates the binary,
  runs `prove`/`verify` off the main thread.
- `prover.ts` — main-thread client: `prove(input) -> ProofOutput`,
  `verifyProof(proof)`, `preloadProvingKey()`, plus the IndexedDB key cache.
- `tx.ts` — `proveTransact(input)` closes the WASM-prove seam: it runs `prove()`
  and maps the result into the `ProofInputs` (128-byte proof points + public
  signals as bigints) that `buildTransact` assembles into the transact PTB.

## Test

```bash
node test/wasm_prove.test.mjs
```

Loads the persisted dev keys, builds a deposit witness via
`build_deposit_input`, proves in-wasm with real entropy, and asserts:
proofA/B/C are 32/64/32 bytes, 128-byte serialized proof, 8 public inputs
(public_value == 1000), **in-wasm verify == true**, two proofs differ
(real entropy), and a tampered proof is rejected.
