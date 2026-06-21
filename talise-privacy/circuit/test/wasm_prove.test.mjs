// Node test harness for the Talise privacy WASM prover.
//
// Loads the persisted DEV proving/verifying keys, builds a DEPOSIT witness via
// the wasm `build_deposit_input` helper, proves with real entropy in-wasm, and
// confirms the proof verifies in-wasm against the verifying key.
//
// Run:  node test/wasm_prove.test.mjs
// (requires `wasm-pack build --target nodejs --out-dir pkg/nodejs --release`)
//
// Exits non-zero on any failure.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { prove, verify, build_deposit_input } from "../pkg/nodejs/talise_privacy_circuit.js";

const here = dirname(fileURLToPath(import.meta.url));
const keysDir = join(here, "..", "keys");

function hexFromBin(p) {
  return readFileSync(p).toString("hex");
}

function main() {
  const provingKeyHex = hexFromBin(join(keysDir, "proving_key.bin"));
  const verifyingKeyHex = readFileSync(join(keysDir, "vk_sui.hex"), "utf8").trim();

  console.log(`[setup] proving key:   ${provingKeyHex.length / 2} bytes`);
  console.log(`[setup] verifying key: ${verifyingKeyHex.length / 2} bytes`);

  // Deposit of 1000, split 600 + 400, into pool 0x1, root 0.
  const inputJson = build_deposit_input("0x1", "0", 1000n, 600n, 400n);

  // Prove (measure latency).
  const t0 = performance.now();
  const proofJson = prove(inputJson, provingKeyHex);
  const t1 = performance.now();

  const proof = JSON.parse(proofJson);

  // Structural assertions.
  const aLen = proof.proofA.length;
  const bLen = proof.proofB.length;
  const cLen = proof.proofC.length;
  const proofBytes = proof.proofSerializedHex.length / 2;
  const pubBytes = proof.publicInputsSerializedHex.length / 2;

  console.log(`[prove] latency: ${(t1 - t0).toFixed(0)} ms`);
  console.log(`[prove] proofA/B/C bytes: ${aLen}/${bLen}/${cLen}`);
  console.log(`[prove] proofSerializedHex: ${proofBytes} bytes`);
  console.log(`[prove] publicInputs (${proof.publicInputs.length}): ${JSON.stringify(proof.publicInputs)}`);
  console.log(`[prove] publicInputsSerializedHex: ${pubBytes} bytes`);

  const fail = (m) => {
    console.error(`FAIL: ${m}`);
    process.exit(1);
  };

  if (aLen !== 32) fail(`proofA must be 32 bytes, got ${aLen}`);
  if (bLen !== 64) fail(`proofB must be 64 bytes, got ${bLen}`);
  if (cLen !== 32) fail(`proofC must be 32 bytes, got ${cLen}`);
  if (proofBytes !== 128) fail(`proofSerializedHex must be 128 bytes, got ${proofBytes}`);
  if (proof.publicInputs.length !== 8) fail(`expected 8 public inputs, got ${proof.publicInputs.length}`);
  if (pubBytes !== 8 * 32) fail(`publicInputsSerializedHex must be 256 bytes, got ${pubBytes}`);

  // public_value (index 2) must equal the deposit amount.
  if (proof.publicInputs[2] !== "1000") fail(`public_value should be 1000, got ${proof.publicInputs[2]}`);

  // In-wasm verify against the VK.
  const ok = verify(proofJson, verifyingKeyHex);
  if (!ok) fail("proof did NOT verify against the verifying key");
  console.log("[verify] in-wasm Groth16 verify: PASS");

  // Real-entropy check: two proves of the same witness must differ (no fixed seed).
  const proof2 = JSON.parse(prove(inputJson, provingKeyHex));
  if (proof2.proofSerializedHex === proof.proofSerializedHex) {
    fail("two proofs were identical — randomness is NOT real entropy (fixed seed?)");
  }
  console.log("[entropy] two proofs differ: PASS (real entropy)");

  // Negative: tampered proof bytes must NOT verify.
  const tampered = { ...proof };
  const buf = Buffer.from(proof.proofSerializedHex, "hex");
  buf[0] ^= 0xff;
  tampered.proofSerializedHex = buf.toString("hex");
  let tamperedOk = false;
  try {
    tamperedOk = verify(JSON.stringify(tampered), verifyingKeyHex);
  } catch {
    tamperedOk = false; // deserialize/verify error == rejected, which is correct
  }
  if (tamperedOk) fail("tampered proof verified — verifier is broken");
  console.log("[verify] tampered proof rejected: PASS");

  console.log("\nALL WASM PROVER TESTS PASSED");
}

main();
