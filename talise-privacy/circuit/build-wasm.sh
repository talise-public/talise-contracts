#!/bin/bash
# Build the Talise privacy circuit to WASM and stage it for the web app.
#
# Outputs:
#   pkg/web/      — wasm-bindgen `--target web` glue + binary (browser/worker)
#   pkg/nodejs/   — wasm-bindgen `--target nodejs` glue (test harness)
#
# Then copies the web artifacts + dev keys into web/public/shield/ so the
# Web Worker prover (web/lib/shield/sdk/prover.worker.ts) can fetch them as
# static assets.
#
# Requires: wasm-pack, the wasm32-unknown-unknown target
#   (rustup target add wasm32-unknown-unknown; cargo install wasm-pack)
set -euo pipefail

CIRCUIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# repo_root/move/talise-privacy/circuit -> repo_root
REPO_ROOT="$(cd "$CIRCUIT_DIR/../../.." && pwd)"
PUBLIC_SHIELD="$REPO_ROOT/web/public/shield"

if ! command -v wasm-pack &>/dev/null; then
  echo "Error: wasm-pack not installed. Run: cargo install wasm-pack" >&2
  exit 1
fi

echo "Building WASM (web target)..."
wasm-pack build "$CIRCUIT_DIR" --target web --out-dir "$CIRCUIT_DIR/pkg/web" --release

echo "Building WASM (nodejs target, for tests)..."
wasm-pack build "$CIRCUIT_DIR" --target nodejs --out-dir "$CIRCUIT_DIR/pkg/nodejs" --release

echo "Staging web artifacts + dev keys into web/public/shield/ ..."
mkdir -p "$PUBLIC_SHIELD"
cp "$CIRCUIT_DIR/pkg/web/talise_privacy_circuit.js"        "$PUBLIC_SHIELD/"
cp "$CIRCUIT_DIR/pkg/web/talise_privacy_circuit_bg.wasm"   "$PUBLIC_SHIELD/"
cp "$CIRCUIT_DIR/pkg/web/talise_privacy_circuit.d.ts"      "$PUBLIC_SHIELD/"
cp "$CIRCUIT_DIR/keys/proving_key.bin"                      "$PUBLIC_SHIELD/"
cp "$CIRCUIT_DIR/keys/vk_sui.hex"                           "$PUBLIC_SHIELD/"

echo "Done. Test with: node $CIRCUIT_DIR/test/wasm_prove.test.mjs"
