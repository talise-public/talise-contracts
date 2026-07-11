#!/usr/bin/env bash
# Publish the `talise_payroll` Move package to a chosen Sui environment and
# print the single env var you need: PAYROLL_PACKAGE_ID.
#
# Usage:
#   scripts/deploy.sh [testnet|mainnet]    # default: testnet
#
# Pre-flight:
#   • `sui` CLI installed and pointing at the right env (`sui client envs`).
#   • The active address holds enough SUI on the chosen network to cover the
#     publish gas (≈0.2 SUI on mainnet at typical prices).
#
# What it does, in order:
#   1. Sanity-check we're on the requested env (offer to switch if not).
#   2. `sui move build` — fail fast on compile errors.
#   3. `sui move test` — refuse to publish a package with failing tests.
#   4. `sui client publish --gas-budget 200000000 --json` — capture output.
#   5. Parse the JSON for the published package id.
#   6. Print the PAYROLL_PACKAGE_ID line to paste into Vercel.
#
# This package has NO init / registry — each Team is a self-contained,
# owner-gated shared object, so there's nothing else to record.

set -euo pipefail

ENV_ARG="${1:-testnet}"
case "$ENV_ARG" in
  testnet|mainnet) : ;;
  *)
    echo "error: env must be 'testnet' or 'mainnet', got '$ENV_ARG'" >&2
    exit 1
    ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PACKAGE_DIR"

echo "» talise_payroll Move publish → $ENV_ARG"
echo "» package dir: $PACKAGE_DIR"
echo

# ── 1. Verify the active sui-cli env ───────────────────────────────────
ACTIVE_ENV="$(sui client active-env 2>/dev/null || true)"
if [ "$ACTIVE_ENV" != "$ENV_ARG" ]; then
  echo "» active sui env is '$ACTIVE_ENV', expected '$ENV_ARG'."
  echo "  switching: sui client switch --env $ENV_ARG"
  sui client switch --env "$ENV_ARG"
fi
echo "» active address: $(sui client active-address)"
echo

# ── 2 + 3. Build + test (refuse to publish a broken package) ───────────
echo "» sui move build"
sui move build
echo "» sui move test"
sui move test
echo

# ── 4. Publish ─────────────────────────────────────────────────────────
RECEIPT="$(mktemp -t talise_payroll_publish.XXXXXX.json)"
echo "» sui client publish --gas-budget 200000000"
sui client publish --gas-budget 200000000 --json >"$RECEIPT"

# ── 5. Parse the published package id ──────────────────────────────────
PACKAGE_ID="$(
  python3 - "$RECEIPT" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
for ch in data.get("objectChanges", []):
    if ch.get("type") == "published":
        print(ch.get("packageId", ""))
        break
PY
)"

if [ -z "$PACKAGE_ID" ]; then
  echo "error: couldn't find a published packageId in the receipt: $RECEIPT" >&2
  exit 1
fi

# ── 6. Print the env var ───────────────────────────────────────────────
echo
echo "──────────────────────────────────────────────────────────────"
echo "✓ published talise_payroll → $ENV_ARG"
echo
echo "Set this in Vercel (all scopes) to light up on-chain teams:"
echo
echo "PAYROLL_PACKAGE_ID=$PACKAGE_ID"
echo
echo "(receipt: $RECEIPT)"
echo "──────────────────────────────────────────────────────────────"
