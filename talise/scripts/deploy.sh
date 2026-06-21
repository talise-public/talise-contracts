#!/usr/bin/env bash
# Publish the `talise` Move package to a chosen Sui environment, then
# extract the published package id + the shared `AutoSwapRegistry`
# object id from the publish receipt. Print the env-var lines you need
# to paste into Vercel and the Onara worker.
#
# Usage:
#   scripts/deploy.sh [testnet|mainnet]    # default: testnet
#
# Pre-flight:
#   • `sui` CLI installed and pointing at the right env (`sui client envs`).
#   • The active address holds enough SUI on the chosen network to
#     cover the publish gas (≈0.3 SUI on mainnet at typical prices).
#   • You're in the `move/talise` directory or one of its parents.
#
# What it does, in order:
#   1. Sanity-check we're on the requested env (offer to switch if not).
#   2. `sui move build` — fail fast on compile errors.
#   3. `sui move test` — refuse to publish a package with failing tests.
#   4. `sui client publish --gas-budget 200000000 --json` — capture output.
#   5. Parse the JSON for the two important ids and the AdminCap.
#   6. Print the env-var snippet for Vercel + Onara.
#
# We DON'T:
#   • Auto-set the env vars anywhere — that's your call and varies by
#     deployment platform. Copy the lines into the right place.
#   • Confirm the publish — `sui client publish` already prompts on
#     mainnet.

set -euo pipefail

ENV_ARG="${1:-testnet}"
case "$ENV_ARG" in
  testnet|mainnet)
    : # accepted
    ;;
  *)
    echo "error: env must be 'testnet' or 'mainnet', got '$ENV_ARG'" >&2
    exit 1
    ;;
esac

# Move to the package directory regardless of where the script was invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PACKAGE_DIR"

echo "» Talise Move publish → $ENV_ARG"
echo "» package dir: $PACKAGE_DIR"
echo

# ── 1. Verify the active sui-cli env ───────────────────────────────────
ACTIVE_ENV="$(sui client active-env 2>/dev/null || true)"
if [ "$ACTIVE_ENV" != "$ENV_ARG" ]; then
  echo "» active sui env is '$ACTIVE_ENV', expected '$ENV_ARG'."
  echo "  switching: sui client switch --env $ENV_ARG"
  sui client switch --env "$ENV_ARG"
fi

ACTIVE_ADDR="$(sui client active-address)"
echo "» publishing from address: $ACTIVE_ADDR"
echo "  (this address will hold the AdminCap and will be set as registry.admin)"
echo

# ── 2. Build ───────────────────────────────────────────────────────────
echo "» sui move build"
sui move build > /dev/null
echo "  ok"

# ── 3. Test ────────────────────────────────────────────────────────────
echo "» sui move test"
TEST_OUT="$(sui move test 2>&1)"
if ! echo "$TEST_OUT" | grep -q "Test result: OK"; then
  echo "$TEST_OUT" | tail -30
  echo
  echo "error: tests failed — refusing to publish a broken package" >&2
  exit 1
fi
echo "  $(echo "$TEST_OUT" | grep "Test result:")"

# ── 4. Publish ─────────────────────────────────────────────────────────
echo
echo "» sui client publish --gas-budget 200000000 --json"
echo "  (mainnet will prompt for confirmation — review the gas cost before approving)"
PUBLISH_RECEIPT="$(mktemp -t talise-publish-XXXXXX.json)"
trap 'rm -f "$PUBLISH_RECEIPT"' EXIT

sui client publish --gas-budget 200000000 --json > "$PUBLISH_RECEIPT"
echo "  publish receipt: $PUBLISH_RECEIPT"

# ── 5. Parse ───────────────────────────────────────────────────────────
# Package id: the `published` object_id in objectChanges.
PACKAGE_ID="$(jq -r '
  .objectChanges[]?
  | select(.type == "published")
  | .packageId
' "$PUBLISH_RECEIPT" | head -n1)"

if [ -z "$PACKAGE_ID" ] || [ "$PACKAGE_ID" == "null" ]; then
  echo "error: could not find packageId in publish receipt" >&2
  cat "$PUBLISH_RECEIPT" | tail -40 >&2
  exit 1
fi

# Registry id: the created object whose objectType contains
# `::auto_swap::AutoSwapRegistry`. Use jq's contains() because the
# fully-qualified type includes the package id we just learned.
REGISTRY_ID="$(jq -r --arg t "::auto_swap::AutoSwapRegistry" '
  .objectChanges[]?
  | select(.type == "created" and (.objectType | tostring | contains($t)))
  | .objectId
' "$PUBLISH_RECEIPT" | head -n1)"

if [ -z "$REGISTRY_ID" ] || [ "$REGISTRY_ID" == "null" ]; then
  echo "error: could not find AutoSwapRegistry in publish receipt" >&2
  echo "       (expected a created object of type ${PACKAGE_ID}::auto_swap::AutoSwapRegistry)" >&2
  exit 1
fi

ADMIN_CAP_ID="$(jq -r --arg t "::auto_swap::AdminCap" '
  .objectChanges[]?
  | select(.type == "created" and (.objectType | tostring | contains($t)))
  | .objectId
' "$PUBLISH_RECEIPT" | head -n1)"

DIGEST="$(jq -r '.digest // empty' "$PUBLISH_RECEIPT")"

# ── 6. Output ──────────────────────────────────────────────────────────
echo
echo "════════════════════════════════════════════════════════════════════"
echo " ✓ Talise published to $ENV_ARG"
echo "════════════════════════════════════════════════════════════════════"
echo
echo "  digest:          $DIGEST"
echo "  package id:      $PACKAGE_ID"
echo "  registry id:     $REGISTRY_ID"
echo "  admin cap id:    ${ADMIN_CAP_ID:-(not surfaced — check the receipt)}"
echo "  admin address:   $ACTIVE_ADDR"
echo
echo "════════════════════════════════════════════════════════════════════"
echo " Paste these into Vercel (Settings → Environment Variables):"
echo "════════════════════════════════════════════════════════════════════"
echo
echo "TALISE_AUTOSWAP_PACKAGE_ID=$PACKAGE_ID"
echo "TALISE_AUTOSWAP_REGISTRY_ID=$REGISTRY_ID"
echo
echo "Apply to Production + Preview + Development scopes, then redeploy."
echo
echo "════════════════════════════════════════════════════════════════════"
echo " Onara worker (no env wiring needed — package/registry ids are"
echo " passed in the /auto-swap request body), BUT confirm the worker's"
echo " SUI_MNEMONIC derives to $ACTIVE_ADDR, otherwise validate_for_swap"
echo " will reject (sender != registry.admin)."
echo "════════════════════════════════════════════════════════════════════"
echo
echo "Receipt kept at: $PUBLISH_RECEIPT"
trap - EXIT  # don't auto-clean the receipt now that we've used it
