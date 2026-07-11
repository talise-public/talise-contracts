# Talise Move Upgrade Dry-Run Runbook

Before running `sui client upgrade` against mainnet, perform a dry-run to
confirm the `compatible` upgrade policy accepts the staged changes.

This runbook exists specifically for the working-tree change that
demotes 24 `public entry fun` declarations to `public fun` across
`sources/auto_swap.move` (and any companion file). Under Sui's
`compatible` policy this is a friendly change: removing the `entry`
qualifier preserves the public ABI for both PTB callers and downstream
Move packages, so the policy check should pass. We still verify with a
dry run before paying for the on-chain upgrade.

## 1. Locate the UpgradeCap id

The cap id lives in `move/talise/Published.toml`. Pull the value that
matches the target network:

| Network  | UpgradeCap id |
| -------- | -------------- |
| mainnet  | `0x006e09cc9a53291821345069564679f0e8ad617878ebc3a761647cadba0512ad` |
| testnet  | `0xa5c80c862b36eac0b59fc218b7c87b6e1ccf61ab8bed5fce12d06b79e7eba37b` |

If `Published.toml` is missing or stale, the cap id can also be
recovered from:

* The original publish receipt (search `sui client publish` output in
  `traces/` or shell history).
* `sui client objects --address <admin>` filtered to type
  `0x2::package::UpgradeCap` once you know which Sui CLI profile owns
  the cap.
* `~/.sui/sui_config/client.yaml` to confirm which active address /
  network the CLI will use; the cap must be owned by the active
  address.

If the cap was rotated into a multisig, the owner is the multisig
address; in that case dry-run with the multisig as `--sender` (see §3).

## 2. Run the dry run

From the package root (`/Users/eromonseleodigie/Talise/move/talise/`):

```bash
# Mainnet
sui client switch --env mainnet
sui client upgrade \
  --upgrade-capability 0x006e09cc9a53291821345069564679f0e8ad617878ebc3a761647cadba0512ad \
  --gas-budget 200000000 \
  --dry-run
```

```bash
# Testnet (optional rehearsal)
sui client switch --env testnet
sui client upgrade \
  --upgrade-capability 0xa5c80c862b36eac0b59fc218b7c87b6e1ccf61ab8bed5fce12d06b79e7eba37b \
  --gas-budget 200000000 \
  --dry-run
```

### Multisig sender (only if the cap is in a multisig)

```bash
sui client upgrade \
  --upgrade-capability <CAP_ID> \
  --gas-budget 200000000 \
  --sender <MULTISIG_ADDR> \
  --serialize-unsigned-transaction \
  --dry-run
```

## 3. What success looks like

A passing dry run produces, in this order:

1. Move build succeeds (`Build Successful`).
2. The CLI prints `Compatibility check passed.` (or equivalent wording
   from the active Sui CLI version) and emits the simulated effects.
3. The bottom of the output shows
   `Status: Success` with simulated gas usage well under 200 000 000
   MIST.
4. No `compatibility check failed` or `IncompatibleUpgrade` error.

If all four hold, the change is safe to ship and you can re-run without
`--dry-run` to broadcast.

## 4. What failure looks like and how to roll back

The `compatible` policy will reject the upgrade if the change inadvertently:

* Removes or renames a public function.
* Changes the signature of a public function (parameters or return).
* Adds, removes, or reorders fields of a public struct.
* Changes the `key`/`store` ability set of a struct.

Demoting `entry` to `public` does not fall into any of these buckets,
so a failure here would indicate an unintended secondary edit slipped
into the working tree.

### Rollback

```bash
cd /Users/eromonseleodigie/Talise/move/talise
git checkout sources/auto_swap.move
# Re-run to confirm a clean tree dry-runs successfully:
sui move build
```

If multiple files were touched, widen the checkout (`git checkout
sources/`) or use `git stash` to set the tree aside while you
investigate.

## 5. Reference: why the `entry` removal is safe

The `entry` modifier restricts a function so that it can only be called
as the top-level call of a PTB, never composed from another Move
module. Removing `entry` from a `public entry fun` widens what can
call the function (any Move module gains the ability to call it). Under
Sui's compatibility rules this is an additive capability change: no
existing caller is broken, no public ABI is removed.

Linting context: the previous wrap-up surfaced these 24 declarations as
candidates for the lint pass because none of them are used as PTB
top-level entry points outside the codebase under our control. Keeping
them as plain `public` clarifies intent and frees the v8 surface to
add `entry` only where a wallet or off-chain signer must call the
function as the first PTB command. The dry run above is the gate that
proves that intent does not break the compatibility envelope.
