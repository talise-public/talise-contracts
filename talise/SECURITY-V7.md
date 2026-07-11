# Talise Auto-Swap — v7 Security Spec

Source of truth for the institutional-security upgrade landing in Move
package v7. This doc fixes the architecture before code is written so
that the threat model, role separation, and migration path are
agreed-upon and reviewable.

## Goals

Convert the auto-swap loop from "demo-acceptable" to "production /
bank-grade":

1. No single key compromise can drain user funds.
2. Every privileged action emits a chain-observable event with a
   cancel window.
3. Recovery from key loss is measured in **minutes**, not "rotate the
   whole package."
4. Worst-case attacker outcome is bounded by published policy
   (allowlists, per-period throttle, slippage ceiling).

## Threat model

| Actor | Trust level | What they can do (v7) | Worst-case impact |
|---|---|---|---|
| **Root admin** (deep cold) | Trusted, audit-able | Grant/revoke any role, change role admins, configure delay | Compromise: attacker proposes role grants — visible on chain, 48h+ cancel window before activation |
| **Treasury role** (cold) | Trusted, signed by 2-of-N | Add/remove allowed dest types, add/remove allowed Cetus providers | Compromise: attacker adds a malicious dest type → 48h delay (if combined with admin-delay policy) → Oncall pauses before activation |
| **Oncall role** (warm) | Operationally trusted | Pause/unpause registry | Compromise: degraded service (forced pause) but no theft |
| **Worker role** (hot, Onara mnemonic) | Day-to-day operations | Call `validate_for_swap`, trigger swaps within cap bounds | Compromise: grinds swaps within `max_per_swap` + `max_per_day` per user. Funds still go to user wallet (`auto_swap_deposit_to_owner` hardwired). Oncall pause + Root revoke kill it in minutes |
| **Cetus aggregator** | Trusted DEX | Provides routes for swap | Compromise: bad price → bounded by 2% Move-level slippage cap + provider allowlist + daily throttle |
| **End user (vault.owner)** | Self-trusted | Withdraw, pause/disable/migrate own caps, accept default-admin transfers if granted | N/A — user controls their own funds |
| **Random actor** | Untrusted | Call `receive_*` (drains accumulator → bag → user wallet only), `deposit` to any vault, query state | None — every state-changing call has its destination hardwired to vault.owner or vault.balances |

## Role hierarchy

```
Root (TaliseRoot one-time-witness)
  │
  ├── grants ──> TreasuryRole (cold, multi-sig recommended)
  │                  └── adds/removes allowed_dest_types
  │                  └── adds/removes allowed_providers
  │
  ├── grants ──> OncallRole (warm, single key OK)
  │                  └── pause_registry / unpause_registry
  │
  └── grants ──> WorkerRole (hot, Onara sponsor key)
                     └── validate_for_swap (executes auto-swaps)
```

All four roles separated. Worker leak is the most likely scenario
(hot key, every-minute usage); under v7 Worker compromise costs at
most `max_per_day` per user before Oncall+Root rotate.

## OZ Contracts for Sui — what we adopt

Library: `OpenZeppelin/contracts-sui` v1.1.0
- Audits: `audits/2026-03-v1.0.0.pdf` + `2026-04-v1.1.0-diff.pdf` +
  `2026-04-v1.1.0-fp-math.pdf` in the OZ repo.
- License: Proprietary (all rights reserved).
- Pin via `rev = "v1.1.0"` in `Move.toml` so upstream changes don't
  silently break us.

Modules we use:

| OZ module | Why we use it |
|---|---|
| `openzeppelin_access::access_control` | Full RBAC with typed `Auth<Role>` capabilities, time-locked default-admin transfer, role grant/revoke/renounce, cancel-pending-transfer. Strictly better than hand-rolled admin checks. |
| `openzeppelin_math::core::u64` | `checked_add` for `used_today + amount` so we abort cleanly on overflow rather than silently wrap. Used in `validate_for_swap`. |
| `openzeppelin_fp_math::UD30x9` | (Future) For any rate / FX math we need. Not used directly in v7 but the dep is wired so we can adopt later. |

Modules we do NOT use:
- `ownership_transfer::{two_step, delayed}` — these wrap individual
  objects for transfer; our admin is a role-bound address, not a
  transferable object.

## Talise-specific code (no OZ equivalent)

Written ourselves, using OZ math primitives internally:

1. **Destination allowlist** — `vector<TypeName>` on registry.
   Asserted in `auto_swap_deposit_to_owner<Dest>` and legacy
   `auto_swap_deposit<Dest>`. A compromised Worker cannot route to
   anything not on the list.

2. **Provider allowlist** — `vector<vector<u8>>` on registry,
   matched against Cetus aggregator response `provider` field.
   Tightens the path the aggregator can take. Initial values:
   `[CETUS, DEEPBOOKV3, AFTERMATH, CETUSDLMM]`.

3. **Per-period throttle** — fields on `AutoSwapCapV2<T>` (see
   migration note below):
   - `max_per_day: u64` — daily budget in source-coin native units
   - `used_today: u64` — running total
   - `day_reset_at_ms: u64` — millisecond timestamp of next reset
   `validate_for_swap` rolls the day over if `now_ms >= day_reset_at_ms`,
   asserts `used_today + amount <= max_per_day`, increments
   `used_today`.

4. **Global pause** — `paused: bool` on registry. Asserted in
   `validate_for_swap` and `receive_from_accumulator*` (so a
   compromised Worker can't even pull funds into the bag during a
   pause).

5. **Slippage** — Enforced off-chain by Onara, with a target ceiling
   of 2%. The on-chain `auto_swap_deposit_to_owner_v2` asserts only
   that the destination type is in `registry.allowed_dest_types` and
   that the `SwapTicket.vault_id` matches the depositing vault; it
   does not assert an output-vs-expected slippage bound. A compromised
   Onara TS config that accepted a 50% slippage route would not be
   rejected at chain level today. If a chain-level cap is later
   desired it would need a new field on the cap/registry and a price
   reference passed alongside the ticket. See
   `sources/vault.move:602-640`.

## Cap migration plan — v3-v6 → v2

**The constraint:** Sui's `compatible` upgrade policy prohibits
adding fields to existing public structs. `AutoSwapCap<T>` layout is
frozen at v3 (`id, vault_id, owner, max_per_swap, expires_at_ms,
paused`). The throttle fields can't be added in-place.

**Solution:** define a new struct `AutoSwapCapV2<T>` with the v3
fields PLUS throttle fields. Provide a one-shot migration:

```move
public entry fun upgrade_cap_to_v2<T>(
    cap: AutoSwapCap<T>,                          // burn v1 cap
    max_per_day: u64,                             // user sets
    clock: &Clock,
    ctx: &TxContext,
): AutoSwapCapV2<T> {                             // mint v2 cap
    assert!(ctx.sender() == auto_swap::cap_owner(&cap), E_NOT_OWNER);
    // Move v1 fields → v2 layout, attach throttle defaults.
}
```

User signs once per cap (or once for "migrate all" if iOS bundles).
The OWNER initiates — operator can't migrate someone's cap.

The legacy `validate_for_swap` (operates on v1 caps) is removed in
v7. Cron's event-walk discovery should ignore v1 caps and only
surface v2-shape caps. v1 caps are effectively dead the moment v7
ships; they need migration to be useful.

## Default admin delay policy

`AccessControl<TaliseRoot>` initialized with
`default_admin_delay_ms = 48 hours`.

Rationale:
- Long enough that monitoring + community can react to an unexpected
  rotation proposal.
- Short enough that legitimate key rotations don't take a week.
- Configurable down to 0 (instant) or up to 60 days (OZ-enforced
  ceiling) via `begin_default_admin_delay_change` if operational
  needs change.

Delay changes are themselves cooldown-gated by OZ
(`MAX_DELAY_INCREASE_WAIT_MS = 48h`) so an attacker can't tighten
the delay to instantly rotate.

## Daily budget defaults

For the live demo user, on initial v2-cap mint:

| Coin | `max_per_swap` raw | `max_per_day` raw | Human-tier daily budget |
|---|---|---|---|
| SUI (9 dec) | 10 × 10^9 (10 SUI) | 100 × 10^9 (100 SUI, ~$100) | ~₦150,000/day |
| USDC (6 dec) | 10 × 10^6 (10 USDC) | 100 × 10^6 (100 USDC, ~$100) | ~₦150,000/day |
| USDT (6 dec) | 10 × 10^6 (10 USDT) | 100 × 10^6 (100 USDT, ~$100) | ~₦150,000/day |

Per-user defaults; user can tighten via `update_cap_bounds_v2` (still
honors `ctx.sender() == cap.owner` check). Cap mint flow in iOS picks
these as a sensible starter; user adjusts via the existing
AutoSwapSettings sliders (which call `update_bounds` → re-points to a
new v7 entry that also accepts `max_per_day`).

## Initialization (one-shot at publish time)

Move v7 publishes with an `init` function that:

1. Claims the One-Time-Witness `AUTO_SWAP` (Move's OTW pattern
   guarantees this can only happen at publish time).
2. Constructs `AccessControl<TaliseRoot>` with the publisher
   (Onara mnemonic-derived address for now) as default admin and
   `default_admin_delay_ms = 48h`.
3. Constructs the `AutoSwapRegistry` shared object, embedding the
   AccessControl + initial `allowed_dest_types = [USDsui]` +
   `allowed_providers = [CETUS, DEEPBOOKV3, AFTERMATH, CETUSDLMM]`
   + `paused = false`.
4. Emits `RegistryInitialized` event.

After publish, the publisher (still hot Onara key initially) must:

5. Grant `WorkerRole` to the Onara hot key (= self, but typed).
6. (Operational) Begin a default-admin transfer to a cold key,
   wait 48h, accept on the cold key. After this the cold key is
   Root; Onara holds Worker only.
7. (Operational) Grant `OncallRole` to the warm incident-response
   key, `TreasuryRole` to a cold treasury key.

Steps 5-7 are off-chain ops, scheduled in the deploy runbook.

## Migration sequencing

1. Publish v7 package (upgrade from v6 — `compatible` policy preserved).
2. Run `init` (automatic at publish — creates new `AutoSwapRegistry`
   shared object).
3. **Update env**: `TALISE_AUTOSWAP_PACKAGE_LATEST = v7`,
   `TALISE_AUTOSWAP_REGISTRY_ID = <new shared object id>`. The old
   v1-original `TALISE_AUTOSWAP_PACKAGE_ID` stays for type tags +
   event filters.
4. Grant `WorkerRole` to the Onara address (one tx, publisher
   signs).
5. Add USDsui to `allowed_dest_types` (one tx, publisher signs).
6. Add `[CETUS, DEEPBOOKV3, AFTERMATH, CETUSDLMM]` to
   `allowed_providers` (one tx, publisher signs).
7. Onara + cron picks up the new registry id via env. They start
   targeting v7 entries with `packageIdLatest`.
8. iOS shows a "Upgrade your auto-swap caps" CTA in AutoSwapSettings
   for any user with v1 caps. User taps → `upgrade_cap_to_v2<T>`
   PTB → existing caps replaced with v2 versions.

## Risks

| Risk | Mitigation |
|---|---|
| OZ Sui v1.1.0 has a bug | Pinned at `rev = v1.1.0`. Audits attached. We can rev forward only after diff-review. |
| OZ adds breaking changes in v2 | We're pinned; opt-in only after review. |
| Existing user (the only one, you) holds v1 caps that become useless | One-tap migrate-all CTA in iOS. Defaults applied automatically. |
| Operational complexity (4 roles vs 1 admin) | Collapse Oncall+Worker into one if team is small. Roles can be added later — adding a new role type is an additive Move upgrade. |
| Init must happen exactly once | OTW pattern enforces this at the Move/runtime level. Can't run init twice. |
| Onara becomes Worker (no longer admin) | Onara was de-facto Worker already; this just types it. Onara LOSES the ability to add allowed dests / pause — those become deliberate operations from cold/warm keys. |

## Out of scope for v7 (deferred)

- **App Attest server-side verification** — web/server work, separate
  ticket. Reduces emulator/tampered-client attack surface but is
  off-chain.
- **Multi-sig for cold roles** — once we have Treasury + Root cold
  keys, wrapping them in a Move-level multi-sig (or external
  Mysten Wallet multisig) is a follow-up.
- **Formal verification with Move Prover** — invariant proofs for
  `validate_for_swap` (`amount > 0 ∧ used_today + amount ≤
  max_per_day ⟹ post.used_today = pre.used_today + amount`).
  Recommended pre-mainnet-volume.
- **External audit** — OtterSec, Movebit, Zellic. Recommended before
  anything beyond $10k AUM.

## File map for the v7 implementation

```
move/talise/
  Move.toml                              ← add OZ deps
  sources/
    auto_swap.move                       ← rewrite registry + add cap_v2 + migrate
    vault.move                           ← assert allowed_dest in deposit_to_owner +
                                            assert registry.paused in receive_*
  tests/
    auto_swap_v7_tests.move              ← role grants, pause, allowlist, throttle
    vault_v7_tests.move                  ← dest-allowlist assertion paths

web/app/api/cron/auto-swap-sweep/
  route.ts                               ← env: use new TALISE_AUTOSWAP_REGISTRY_ID
                                           v7
onara/api/src/
  autoSwap.ts                            ← updated PTB targets v7 validate_for_swap_v2
  receiveFromAccumulator*.ts             ← unchanged (already pkg-id-latest aware)

ios/Talise/Features/Earn/
  AutoSwapSettings.swift                 ← add v1→v2 cap migration CTA (mirrors v2→v3)

web/lib/
  vault.ts                               ← buildUpgradeCapToV2Tx, env consts
```

Total estimated effort: ~6 hours including tests, publish, init, env rotation, and downstream wiring.
