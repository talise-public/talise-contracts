<div align="center">

# Talise Contracts

**Money that moves like a message.**

The Move packages behind Talise: gasless dollar payments, claim links, streaming, an on-chain savings vault, and a shielded (private) transfer pool, deployed on Sui mainnet.

[Live app](https://app.talise.io) · [Frontend](https://github.com/talise-public/talise-frontend) · [Mobile](https://github.com/talise-public/talise-mobile) · [Docs](https://github.com/talise-public/talise-docs)

</div>

---

## What this is

The Sui Move smart contracts that settle every Talise payment. Each package is independent and composable, so the app can mix a send, a vault deposit, and a receipt into a single programmable transaction block.

## Packages

| Package | Purpose | Key modules |
|---|---|---|
| `talise` | Core payments | `send`, `cheque`, `stream`, `vault`, `batch_pay`, `auto_swap`, `compliance`, `receipt`, `remit_escrow` |
| `talise-privacy` | Shielded transfers | `shielded_pool`, `merkle`, `note_account`, `proof`, `ext_data` |
| `talise-goals` | On-chain savings goals | `goal_vault` |
| `talise-yield` | Idle-balance routing | `yield_router` |
| `talise-pay` | Payment primitives | `cheque`, `stream` |

## Highlights

- **Gasless sends.** Payments move USDsui with sub-second finality, with gas sponsored off chain.
- **Cheques.** Bearer claim links settled either on chain or through an escrow, with a one-shot claim guard.
- **Streaming.** Value released over time by the second.
- **Shielded pool.** A Groth16 zero-knowledge pool with a Merkle commitment tree, nullifiers, and encrypted notes, so a transfer hides its amount and unlinks sender from recipient.
- **Compliance.** On-chain hooks for screening and claim gating.

## Build and test

Install the [Sui CLI](https://docs.sui.io/guides/developer/getting-started/sui-install), then per package:

```bash
cd talise          # or talise-privacy, talise-goals, talise-yield, talise-pay
sui move build
sui move test
```

Build artifacts are gitignored, so only sources, `Move.toml`, and the published `Move.lock` are tracked.

## License

MIT. See [LICENSE](./LICENSE).
