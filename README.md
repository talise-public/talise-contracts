<div align="center">

# Talise Contracts

**Money that moves like a message.**

The Move packages behind Talise: gasless dollar payments, claim links, streaming, an on-chain savings vault, and a shielded (private) transfer pool, deployed on Sui mainnet.

[Website](https://talise.io) · [iOS app (TestFlight)](https://testflight.apple.com/join/BFNEPYtM) · [Frontend](https://github.com/talise-public/talise-frontend) · [Mobile](https://github.com/talise-public/talise-mobile) · [Docs](https://github.com/talise-public/talise-docs)

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

## Deployed on Sui mainnet

| Package | Package ID |
|---|---|
| Core payments (`send`, `vault`, `auto_swap`, `receipt`) | `0xc74a7df07b4089d92f196d1db73ce0574db7f58ae0ba2b19b2a59d402958d394` |
| Cheques + streaming | `0x4ba838c7ded1b57aededff4e825aa251858b05b720083856351dd8325094a13e` |
| Goal vault (savings) | `0xb0898eef5734ee9ebfbdbacd9e39533d7070159d4a87287ddde8a5b331059947` |

Verify any of them on [SuiVision](https://suivision.xyz/package/0xc74a7df07b4089d92f196d1db73ce0574db7f58ae0ba2b19b2a59d402958d394).

## Highlights

- **Gasless sends.** Payments move USDsui with sub-second finality, with gas sponsored off chain.
- **Cheques.** Bearer claim links settled either on chain or through an escrow, with a one-shot claim guard.
- **Streaming.** Value released over time, by the second.
- **Shielded pool.** A Groth16 zero-knowledge pool with a height-26 Merkle commitment tree, nullifiers, and encrypted notes, so a transfer hides its amount and unlinks sender from recipient.
- **Compliance.** On-chain hooks for screening and claim gating.

## Why it fits Sui

Assets are objects with type-level ownership, transactions bundle logic atomically as programmable transaction blocks, and Move enforces composability safely. A Talise payment is therefore a programmable financial action: a send can carry a receipt, route through a vault, or settle a claim link, all in one signed transaction.

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
