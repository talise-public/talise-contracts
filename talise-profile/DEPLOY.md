# talise_profile — mainnet deployment

- PACKAGE_ID:  0x2e09b4abfee5d2d590f94d9b1370480913ad9dd58363aa73c38552c99bf67dd2
- UPGRADE_CAP: 0xabe3553647ffb3265a46ce84d08d93efe5df3319bc99fbd02b62c6cadd9574f0  (held by publisher 0x8a319488…)
- publish digest: BwtdB8iYrt6wZk2Ui4kZkaPom1eauibWiKExtuFvC386
- publisher: 0x8a319488de2a8043a7b503d4a906ce5feedb793787bdb9a63bc6327d46310cdb

Move-doctor: 92/100 (excellent) — 0 warnings, 0 security findings; `sui move test` 1/1 pass.

Module `talise_profile::profile`:
- `create(avatar, config, clock, ctx): Profile`  — first-time, returns object (PTB transfers to owner)
- `set(&mut Profile, avatar, config, clock, ctx)` — owner-gated update
- Owner-owned, holds no funds. Emits `ProfileUpdated`.

Backend env to set (Vercel): PROFILE_PACKAGE_ID = 0x2e09b4ab…67dd2

NOTE: published via web/scripts/publish-profile.mjs (JSON-RPC) — the sui CLI's
gRPC read path returns empty on this machine, so build+sign+submit was done
directly over JSON-RPC.
