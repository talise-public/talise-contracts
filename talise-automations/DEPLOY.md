# talise_automations — mainnet deployment

- PACKAGE_ID:  0xf6190d582f88dc3301e060820ebe81b656d96f6bf71c0f6f2e0cf23cbde0339c
- REGISTRY_ID: 0x7a1d890e9b03ace32048ed09acb3856cbfbb021db67baf97e0fe41feebd10178  (AutomationRegistry, shared)
- ADMIN_CAP:   0x8d4d84c31f3a7c2aa1f9002ea963a1ef7acd887c8e180936ee67fd136ae3604e  (held by publisher 0x8a319…)
- WORKER:      0x91f2aafd089acadd893935ec083928bb8804313b557fe6b111787acc31e8a64b  (registered via add_worker; SK in Vercel AUTOMATIONS_WORKER_SK)
- publish digest: 9nMnoLHXwJgm9rpWyF1GCYY3eM1CpytVG2nTq7h1qCHW
- add_worker digest: HYDDY4Ljy2RXrhHW4adaqgs5xWqUVEc3ubHfUVjh2CXc

Move-doctor audit: `sui move build` clean + `sui move test` 4/4 pass
(create/execute/topup/cancel, can't-execute-before-due, worker-gate, owner-gate).
