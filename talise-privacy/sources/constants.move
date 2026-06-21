/// Talise privacy — compile-time constants (Workstream A, mirrors Vortex's
/// `vortex_constants`). Macros so callers inline the values with zero runtime
/// cost, same idiom as the reference.
///
/// SECURITY POSTURE OF THE VERIFYING KEY (read before any mainnet decision):
/// this VK is the output of a SINGLE-PARTY arkworks setup (`circuit/keygen.rs`,
/// `OsRng`, trapdoor sampled and discarded in-process — NOT a zero-seed key, and
/// NOT recoverable by an external party). It is therefore NOT forgeable by an
/// outsider, but its soundness still rests on trusting that the one operator who
/// ran keygen did not capture the setup trapdoor (α, β, τ, δ). Trustless
/// unforgeability requires a MULTI-PARTY ceremony (Powers-of-Tau phase-1 for
/// α/β/τ + circuit-specific phase-2 for δ), where security holds if ANY single
/// participant was honest. That ceremony is a people+time process, not a solo
/// script; until it runs, this VK is fit for TESTNET and an operator-trusted
/// capped pilot only — see PRIVACY-BUILD-PLAN.md "Remaining gates".
module talise_privacy::constants;

// === Package View Functions ===

/// Single-party OsRng dev VK (matches `circuit/keys/vk_sui.hex` and
/// prove_deposit's persisted key, verified byte-for-byte). See the module
/// header for the exact trust assumption: not outsider-forgeable, but not yet
/// the multi-party-ceremony output trustless mainnet at scale requires.
public(package) macro fun verifying_key(): vector<u8> {
    // Single-party OsRng dev VK == circuit/keys/vk_sui.hex (byte-matched).
    // Multi-party ceremony output replaces this wholesale before scale.
    x"0400f07bc59c5d8eea2d649783a55fcbc64dd793fa1d102e87bb7872bf7fc6853adb445f837298fe2cdc8f935f1658612acec5d538831b9a6542412bbf36321ff5acd09efdf65b13e029ed3b8b3f5a6ebe1b68c12c0c847918db75267527e5a87a0201288a0d169552021541b9ffd92e959ad3dac3e8a21608369684683ae512a1868d2f05c002d9fc6dd1d61d6741a4c262970b896abbda2ee5c8c8b28085ac7226a2ac22840639b823f79dc682d2ffbabf053562c44c018e5c3326e1ca3e04703e766fdc2aeaade5b3d890979bb2b27e9fed88542f9e0e12597e697624309d09000000000000008ff673d2e70b20cf402f0eb3ac0c2c5b29acacacde983fdf16ae05d0e390b512de33cdb8f0886968fd89b590b0674679306803af6e8ee1a6ea595da51918122c81b949bd05f397ccec60a1a10c3fb7c7e9fb26c654654b7595b157249bd4439729479f9487d16c5590dbd6c9d5e6f25ec46ceabc3ae9af3b4101b7f132c40f233dd7031fdb1257e7a66b7bd72d7982913efc556c0782faf2a026b9855591f383e223ccce2f9cc47c2e85ba4c0223d3442cfea04104d3b48014da37aa19b57306cd18602b8c1955902007e772e70eac9fd19b9e520b3e54bb37015f8309d0e922883762fc1fc4aa8956e1c5f7b352db26b5f46996df5baf69100adaad7e9d7118cb4ae1fbbed3ea13f96779f1be6fb248ba5622afb4ebc92bcdf93f62c72a4b14"
}

/// BN254 scalar field modulus. Native `poseidon_bn254` and `groth16::bn254()`
/// both operate over this field; public inputs are reduced mod this value.
public(package) macro fun bn254_field_modulus(): u256 {
    21888242871839275222246405745257275088548364400416034343698204186575808495617
}

/// Merkle tree height. 2^26 ≈ 67M leaves of capacity.
public(package) macro fun height(): u64 {
    26
}

/// Root ring-buffer history depth — how many recent roots a proof may target.
public(package) macro fun root_history_size(): u64 {
    100
}

/// Precomputed "empty subtree" hashes: index 0 is the all-ZERO leaf, index i is
/// `poseidon_bn254([h[i-1], h[i-1]])`, up through index HEIGHT (==26). That is
/// HEIGHT+1 == 27 entries; `new()` seeds `subtrees[0..HEIGHT]` and the genesis
/// root from `[HEIGHT]`.
///
/// These are the canonical BN254 empty-tree hashes (the same series Vortex and
/// Tornado-Nova publish). They are DERIVED, not arbitrary — the Phase-0 gate
/// (Rust-root == Move-root) re-derives index `[HEIGHT]` against this list and a
/// fresh `merkle::new().root()` to prove the on-chain Poseidon matches the
/// circuit's gadget. If that cross-check ever fails these must be regenerated
/// from `sui::poseidon::poseidon_bn254` directly.
public(package) macro fun empty_subtree_hashes(): vector<u256> {
    vector[
        18688842432741139442778047327644092677418528270738216181718229581494125774932,
        929670100605127589096201729966801143828059989180770638007278601230757123028,
        20059153686521406362481271315473498068253845102360114882796737328118528819600,
        667276972495892769517195136104358636854444397700904910347259067486374491460,
        12333205860481369973758777121486440301866097422034925170601892818077919669856,
        13265906118204670164732063746425660672195834675096811019428798251172285860978,
        3254533810100792365765975246297999341668420141674816325048742255119776645299,
        18309808253444361227126414342398728022042151803316641228967342967902364963927,
        12126650299593052178871547753567584772895820192048806970138326036720774331291,
        9949817351285988369728267498508465715570337443235086859122087250007803517342,
        11208526958197959509185914785003803401681281543885952782991980697855275912368,
        59685738145310886711325295148553591612803302297715439999772116453982910402,
        20837058910394942465479261789141487609029093821244922450759151002393360448717,
        8209451842087447702442792222326370366485985268583914555249981462794434142285,
        19651337661238139284113069695072175498780734789512991455990330919229086149402,
        11527931080332651861006914960138009072130600556413592683110711451245237795573,
        20764556403192106825184782309105498322242675071639346714780565918367449744227,
        10818178251908058160377157228631396071771716850372988172358158281935915764080,
        21598305620835755437985090087223184201582363356396834169567261294737143234327,
        16481295130402928965223624965091828506529631770925981912487987233811901391354,
        17911512007742433173433956238979622028159186641781974955249650899638270671335,
        5186032540459307640178997905000265487821097518169449170073506338735292796958,
        19685513117592528774434273738957742787082069361009067298107167967352389473358,
        10912258653908058948673432107359060806004349811796220228800269957283778663923,
        19880031465088514794850462701773174075421406509504511537647395867323147191667,
        18344394662872801094289264994998928886741543433797415760903591256277307773470,
        4023688209857926016730691838838984168964497755397275208674494663143007853450,
    ]
}
