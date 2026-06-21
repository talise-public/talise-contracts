//! Talise privacy ZK circuit.
//!
//! Vendored from the Interest Protocol Vortex circuit crate
//! (https://github.com/interest-protocol/vortex, `circuit/`). BN254 / arkworks
//! Groth16, 2-in / 2-out shielded-transaction circuit, Merkle height 26,
//! circomlib-compatible optimized Poseidon.
//!
//! IMPORTANT: any Groth16 keys produced here are DEV / TEST keys. They are
//! generated locally with a real-entropy RNG for convenience, NOT via a trusted
//! multi-party setup ceremony, and MUST NOT be used to secure real funds.

pub mod circuit;
pub mod constants;
pub mod merkle_tree;
pub mod poseidon_opt;
pub mod prover;

/// Browser (WASM) prover. Only compiled for the `wasm32` target so the native
/// crate (bins, `cargo test`, `prove_deposit`) is completely unaffected.
#[cfg(target_arch = "wasm32")]
pub mod wasm;
