/// Talise privacy — external (cleartext) transaction data (Workstream A,
/// mirrors `vortex_ext_data`). This is the PUBLIC side of a `transact`: the
/// signed value delta, the relayer + its fee, and the two encrypted note
/// outputs. It is bound to the proof by the `public_value` tie-check in
/// `shielded_pool::process_transaction`.
module talise_privacy::ext_data;

use talise_privacy::constants;

/// Local mirror of `errors::EInvalidRelayer` (806). See `errors.move` for the
/// canonical registry; declared locally so `assert!` names a same-module
/// constant (W04005).
const EInvalidRelayer: u64 = 806;

// === Structs ===

public struct ExtData has copy, drop, store {
    /// Cleartext magnitude of the public leg (deposit-in or withdraw-out).
    value: u64,
    /// true => deposit (value flows INTO the pool); false => withdraw.
    value_sign: bool,
    /// The relayer that may submit this tx (@0x0 == self-submitted, no gate).
    relayer: address,
    /// Fee paid to the relayer out of the pool, in CoinType units.
    relayer_fee: u64,
    /// Ciphertext of output note 0 (for the recipient to trial-decrypt).
    encrypted_output0: vector<u8>,
    /// Ciphertext of output note 1 (change / second output).
    encrypted_output1: vector<u8>,
}

// === Public Mutative Functions ===

public fun new(
    value: u64,
    value_sign: bool,
    relayer: address,
    relayer_fee: u64,
    encrypted_output0: vector<u8>,
    encrypted_output1: vector<u8>,
): ExtData {
    ExtData {
        value,
        value_sign,
        relayer,
        relayer_fee,
        encrypted_output0,
        encrypted_output1,
    }
}

// === Assert Functions ===

/// If a relayer is named, the submitter MUST be that relayer. Anti-griefing:
/// stops a third party from front-running another user's relayed tx.
public(package) fun assert_relayer(self: ExtData, ctx: &TxContext) {
    if (self.relayer != @0x0)
        assert!(self.relayer == ctx.sender(), EInvalidRelayer);
}

// === Package View Functions ===

public(package) fun value(self: ExtData): u64 { self.value }

public(package) fun value_sign(self: ExtData): bool { self.value_sign }

public(package) fun relayer(self: ExtData): address { self.relayer }

public(package) fun relayer_fee(self: ExtData): u64 { self.relayer_fee }

public(package) fun encrypted_output0(self: ExtData): vector<u8> { self.encrypted_output0 }

public(package) fun encrypted_output1(self: ExtData): vector<u8> { self.encrypted_output1 }

/// The signed public delta as a field element. Deposit: the pool nets
/// `value - relayer_fee`. Withdraw: the pool loses `value`, expressed as the
/// field-negative `modulus - value` so the SNARK's conservation equation
/// `Σin + public = Σout` holds over the field. MUST equal `proof.public_value()`.
public(package) fun public_value(self: ExtData): u256 {
    if (self.value_sign)
        ((self.value - self.relayer_fee) as u256)
    else
        constants::bn254_field_modulus!() - (self.value as u256)
}
