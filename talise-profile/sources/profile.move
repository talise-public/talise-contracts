/// Talise on-chain profile — a per-user, owner-owned object recording the user's
/// chosen profile picture (`avatar`) and Copilot look (`config`, a small JSON
/// blob: colour + background). Updated via Onara-SPONSORED, gasless txns: the
/// user signs (owner authority), the sponsor pays gas.
///
/// Owner-owned (transferred to its creator), so ONLY a tx the user signs can
/// mutate it — no shared/worker access. Holds no funds, so it carries no custody
/// risk. One profile per user (the app tracks the object id off-chain, like the
/// goal vaults).
module talise_profile::profile;

use std::string::String;
use sui::{clock::Clock, event};

/// Field caps — keep on-chain state bounded.
const MAX_AVATAR_LEN: u64 = 512;
const MAX_CONFIG_LEN: u64 = 1024;

const ENotOwner: u64 = 0;
const ETooLong: u64 = 1;

public struct Profile has key, store {
    id: UID,
    owner: address,
    /// The chosen picture — e.g. "copilot" or an NFT/image reference.
    avatar: String,
    /// The Copilot look as a small JSON blob (colour + background).
    config: String,
    updated_ms: u64,
}

/// Emitted on create and on every update — lets indexers track profile changes
/// without reading the object each time. The current avatar/config live on the
/// object (read those for the value).
public struct ProfileUpdated has copy, drop {
    profile: address,
    owner: address,
    updated_ms: u64,
}

fun check_lens(avatar: &String, config: &String) {
    assert!(avatar.length() <= MAX_AVATAR_LEN, ETooLong);
    assert!(config.length() <= MAX_CONFIG_LEN, ETooLong);
}

/// First-time create: build a profile for the sender and RETURN it (composable)
/// — the caller transfers it, e.g. `transfer::public_transfer(p, sender)` in the
/// sponsored PTB. The app calls this when the user has no profile object yet.
public fun create(
    avatar: String,
    config: String,
    clock: &Clock,
    ctx: &mut TxContext,
): Profile {
    check_lens(&avatar, &config);
    let owner = ctx.sender();
    let now = clock.timestamp_ms();
    let id = object::new(ctx);
    let addr = id.to_address();
    let p = Profile { id, owner, avatar, config, updated_ms: now };
    event::emit(ProfileUpdated { profile: addr, owner, updated_ms: now });
    p
}

/// Update an existing profile's avatar + config. Owner-gated (defence in depth —
/// the object is owner-owned, so only the owner's tx can reach here anyway).
public fun set(
    self: &mut Profile,
    avatar: String,
    config: String,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(self.owner == ctx.sender(), ENotOwner);
    check_lens(&avatar, &config);
    self.avatar = avatar;
    self.config = config;
    self.updated_ms = clock.timestamp_ms();
    event::emit(ProfileUpdated {
        profile: self.id.to_address(),
        owner: self.owner,
        updated_ms: self.updated_ms,
    });
}

// === Views ===
public fun avatar(self: &Profile): String { self.avatar }
public fun config(self: &Profile): String { self.config }
public fun owner(self: &Profile): address { self.owner }
public fun updated_ms(self: &Profile): u64 { self.updated_ms }
