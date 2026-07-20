#[test_only]
module talise_profile::profile_tests;

use talise_profile::profile;
use sui::{test_scenario as ts, clock};
use std::string;

#[test]
fun create_then_update() {
    let owner = @0xA;
    let mut sc = ts::begin(owner);
    let clk = clock::create_for_testing(sc.ctx());

    // First-time create returns a Profile (the PTB transfers it to the owner).
    let mut p = profile::create(
        string::utf8(b"copilot"),
        string::utf8(b"{\"color\":\"classic\",\"bg\":\"worldcup\"}"),
        &clk,
        sc.ctx(),
    );
    assert!(profile::avatar(&p) == string::utf8(b"copilot"), 0);
    assert!(profile::owner(&p) == owner, 1);

    // Update swaps avatar + config in place.
    profile::set(
        &mut p,
        string::utf8(b"nft:0xabc"),
        string::utf8(b"{\"color\":\"violet\",\"bg\":\"beach\"}"),
        &clk,
        sc.ctx(),
    );
    assert!(profile::avatar(&p) == string::utf8(b"nft:0xabc"), 2);
    assert!(profile::config(&p) == string::utf8(b"{\"color\":\"violet\",\"bg\":\"beach\"}"), 3);

    transfer::public_transfer(p, owner);
    clock::destroy_for_testing(clk);
    sc.end();
}
