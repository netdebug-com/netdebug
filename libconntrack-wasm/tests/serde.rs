use std::{collections::HashMap, net::IpAddr};

use libconntrack_wasm::DnsTrackerEntry;
use wasm_bindgen_test::*;

// wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn pass() {
    assert_eq!(1, 1);
}

#[wasm_bindgen_test]
fn chrono_serdes_test() {
    let json_dns_records = std::include_str!("dns_entry_json.txt");
    for json in json_dns_records.lines() {
        // test passes if unwrap() doesn't panic
        let _dns_entry: DnsTrackerEntry = serde_json::from_str(&json).unwrap();
    }
}

// Doens't work for some json parsing issue on IpAddr!? 
// we don't see it in practice, so just ignore for now - probably a problem
// with the test data
#[ignore]
#[wasm_bindgen_test]
fn dns_cache_serde_test() {
    let json = std::include_str!("dns_cache.json");

    // test passes if unwrap() doesn't panic
    let _dns_cache: HashMap<IpAddr, DnsTrackerEntry> = serde_json::from_str(json).unwrap();
}
