use std::{collections::HashMap, net::IpAddr};
use libconntrack_wasm::DnsTrackerEntry;
/**
 * Anything in this file must compile for both native rust/x86 AND WASM
 * 
 * So no thread, deep OS calls, etc. here
 */
use serde::{Deserialize, Serialize};

pub fn get_git_hash_version() -> String {
    env!("GIT_HASH").to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerToGuiMessages {
    VersionCheck(String),
    DumpFlowsReply(Vec<String>),
    DumpDnsCache(HashMap<IpAddr, DnsTrackerEntry>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GuiToServerMessages {
    DumpFlows(),
    DumpDnsCache(),
}
