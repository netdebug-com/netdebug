use std::{collections::HashMap, net::IpAddr};

use serde::{Deserialize, Serialize};
use typescript_type_def::TypeDef;

use crate::{DnsTrackerEntry, IpProtocol};

#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize, TypeDef)]
pub struct ConnectionKey {
    #[type_def(type_of = "String")]
    pub local_ip: IpAddr,
    #[type_def(type_of = "String")]
    pub remote_ip: IpAddr,
    pub local_l4_port: u16,
    pub remote_l4_port: u16,
    pub ip_proto: IpProtocol,
}

impl ConnectionKey {
    pub fn to_string_with_dns(&self, dns_cache: &HashMap<IpAddr, DnsTrackerEntry>) -> String {
        let local = if let Some(entry) = dns_cache.get(&self.local_ip) {
            entry.hostname.clone()
        } else {
            format!("[{}]", self.local_ip)
        };
        let remote = if let Some(entry) = dns_cache.get(&self.remote_ip) {
            entry.hostname.clone()
        } else {
            format!("[{}]", self.remote_ip)
        };
        format!(
            "{} {}::{} --> {}::{} ",
            self.ip_proto, local, self.local_l4_port, remote, self.remote_l4_port,
        )
    }
}

impl std::fmt::Display for ConnectionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} [{}]::{} --> [{}]::{} ",
            self.ip_proto, self.local_ip, self.local_l4_port, self.remote_ip, self.remote_l4_port,
        )
    }
}
