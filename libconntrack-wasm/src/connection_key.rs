use std::{
    collections::HashMap,
    fmt::Display,
    net::{AddrParseError, IpAddr},
    num::ParseIntError,
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use typescript_type_def::TypeDef;

use crate::{DnsTrackerEntry, IpProtocol};

const ICMP4_ECHO_REQUEST_TYPE: u8 = 8;
const ICMP6_ECHO_REQUEST_TYPE: u8 = 128;

#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize, TypeDef)]
pub struct ConnectionKey {
    #[type_def(type_of = "String")]
    pub local_ip: IpAddr,
    #[type_def(type_of = "String")]
    pub remote_ip: IpAddr,
    /// With ip_proto=TCP|UDP, this is the l4 local port
    /// But with ICMP4|ICMP6, this is the ICMP_header.type
    pub local_l4_port: u16,
    /// With ip_proto=TCP|UDP, this is the l4 remote port
    /// But with ICMP4|ICMP6 echo request|echo reply, this is the IcmpEchoHeader.id
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

    pub fn make_icmp_echo_key(local_ip: IpAddr, remote_ip: IpAddr, ping_id: u16) -> ConnectionKey {
        let (ip_proto, echo_type) = if local_ip.is_ipv4() {
            (IpProtocol::ICMP, ICMP4_ECHO_REQUEST_TYPE)
        } else {
            (IpProtocol::ICMP6, ICMP6_ECHO_REQUEST_TYPE)
        };

        ConnectionKey {
            local_ip,
            remote_ip,
            // HACK!  IMHO the pain of adding extra fields to this struct is worse
            // than this work around, but let's discuss
            local_l4_port: echo_type as u16,
            remote_l4_port: ping_id,
            ip_proto,
        }
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

/// An opaque, compact string representation of a connection key. Mostly for use by the UI. This
/// allows to use the UI as a unique id (e.g., for react `key` fields) and it allows the UI
/// to send request for a particular connection or set of connections
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize, TypeDef)]
#[serde(transparent)]
pub struct ConnectionIdString {
    id: String,
}

impl Display for ConnectionIdString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.id)
    }
}

impl From<&ConnectionKey> for ConnectionIdString {
    fn from(value: &ConnectionKey) -> Self {
        ConnectionIdString {
            // WARNING WARNING: This implemenation MUST match the implementation of in the UI
            // WARNING WARNING: (`connIdString()` in utils.ts
            // WARNING WARNING: It is used to identify connections between UI and desktop
            id: format!(
                "{}-{}-{}-{}-{}",
                value.ip_proto.to_wire(),
                value.local_ip,
                value.local_l4_port,
                value.remote_ip,
                value.remote_l4_port
            ),
        }
    }
}

#[derive(Clone, thiserror::Error, Debug)]
pub enum ConnectionIdError {
    #[error("Expected to have 5 parts with `-` or `#` separator")]
    InvalidNumParts,
    #[error("Could not parse IP protocol or port into integer")]
    ParseProtoOrPort {
        #[from]
        src: ParseIntError,
    },
    #[error("Failed to parse src or dst IP")]
    ParseIpError {
        #[from]
        src: AddrParseError,
    },
}

impl TryFrom<&ConnectionIdString> for ConnectionKey {
    type Error = ConnectionIdError;

    fn try_from(idstr: &ConnectionIdString) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = if idstr.id.contains('-') {
            idstr.id.split('-').collect()
        } else {
            // Backwards compatibility. We used to use '#' as separator
            // but changed it to `-`
            idstr.id.split('#').collect()
        };
        if parts.len() != 5 {
            Err(ConnectionIdError::InvalidNumParts)
        } else {
            Ok(ConnectionKey {
                ip_proto: IpProtocol::from_wire(u8::from_str(parts[0])?),
                local_ip: IpAddr::from_str(parts[1])?,
                local_l4_port: u16::from_str(parts[2])?,
                remote_ip: IpAddr::from_str(parts[3])?,
                remote_l4_port: u16::from_str(parts[4])?,
            })
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_connection_id_string() {
        let key = ConnectionKey {
            local_ip: IpAddr::from_str("127.0.0.1").unwrap(),
            remote_ip: IpAddr::from_str("1.2.3.4").unwrap(),
            local_l4_port: 23,
            remote_l4_port: 4242,
            ip_proto: IpProtocol::TCP,
        };
        assert_eq!(
            ConnectionIdString::from(&key).id,
            "6-127.0.0.1-23-1.2.3.4-4242"
        );
        let conn_id = ConnectionIdString::from(&key);
        assert_eq!(ConnectionKey::try_from(&conn_id).unwrap(), key);

        let key = ConnectionKey {
            local_ip: IpAddr::from_str("::1").unwrap(),
            remote_ip: IpAddr::from_str("2001:db8::1").unwrap(),
            local_l4_port: 23,
            remote_l4_port: 4242,
            ip_proto: IpProtocol::Other(123),
        };
        assert_eq!(
            ConnectionIdString::from(&key).id,
            "123-::1-23-2001:db8::1-4242"
        );
        let conn_id = ConnectionIdString::from(&key);
        assert_eq!(ConnectionKey::try_from(&conn_id).unwrap(), key);
    }

    #[test]
    fn test_conn_id_backwards_compatibility() {
        let idstr = ConnectionIdString {
            id: "6#127.0.0.1#23#1.2.3.4#4242".to_owned(),
        };
        let expected_key = ConnectionKey {
            local_ip: IpAddr::from_str("127.0.0.1").unwrap(),
            remote_ip: IpAddr::from_str("1.2.3.4").unwrap(),
            local_l4_port: 23,
            remote_l4_port: 4242,
            ip_proto: IpProtocol::TCP,
        };
        assert_eq!(ConnectionKey::try_from(&idstr).unwrap(), expected_key);
    }

    #[test]
    fn test_connection_id_errors() {
        let to_conn_key = |conn_id_str: &str| {
            ConnectionKey::try_from(&ConnectionIdString {
                id: conn_id_str.to_owned(),
            })
        };
        assert!(to_conn_key("asdf").is_err());
        assert!(to_conn_key("X-127.0.0.1-23-1.2.3.4-4242").is_err());
        assert!(to_conn_key("6-xxx-23-1.2.3.4-4242").is_err());
        assert!(to_conn_key("6-127.0.0.1-xxxx-1.2.3.4-4242").is_err());
        assert!(to_conn_key("6-127.0.0.1-23-xxx-4242").is_err());
        assert!(to_conn_key("6-127.0.0.1-23-1.2.3.4-xxxxx").is_err());
    }

    /// Make sure that ConnectionIdString is serialized just like a normal String
    /// i.e., serde(transparent) does what I think it does.
    #[test]
    fn test_connection_serialize() {
        let x: Vec<ConnectionIdString> = vec![ConnectionIdString {
            id: "123-::1-23-2001:db8::1-4242".to_owned(),
        }];
        assert_eq!(
            serde_json::to_string(&x).unwrap(),
            r#"["123-::1-23-2001:db8::1-4242"]"#
        );
    }
}
