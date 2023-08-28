use log::{debug, warn};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::IpAddr};
use tokio::{
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};

use chrono::{DateTime, Duration, Utc};

use crate::connection::ConnectionKey;
use dns_parser::{self, QueryType};

pub const UDP_DNS_PORT: u16 = 53;

#[serde_with::serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsTrackerEntry {
    hostname: String,
    created: DateTime<Utc>,
    #[serde_as(as = "Option<serde_with::DurationMicroSeconds<i64>>")]
    rtt: Option<chrono::Duration>,
}

pub struct DnsPendingEntry {
    sent_timestamp: Duration,
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub struct DnsPendingKey {
    connection_key: ConnectionKey,
    transaction_id: u16,
}

pub struct DnsTracker {
    pub reverse_map: HashMap<IpAddr, DnsTrackerEntry>,
    pub pending: HashMap<DnsPendingKey, DnsPendingEntry>,
}

pub enum DnsTrackerMessage {
    NewEntry {
        key: ConnectionKey,
        timestamp: Duration,
        data: Vec<u8>,
        src_is_local: bool,
    },
}

impl DnsTracker {
    /// New DnsTracker
    pub fn new() -> DnsTracker {
        DnsTracker {
            reverse_map: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    pub async fn spawn(mut self) -> (UnboundedSender<DnsTrackerMessage>, JoinHandle<()>) {
        let (tx, rx) = unbounded_channel::<DnsTrackerMessage>();
        let join = tokio::spawn(async move { self.do_async_loop(rx).await });
        (tx, join)
    }

    pub async fn do_async_loop(&mut self, mut rx: UnboundedReceiver<DnsTrackerMessage>) {
        while let Some(msg) = rx.recv().await {
            match msg {
                DnsTrackerMessage::NewEntry {
                    data,
                    timestamp,
                    key,
                    src_is_local,
                } => self.parse_dns(key, timestamp, data, src_is_local).await,
            }
        }
    }

    async fn parse_dns(
        &mut self,
        key: ConnectionKey,
        timestamp: Duration,
        data: Vec<u8>,
        src_is_local: bool,
    ) {
        let dns_packet = match dns_parser::Packet::parse(&data) {
            Ok(pkt) => pkt,
            Err(e) => {
                warn!(
                    "Ignoring unparsed DNS message: {} :: {:?} : {} ",
                    e, data, key
                );
                return; // nothing left to do
            }
        };

        if dns_packet.header.query {
            self.parse_dns_request(key, timestamp, dns_packet, src_is_local);
        } else {
            self.parse_dns_reply(key, timestamp, dns_packet, src_is_local);
        }
    }

    /**
     * Got a DNS request - store it as a pending entry
     */
    fn parse_dns_request(
        &mut self,
        key: ConnectionKey,
        timestamp: Duration,
        dns_packet: dns_parser::Packet<'_>,
        _src_is_local: bool,
    ) {
        let key = DnsPendingKey {
            connection_key: key,
            transaction_id: dns_packet.header.id,
        };

        let pending = DnsPendingEntry {
            sent_timestamp: timestamp,
        };
        self.pending.insert(key, pending);
    }

    /**
     * Got a DNS reply - try to match it to the request and calc perf data
     */
    fn parse_dns_reply(
        &mut self,
        key: ConnectionKey,
        timestamp: Duration,
        dns_packet: dns_parser::Packet<'_>,
        _src_is_local: bool,
    ) {
        let key = DnsPendingKey {
            connection_key: key,
            transaction_id: dns_packet.header.id,
        };
        let rtt = if let Some(pending) = self.pending.get(&key) {
            // NOTE: important to use chrono::Duration here and not std::time::Duration
            // as the latter will panic!() if the rtt is negative which can happen
            // with erradic clocks and standard network pendantics
            let rtt = timestamp - pending.sent_timestamp;
            self.pending.remove(&key);
            Some(rtt)
        } else {
            // if we didn't see the outgoing request, we won't be able to calc the rtt
            None
        };

        // cache all of the permutations so we can efficiently map from IP to A/AAAA record
        let created = Utc::now();
        for question in &dns_packet.questions {
            if question.qclass != dns_parser::QueryClass::IN {
                warn!(
                    "Ignoring non-Internet/Class::IN DNS resource record query: {:?}",
                    question
                );
                continue;
            }

            if question.qtype != QueryType::A && question.qtype != QueryType::AAAA {
                debug!(
                    "Ignoring non-A/AAAA DNS resource record query: {:?}",
                    question
                );
                continue;
            }
            let hostname = question.qname.to_string();

            for answer in &dns_packet.answers {
                if answer.cls != dns_parser::Class::IN {
                    warn!(
                        "Ignoring non-Internet/Class::IN DNS resource record: {:?}",
                        answer
                    );
                    continue;
                }
                use dns_parser::RData::*;
                let addr = match answer.data {
                    // only match A/AAAA records, for now
                    A(a) => Some(IpAddr::from(a.0)),
                    AAAA(aaaa) => Some(IpAddr::from(aaaa.0)),
                    CNAME(_) |
                    MX(_) |
                    NS(_) |
                    PTR(_) |    // maybe one day cache these as well?
                    SOA(_) |
                    SRV(_) |
                    TXT(_) |
                    Unknown(_) => None,
                };
                if let Some(ip) = addr {
                    self.reverse_map.insert(
                        ip,
                        DnsTrackerEntry {
                            hostname: hostname.clone(),
                            created,
                            rtt,
                        },
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::{collections::HashSet, str::FromStr};

    #[tokio::test]
    async fn match_dns_request_to_reply() {
        let mut dns_tracker = DnsTracker::new();
        let request: [u8; 26] = [
            0x8d, 0xb9, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x6f,
            0x03, 0x73, 0x73, 0x32, 0x02, 0x75, 0x73, 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let reply: [u8; 90] = [
            0x8d, 0xb9, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x6f,
            0x03, 0x73, 0x73, 0x32, 0x02, 0x75, 0x73, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x04, 0x0d, 0xe3, 0x15, 0x8f,
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x04, 0x0d, 0xe3,
            0x15, 0x75, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x04,
            0x0d, 0xe3, 0x15, 0xaf, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2e,
            0x00, 0x04, 0x0d, 0xe3, 0x15, 0x53,
        ];

        let key = ConnectionKey {
            local_ip: IpAddr::from_str("127.0.0.1").unwrap(),
            remote_ip: IpAddr::from_str("8.8.8.8").unwrap(),
            local_l4_port: 1234,
            remote_l4_port: 53,
            ip_proto: 6,
        };
        let timestamp = Duration::microseconds(0);
        dns_tracker
            .parse_dns(key.clone(), timestamp, request.to_vec(), true)
            .await;
        assert_eq!(dns_tracker.pending.len(), 1);
        assert_eq!(dns_tracker.reverse_map.len(), 0);
        let timestamp = Duration::microseconds(100);
        dns_tracker
            .parse_dns(key, timestamp, reply.to_vec(), true)
            .await;
        assert_eq!(dns_tracker.pending.len(), 0);
        assert_eq!(dns_tracker.reverse_map.len(), 4);
        if let Some((ip, entry)) = dns_tracker.reverse_map.iter().next() {
            // could be any of these four - hashmap order is not specified
            let valid_ips = HashSet::from([
                IpAddr::from_str("13.227.21.143").unwrap(),
                IpAddr::from_str("13.227.21.117").unwrap(),
                IpAddr::from_str("13.227.21.175").unwrap(),
                IpAddr::from_str("13.227.21.83").unwrap(),
            ]);
            assert!(valid_ips.contains(ip));
            assert_eq!(entry.rtt.unwrap(), timestamp); // RTT is the second timestamp b/c first is zero
        } else {
            panic!("No DNS entry cached!?");
        }
    }
}
