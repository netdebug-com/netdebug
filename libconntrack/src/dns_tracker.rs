#[cfg(not(test))]
use log::{debug, warn};
#[cfg(test)]
use std::{println as debug, println as warn}; // Workaround to use prinltn! for logs.

use std::{collections::HashMap, net::IpAddr};
use tokio::{
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};

use chrono::{Duration, Utc};
use libconntrack_wasm::DnsTrackerEntry;

use crate::connection::ConnectionKey;
use dns_parser::{self, QueryType};

pub const UDP_DNS_PORT: u16 = 53;
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
    DumpReverseMap {
        tx: UnboundedSender<HashMap<IpAddr, DnsTrackerEntry>>,
    },
    CacheForever {
        // used to make all of the local IPs show up as 'localhost'
        ip: IpAddr,
        hostname: String,
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
                DnsTrackerMessage::DumpReverseMap { tx } => self.dump_reverse_map(tx),
                DnsTrackerMessage::CacheForever { ip, hostname } => {
                    self.cache_forever(ip, hostname)
                }
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
                            ttl: Some(chrono::Duration::seconds(answer.ttl as i64)),
                        },
                    );
                }
            }
        }
    }

    /**
     * Send a copy of the reverse DNS map back to the caller.
     *
     */
    fn dump_reverse_map(&mut self, tx: UnboundedSender<HashMap<IpAddr, DnsTrackerEntry>>) {
        // Good time to expire the cache to stop propagating stale data
        self.expire_cache();
        let reverse_map = self.reverse_map.clone();
        if let Err(e) = tx.send(reverse_map) {
            warn!("Problem sending the reverse_map DNS dump: {}", e);
        }
    }

    /**
     * Permanently add this mapping to the cache - useful for tracking localhost's IPs
     * and pretty printing
     *
     * Could in theory get overridden if we look ourselves up, but then should just
     * get the FQDN which seems better
     */
    fn cache_forever(&mut self, ip: IpAddr, hostname: String) {
        let created = Utc::now();
        let rtt = None;
        self.reverse_map.insert(
            ip,
            DnsTrackerEntry {
                hostname,
                created,
                rtt,
                ttl: None,
            },
        );
    }

    /**
     * Walk the reverse_map and remove any entries that are older than their TTL
     */
    fn expire_cache(&mut self) {
        let now = Utc::now();
        // first pass, figure out which ones to delete; clone the keys so we don't reference the map
        let remove_list = &self
            .reverse_map
            .iter()
            .filter_map(|(k, v)| {
                if let Some(ttl) = v.ttl {
                    if now > (v.created + ttl) {
                        Some(k.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect::<Vec<IpAddr>>();
        // second pass, delete them
        for k in remove_list {
            self.reverse_map.remove(k);
        }
    }
}

#[cfg(test)]
mod test {
    use etherparse::TransportHeader;

    use crate::{connection::test::test_dir, owned_packet::OwnedParsedPacket, utils};

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

    #[tokio::test]
    async fn test_dns_expiration() {
        let mut dns_tracker = DnsTracker::new();
        // 'create' the entry 2 seconds ago with a ttl of 1 second, so it should expire immediately
        dns_tracker.reverse_map.insert(
            IpAddr::from_str("1.2.3.4").unwrap(),
            DnsTrackerEntry {
                hostname: "foo".to_string(),
                created: Utc::now() - Duration::seconds(2),
                rtt: None,
                ttl: Some(Duration::seconds(1)),
            },
        );
        dns_tracker.expire_cache();
        assert_eq!(dns_tracker.reverse_map.len(), 0);
    }

    #[tokio::test]
    /**
     * Walk through every packet in a live capture of DNS traffic and make sure
     * we can parse everything and serialize/deserialize everything
     */
    async fn verify_real_dns_data() {
        let mut dns_tracker = DnsTracker::new();
        let local_addrs = HashSet::from([
            IpAddr::from_str("192.168.1.103").unwrap(),
            IpAddr::from_str("2600:1700:5b20:4e10:3529:39f:19de:6434").unwrap(),
        ]);
        let mut capture = pcap::Capture::from_file(test_dir("tests/dns_traces.pcap")).unwrap();
        // grab each packet and dump it into the dns tracker
        while let Ok(pkt) = capture.next_packet() {
            let pkt = OwnedParsedPacket::try_from(pkt).unwrap();
            let udp = match &pkt.transport {
                Some(TransportHeader::Udp(udp)) => udp,
                _ => panic!("Non-UDP packet in the DNS+UDP only trace")
            };
            assert!(udp.source_port == UDP_DNS_PORT || udp.destination_port == UDP_DNS_PORT);
            let (key, src_is_local) = pkt.to_connection_key(&local_addrs).unwrap();
            let timestamp = utils::timeval_to_duration(pkt.pcap_header.ts.clone());
            dns_tracker.parse_dns(key, timestamp, pkt.payload, src_is_local).await;
        }
        // TODO: sanity check this data; for now just parsing is enough
        
        // now make sure we can serialize/deserialize it all
        for (_ip, dns_entry) in &dns_tracker.reverse_map {
            let json = serde_json::to_string(dns_entry).unwrap();
            println!("{}", json);
            let new_value : DnsTrackerEntry = serde_json::from_str(&json).unwrap();
            assert_eq!(*dns_entry, new_value);
        }
    }
}
