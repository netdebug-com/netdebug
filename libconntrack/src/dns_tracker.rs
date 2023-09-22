use common::evicting_hash_map::EvictingHashMap;
#[cfg(not(test))]
use log::{debug, warn};
#[cfg(test)]
use std::{println as debug, println as warn}; // Workaround to use prinltn! for logs.

use std::{collections::HashMap, io::Error, net::IpAddr};
use tokio::{
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};

use chrono::{Duration, Utc};
use libconntrack_wasm::DnsTrackerEntry;

use crate::connection::{ConnectionKey, ConnectionTrackerMsg};
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

pub struct DnsTracker<'a> {
    pub reverse_map: HashMap<IpAddr, DnsTrackerEntry>,
    pub reverse_map_recently_expired: EvictingHashMap<'a, IpAddr, DnsTrackerEntry>,
    pub pending: HashMap<DnsPendingKey, DnsPendingEntry>,
    pub unparsed_pkt_count: usize,
}

pub struct DnsTrackerStats {
    pub unparsed_pkt_count: usize,
}

pub enum DnsTrackerMessage {
    NewEntry {
        key: ConnectionKey,
        timestamp: Duration,
        data: Vec<u8>,
        src_is_local: bool,
    },
    DumpReverseMap {
        // NOTE: this only returns the current active entries
        // and ignores the recently expired entries
        tx: UnboundedSender<HashMap<IpAddr, DnsTrackerEntry>>,
    },
    CacheForever {
        // used to make all of the local IPs show up as 'localhost'
        ip: IpAddr,
        hostname: String,
    },
    Lookup {
        ip: IpAddr,
        key: ConnectionKey,
        tx: UnboundedSender<ConnectionTrackerMsg>,
    },
    LookupBatch {
        // Lookup this list of IP addresses
        // NOTE: by passing this to the DNS tracker and it passing back
        // an answer, we can leverage the LRU cache for the recently expired
        // entries
        addrs: Vec<IpAddr>,
        tx: UnboundedSender<HashMap<IpAddr, DnsTrackerEntry>>,
        use_expired: bool,
    },
    GetStats {
        tx: UnboundedSender<DnsTrackerStats>,
    },
}

impl<'a> DnsTracker<'a> {
    /// New DnsTracker
    pub fn new(expired_entries_capacity: usize) -> DnsTracker<'a> {
        DnsTracker {
            reverse_map: HashMap::new(),
            pending: HashMap::new(),
            reverse_map_recently_expired: EvictingHashMap::new(expired_entries_capacity, |_, _| {}),
            unparsed_pkt_count: 0,
        }
    }

    /**
     * Naively, we can't resolve IP DNS information for connections that were
     * started before the DnsTracker.  If available, pre-populate the DNS
     * cache information that we keep with the one that the OS keeps to help
     * resolve more IP addresses, e.g., in the GUI.
     */
    pub fn try_to_load_os_cache(&mut self) -> Result<(), Box<Error>> {
        // unless this is windows, this is currently a NOOP
        #[cfg(windows)]
        self.load_windows_dns_cache(
            // Note, 'ipconfig /displaydns' also does this, but needs admin!?
            // this is also easier to parse
            std::process::Command::new("powershell")
                // 'out-string -width 256' overrides the $COLS equivalent and
                // stops trunaction of the output - sigh
                // could convert everything to json with '|convertTo-Json' but
                // seems like a PITA
                .arg("get-dnsclientcache | out-string -width 256")
                .output()
                .unwrap()
                .stdout
                .as_slice(),
        )?;
        Ok(())
    }

    pub async fn spawn(
        expired_entries_capacity: usize,
    ) -> (UnboundedSender<DnsTrackerMessage>, JoinHandle<()>) {
        let mut dns_tracker = DnsTracker::new(expired_entries_capacity);
        let (tx, rx) = unbounded_channel::<DnsTrackerMessage>();
        let join = tokio::spawn(async move { dns_tracker.do_async_loop(rx).await });
        (tx, join)
    }

    pub async fn do_async_loop(&mut self, mut rx: UnboundedReceiver<DnsTrackerMessage>) {
        while let Some(msg) = rx.recv().await {
            use DnsTrackerMessage::*;
            match msg {
                NewEntry {
                    data,
                    timestamp,
                    key,
                    src_is_local,
                } => self.parse_dns(key, timestamp, data, src_is_local).await,
                DumpReverseMap { tx } => self.dump_reverse_map(tx),
                CacheForever { ip, hostname } => self.cache_forever(ip, hostname),
                LookupBatch {
                    addrs,
                    tx,
                    use_expired,
                } => self.lookup_batch(addrs, tx, use_expired),
                Lookup { ip, key, tx } => self.lookup_for_connection_tracker(ip, key, tx),
                GetStats { tx } => self.fetch_stats(tx),
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
                self.unparsed_pkt_count += 1;
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
                    HTTPS(_) |
                    Unknown(_, _) => None,
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
            // moved expired entries to the recently expired cache
            let entry = self.reverse_map.remove(k).unwrap();
            self.reverse_map_recently_expired.insert(*k, entry);
        }
    }

    /*
    * Load the OS-level DNS cache info into our cache to pre-populate things
    *
    * Yes, it's screen scraping, but the win32 API for this appears to be
    * obfuscated and/or private - this seems easier
    *
    *
    Entry                     RecordName                Record Status    Section TimeTo Data   Data
                                                        Type                     Live   Length
    -----                     ----------                ------ ------    ------- ------ ------ ----
    ocsp.digicert.com         ocsp.digicert.com         CNAME  Success   Answer    2241      8 ocsp.edge.digicert.com
    ocsp.digicert.com         ocsp.edge.digicert.com    CNAME  Success   Answer    2241      8 fp2e7a.wpc.2be4.phicdn.net
    ocsp.digicert.com         fp2e7a.wpc.2be4.phicdn... CNAME  Success   Answer    2241      8 fp2e7a.wpc.phicdn.net
    ocsp.digicert.com         fp2e7a.wpc.phicdn.net     A      Success   Answer    2241      4 192.229.211.108
         *
         */
    #[cfg(windows)]
    fn load_windows_dns_cache<R>(&mut self, input: R) -> Result<(), Box<Error>>
    where
        R: std::io::Read,
    {
        use std::str::FromStr;

        let all_input = std::io::read_to_string(input).unwrap();
        for line in all_input.lines() {
            let tokens = line.split_whitespace().collect::<Vec<&str>>();
            // we only care about 'A' and 'AAAA' for now
            if tokens.len() >= 7 && (tokens[2] == "A" || tokens[2] == "AAAA") {
                let entry = DnsTrackerEntry {
                    hostname: tokens[1].to_string(),
                    created: Utc::now(), // kinda a fudge, oh well
                    rtt: None,
                    ttl: Some(Duration::seconds(i64::from_str(tokens[5]).expect("digits"))),
                };
                match IpAddr::from_str(tokens[7]) {
                    Ok(ip) => {
                        self.reverse_map.insert(ip, entry);
                    }
                    Err(e) => warn!(
                        "DnsTracker::load_windows_dns_cache - failed to parse IP in '{}' : {}",
                        tokens[7], e
                    ),
                };
            }
        }
        Ok(())
    }

    /**
     * Lookup at batch of IP addresses and send it back to the caller.
     */

    fn lookup_batch(
        &mut self,
        addrs: Vec<IpAddr>,
        tx: UnboundedSender<HashMap<IpAddr, DnsTrackerEntry>>,
        use_expired: bool,
    ) {
        let mut answer = HashMap::new();

        for ip in addrs {
            // first try the active/valid entries
            if let Some(entry) = self.reverse_map.get(&ip) {
                answer.insert(ip, entry.clone());
            } else if use_expired {
                if let Some(entry) = self.reverse_map_recently_expired.get_mut(&ip) {
                    answer.insert(ip, entry.clone());
                }
            }
            /* else -- TODO: do a regular DNS PTR lookup to map the ip to something; for later */
        }

        if let Err(e) = tx.send(answer) {
            warn!(
                "Failed to send DnsTracker::lookup_batch answer back to caller: {}",
                e
            );
        }
    }

    /**
     * This is used specifically for the ConnectionTracker so we can record DNS names and not forget them
     * for the lifetime of the connection
     */

    fn lookup_for_connection_tracker(
        &self,
        ip: IpAddr,
        key: ConnectionKey,
        tx: UnboundedSender<ConnectionTrackerMsg>,
    ) {
        let remote_hostname = if let Some(entry) = self.reverse_map.get(&ip) {
            Some(entry.hostname.clone())
        } else {
            None
        };
        debug!("Looking up IP: {} - found {:?}", ip, remote_hostname);
        use ConnectionTrackerMsg::*;
        if let Err(e) = tx.send(SetConnectionRemoteHostnameDns {
            key,
            remote_hostname,
        }) {
            warn!(
                "Failed to send DnsLookup reply to connection manager: {}",
                e
            );
        }
    }

    fn fetch_stats(&self, tx: UnboundedSender<DnsTrackerStats>) {
        if let Err(e) = tx.send(DnsTrackerStats {
            unparsed_pkt_count: self.unparsed_pkt_count,
        }) {
            warn!("Sending error processing fetch_stats(): {}", e);
        }
    }
}

#[cfg(test)]
mod test {
    use etherparse::TransportHeader;

    use crate::{
        connection::{test::test_dir, ConnectionTracker},
        owned_packet::OwnedParsedPacket,
        pcap::MockRawSocketWriter,
        utils,
    };

    use super::*;
    use std::{collections::HashSet, str::FromStr};

    #[tokio::test]
    async fn match_dns_request_to_reply() {
        let mut dns_tracker = DnsTracker::new(10);
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
        let mut dns_tracker = DnsTracker::new(10);
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
        assert_eq!(dns_tracker.reverse_map_recently_expired.len(), 0);
        dns_tracker.expire_cache();
        assert_eq!(dns_tracker.reverse_map.len(), 0);
        assert_eq!(dns_tracker.reverse_map_recently_expired.len(), 1);
    }

    #[tokio::test]
    /**
     * Walk through every packet in a live capture of DNS traffic and make sure
     * we can parse everything and serialize/deserialize everything
     */
    async fn verify_real_dns_data() {
        let mut dns_tracker = DnsTracker::new(10);
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
                _ => panic!("Non-UDP packet in the DNS+UDP only trace"),
            };
            assert!(udp.source_port == UDP_DNS_PORT || udp.destination_port == UDP_DNS_PORT);
            let (key, src_is_local) = pkt.to_connection_key(&local_addrs).unwrap();
            let timestamp = utils::timeval_to_duration(pkt.pcap_header.ts.clone());
            dns_tracker
                .parse_dns(key, timestamp, pkt.payload, src_is_local)
                .await;
        }
        // TODO: sanity check this data; for now just parsing is enough

        // now make sure we can serialize/deserialize it all
        for (_ip, dns_entry) in &dns_tracker.reverse_map {
            let json = serde_json::to_string(dns_entry).unwrap();
            println!("{}", json);
            let new_value: DnsTrackerEntry = serde_json::from_str(&json).unwrap();
            assert_eq!(*dns_entry, new_value);
        }
    }

    #[test]
    #[cfg(windows)]
    fn verify_windows_load_os_client_cache() {
        use std::fs::File;

        let mut dns_tracker = DnsTracker::new(10);
        let input = File::open(test_dir("tests/windows_get_dnsclientcache.txt")).unwrap();
        assert!(dns_tracker.load_windows_dns_cache(input).is_ok());
        assert_eq!(dns_tracker.reverse_map.len(), 24); // from the test data
    }

    #[test]
    fn verify_load_os_client_cache() {
        use std::net::ToSocketAddrs;
        let mut dns_tracker = DnsTracker::new(10);
        // resolve google.com to add something to the OS cache; just the first one
        #[allow(unused)] // this var won't be used if not windows
        let addr = "google.com:443".to_socket_addrs().unwrap().next();
        dns_tracker.try_to_load_os_cache().unwrap();
        /*
         * If not windows, it's ok for the DnsTracker::try_to_load_os_cache() to just not Err(_) out
         * Which is handled by the .unwrap()
         */
        #[cfg(windows)]
        {
            let google_addr = addr.unwrap();
            assert!(dns_tracker.reverse_map.contains_key(&google_addr.ip()));
        }
    }

    /**
     * This is a list of IPs that we've manually found to be in the following
     * pcap of DNS requests/replies - let's make sure we can resolve all of them
     */

    #[tokio::test]
    async fn verify_lost_dns() {
        use std::{
            fs::File,
            io::{BufRead, BufReader},
        };
        use tokio::sync::mpsc;
        let (dns_tx, _) = DnsTracker::spawn(100).await;
        let local_addrs =
            HashSet::from([IpAddr::from_str("2600:1700:5b20:4e10:adc4:bd8f:d640:2d48").unwrap()]);
        let log_dir = ".".to_string();
        let storage_service_client = None;
        let max_connections_per_tracker = 32;
        let raw_sock = MockRawSocketWriter::new();
        let mut connection_tracker = ConnectionTracker::new(
            log_dir,
            storage_service_client,
            max_connections_per_tracker,
            local_addrs,
            raw_sock,
        );
        connection_tracker.set_dns_tracker(dns_tx.clone());
        dns_tx
            .send(DnsTrackerMessage::CacheForever {
                ip: IpAddr::from_str("192.168.1.103").unwrap(),
                hostname: "localhost".to_string(),
            })
            .unwrap();

        // dump all the packets from the trace into the connection tracker; they will send all to DNS
        let mut capture = pcap::Capture::from_file(test_dir("tests/lost_dns.pcap")).unwrap();
        while let Ok(pkt) = capture.next_packet() {
            let owned_pkt = OwnedParsedPacket::try_from(pkt).unwrap();
            connection_tracker.add(owned_pkt);
        }
        // NOTE that 'tests/lost_dns.ips_all' includes IPs that we don't see in DNS!
        let addrs = BufReader::new(File::open(test_dir("tests/lost_dns.ips_all")).unwrap())
            .lines()
            .map(|s| IpAddr::from_str(s.unwrap().as_str()).unwrap())
            .collect::<Vec<IpAddr>>();
        let working_addrs = BufReader::new(File::open(test_dir("tests/lost_dns.ips")).unwrap())
            .lines()
            .map(|s| IpAddr::from_str(s.unwrap().as_str()).unwrap())
            .collect::<HashSet<IpAddr>>();
        // make sure everything parsed properly
        let (stats_tx, mut stats_rx) = mpsc::unbounded_channel();
        dns_tx
            .send(DnsTrackerMessage::GetStats { tx: stats_tx })
            .unwrap();
        let stats = stats_rx.recv().await.unwrap();
        assert_eq!(stats.unparsed_pkt_count, 0);

        // make sure we can look up everything
        let (cache_tx, mut cache_rx) = mpsc::unbounded_channel();
        dns_tx
            .send(DnsTrackerMessage::LookupBatch {
                addrs: addrs.clone(),
                tx: cache_tx,
                use_expired: true,
            })
            .unwrap();
        let dns_cache = cache_rx.recv().await.unwrap();
        let mut missing_count = 0;
        for ip in addrs {
            if !dns_cache.contains_key(&ip) {
                debug!("We're missing IP {}", ip);
                missing_count += 1;
                assert!(!working_addrs.contains(&ip));
            }
        }
        assert_eq!(missing_count, 34);
    }
}
