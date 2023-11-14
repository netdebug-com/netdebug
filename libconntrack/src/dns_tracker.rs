use bytes::{BufMut, BytesMut};
use common_wasm::evicting_hash_map::EvictingHashMap;
#[cfg(not(test))]
use log::{debug, warn};
use rand::Rng;
#[cfg(test)]
use std::{println as debug, println as warn}; // Workaround to use prinltn! for logs.

use std::{collections::HashMap, io::Error, net::IpAddr, str::FromStr};
use tokio::{
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};

use chrono::{DateTime, Duration, Utc};
use libconntrack_wasm::DnsTrackerEntry;

use crate::{
    connection::ConnectionKey,
    connection_tracker::{ConnectionTrackerMsg, ConnectionTrackerSender},
    send_or_log_sync,
    utils::PerfMsgCheck,
};
use dns_parser::{self, QueryType};

pub const UDP_DNS_PORT: u16 = 53;
pub struct DnsPendingEntry {
    sent_timestamp: DateTime<Utc>,
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
    pub local_dns_servers: HashMap<IpAddr, usize>,
    pending_lookups: EvictingHashMap<'a, IpAddr, (Vec<ConnectionKey>, ConnectionTrackerSender)>,
}

pub struct DnsTrackerStats {
    pub unparsed_pkt_count: usize,
}

pub enum DnsTrackerMessage {
    NewEntry {
        key: ConnectionKey,
        timestamp: DateTime<Utc>,
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
        tx: ConnectionTrackerSender,
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
            local_dns_servers: HashMap::new(),
            // TODO: use the eviction callback to track DNS entires that never got a reply
            pending_lookups: EvictingHashMap::new(expired_entries_capacity, |_, _| {}),
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
                } => self.lookup_batch(addrs, tx, use_expired).await,
                Lookup { ip, key, tx } => self.lookup_for_connection_tracker(ip, key, tx).await,
                GetStats { tx } => self.fetch_stats(tx),
            }
        }
    }

    async fn parse_dns(
        &mut self,
        key: ConnectionKey,
        timestamp: DateTime<Utc>,
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
        timestamp: DateTime<Utc>,
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
        timestamp: DateTime<Utc>,
        dns_packet: dns_parser::Packet<'_>,
        _src_is_local: bool,
    ) {
        // track who sent us a DNS reply
        let src_dns_server = key.remote_ip.clone();
        if dns_packet.header.response_code == dns_parser::ResponseCode::NoError {
            *self.local_dns_servers.entry(src_dns_server).or_insert(0) += 1;
        }

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

            for answer in &dns_packet.answers {
                self.parse_resource_record(answer, &rtt, &created);
            }
            for additional in &dns_packet.additional {
                self.parse_resource_record(additional, &rtt, &created);
            }
        }
    }

    fn parse_resource_record(
        &mut self,
        answer: &dns_parser::ResourceRecord<'_>,
        rtt: &Option<Duration>,
        created: &DateTime<Utc>,
    ) {
        let hostname = answer.name.to_string();
        if answer.cls != dns_parser::Class::IN {
            warn!(
                "Ignoring non-Internet/Class::IN DNS resource record: {:?}",
                answer
            );
            return;
        }
        use dns_parser::RData::*;
        let reply = match answer.data {
            // only match A/AAAA records, for now
            A(a) => Some((IpAddr::from(a.0), hostname, false)),
            AAAA(aaaa) => Some((IpAddr::from(aaaa.0), hostname, false)),
            PTR(ptr) => match dns_ptr_decode(&hostname) {
                Ok(ip) => Some((ip, ptr.0.to_string(), true)),
                Err(e) => {
                    warn!("dns_ptr_decode returned {}", e);
                    None
                }
            },
            CNAME(_)
            | MX(_)
            | NS(_)
            | SOA(_)
            | SRV(_)
            | TXT(_)
            | HTTPS(_)
            | SVCB(_)
            | Unknown(_, _) => None,
        };
        if let Some((ip, hostname, from_ptr_record)) = reply {
            if !from_ptr_record || !self.reverse_map.contains_key(&ip) {
                // only write the record if it's not a PTR or if it doesn't
                // overwrite non-PTR data
                // A/AAAA is preferred because that's more likely to be meaningful to humans
                // e.g. "google.com" instead of "server463.1ee100.net"
                self.reverse_map.insert(
                    ip,
                    DnsTrackerEntry {
                        hostname: hostname.clone(),
                        created: created.clone(),
                        from_ptr_record,
                        rtt: rtt.clone(),
                        ttl: Some(chrono::Duration::seconds(answer.ttl as i64)),
                    },
                );
                self.check_pending_lookups(ip, hostname);
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
                from_ptr_record: false,
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

    /**
     * Sometimes we need more clarity and need to lookup an IpAddr ourselves.
     * This can happen if some program has used an IP without first doing a
     * plaintext DNS lookup on UDP 53, e.g., if they did a DNS lookup in QUIC
     * or worse, none at all
     *
     * We can just fire and forget this message because if we get a reply, our
     * standard DNS tracking schemes should parse it and add it into our cache
     *
     * TODO: add some ratelimiting/intelligence to not keep probing the same IP
     * if we're not getting replies
     */

    async fn send_dns_ptr_lookup(&mut self, ip: IpAddr) {
        if cfg!(test) {
            // if we're a test, never send a packet out
            return;
        }
        let dns_server = if self.local_dns_servers.len() > 0 {
            // pick the most common DNS server we've seen a reply from
            self.local_dns_servers
                .iter()
                .max_by(|(_k1, v1), (_k2, v2)| v2.cmp(&v1))
                .map(|(k, _v)| k)
                .unwrap()
                .clone()
        } else {
            // we know nothing, just use a global DNS server
            IpAddr::from_str("8.8.8.8").unwrap()
        };
        let request = make_dns_ptr_lookup_request(ip, None).unwrap();
        let bind_addr = if dns_server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        match tokio::net::UdpSocket::bind(bind_addr).await {
            Ok(udp) => {
                if let Err(e) = udp.send_to(&request, (dns_server, 53)).await {
                    warn!("Failed to send UDP DNS lookup: {} : {}", dns_server, e);
                }
            }
            Err(e) => {
                warn!("Failed to bind a UDP socket on {}  :: {}", bind_addr, e);
            }
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
        let all_input = std::io::read_to_string(input).unwrap();
        for line in all_input.lines() {
            let tokens = line.split_whitespace().collect::<Vec<&str>>();
            // we only care about 'A' and 'AAAA' for now
            if tokens.len() >= 7 && (tokens[2] == "A" || tokens[2] == "AAAA") {
                let entry = DnsTrackerEntry {
                    hostname: tokens[1].to_string(),
                    created: Utc::now(), // kinda a fudge, oh well
                    from_ptr_record: false,
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

    async fn lookup_batch(
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
                continue;
            }
            if use_expired {
                if let Some(entry) = self.reverse_map_recently_expired.get_mut(&ip) {
                    answer.insert(ip, entry.clone());
                    continue;
                }
            }
            /* else -- do a regular DNS PTR lookup to try to map the ip to something */
            self.send_dns_ptr_lookup(ip).await;
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

    async fn lookup_for_connection_tracker(
        &mut self,
        ip: IpAddr,
        key: ConnectionKey,
        tx: ConnectionTrackerSender,
    ) {
        let remote_hostname = if let Some(entry) = self.reverse_map.get(&ip) {
            Some(entry.hostname.clone())
        } else if let Some(entry) = self.reverse_map_recently_expired.get_mut(&ip) {
            /*
            TODO:
            check expired and if not
            queue request in an evicting hash and send out a DNS request for the PTR record
            nuke the lookup_batch function
            */
            Some(entry.hostname.clone())
        } else {
            if !self.pending_lookups.contains_key(&ip) {
                self.pending_lookups.insert(ip.clone(), (vec![key], tx));
                self.send_dns_ptr_lookup(ip).await;
            } else {
                let (keys, _tx) = self.pending_lookups.get_mut(&ip).unwrap();
                keys.push(key);
            }
            return;
        };
        debug!("Looking up IP: {} - found {:?}", ip, remote_hostname);
        use ConnectionTrackerMsg::*;
        send_or_log_sync!(
            tx,
            "conntracker",
            SetConnectionRemoteHostnameDns {
                keys: vec![key],
                remote_hostname,
            }
        );
    }

    fn fetch_stats(&self, tx: UnboundedSender<DnsTrackerStats>) {
        if let Err(e) = tx.send(DnsTrackerStats {
            unparsed_pkt_count: self.unparsed_pkt_count,
        }) {
            warn!("Sending error processing fetch_stats(): {}", e);
        }
    }

    /**
     * When we learn a new ip --> hostname mapping, check to see if
     * the ConnectionTracker is waiting to hear about this IP and
     * notify it if it is.
     *
     * Remove the entry if it's found
     *
     */
    fn check_pending_lookups(&mut self, ip: IpAddr, remote_hostname: String) {
        if self.pending_lookups.contains_key(&ip) {
            let (keys, tx) = self.pending_lookups.remove(&ip).unwrap();
            use ConnectionTrackerMsg::*;
            send_or_log_sync!(
                tx,
                "Connection_tracker",
                SetConnectionRemoteHostnameDns {
                    keys,
                    remote_hostname: Some(remote_hostname)
                }
            );
        }
    }
}

/**
 * IP PTR records are encoded --> take the name and decode the IP from it
 *
 * 8.128.8.128.in-addr.arpa. --> 128.8.128.8
 * e.0.0.2.0.0.0.0.0.0.0.0.0.0.0.0.3.1.8.0.5.0.0.4.0.b.8.f.7.0.6.2.ip6.arpa. --> 2607:f8b0:4005:813::200e
 *
 * Note to self: there's got to be a cleaner/safer way to do this
 */

fn dns_ptr_decode(name: &String) -> Result<IpAddr, Box<dyn std::error::Error>> {
    let name = name.to_lowercase(); // can't be chained with .trim_end_matches()
    let name = name.trim_end_matches('.'); // remove trailing period if there
    if name.ends_with(DNS_PTR_V4_DOMAIN) {
        let tokens = name.split(".").collect::<Vec<&str>>();
        Ok(IpAddr::try_from([
            u8::from_str_radix(tokens[3], 10)?,
            u8::from_str_radix(tokens[2], 10)?,
            u8::from_str_radix(tokens[1], 10)?,
            u8::from_str_radix(tokens[0], 10)?,
        ])?)
    } else if name.ends_with(DNS_PTR_V6_DOMAIN) {
        let tokens = name.split(".").collect::<Vec<&str>>();
        if tokens.len() < 32 {
            return Err(format!("dns_ptr_decode: Less than 32 digits in Ipv6 addr!?").into());
        }
        let mut addr: [u8; 16] = [0; 16];
        for i in 0..=15 {
            let oct = (u8::from_str_radix(&tokens[2 * i + 1], 16)? << 4)
                + u8::from_str_radix(&tokens[2 * i], 16)?;
            addr[15 - i] = oct; // put in reverse order
        }
        Ok(IpAddr::try_from(addr)?)
    } else {
        Err(format!("dns_ptr_decode() Didn't end with known domain: '{}'", name).into())
    }
}

/**
 * The opposite of dns_ptr_decode
 */

fn dns_ptr_encode(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // reverse order in base10, per DNS RFC
            format!(
                "{}.{}.{}.{}.{}",
                octets[3], octets[2], octets[1], octets[0], DNS_PTR_V4_DOMAIN
            )
        }
        IpAddr::V6(v6) => {
            let mut base = v6
                .octets()
                .map(|oct| format!("{:x}.{:x}", 0x0f & oct, (0xf0 & oct) >> 4));
            base.reverse();
            format!("{}.{}", base.join("."), DNS_PTR_V6_DOMAIN)
        }
    }
}

/**
 * The dns-parser library doesn't support writing - sigh.  We don't need proper writing,
 * just a simple request, so hack it together with wireshark and test it.
 *
 * The query name is funkily encoded almost like a run-length encoding, so
 * "www.foobar.com" is encoded a 3www6foobar3com0
 *
 * For reference/pretty DNS header pictures:
 * https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf
 *  (Thank you Alan - miss you man :-)
 *
 */
const DNS_HEADER_LEN: usize = 12;
const DNS_MIN_MSG_LEN: usize = DNS_HEADER_LEN + 6; // includes initial digit for lead label and 0 for string termination
pub fn make_dns_lookup_request(
    name: String,
    qtype: QueryType,
    transaction_id: Option<u16>,
) -> Result<Vec<u8>, String> {
    let mut request = BytesMut::with_capacity(DNS_MIN_MSG_LEN + name.len());
    let transaction_id = match transaction_id {
        Some(id) => id,
        None => {
            let mut rng = rand::thread_rng();
            rng.gen()
        }
    };
    request.put_u16(transaction_id);
    request.put_u8(1); // FLAGS=recursion desired
    request.put_u8(0); // other half of flags
    request.put_u16(1); // #questions = 1
    request.put_u16(0); // #answers = 0
    request.put_u16(0); // #authories = 0
    request.put_u16(0); // #additional = 0
    for label in name.split('.') {
        if label.len() > 63 {
            return Err(format!(
                "DNS label too long for protocol: {} from {}",
                label, name
            ));
        }
        if label.is_empty() {
            break; // skip trailing '.' as an empty label is not allowed in DNS
        }
        request.put_u8(label.len() as u8);
        request.put_slice(label.as_bytes());
    }
    request.put_u8(0); // null terminate string
    request.put_u16(qtype as u16);
    request.put_u16(dns_parser::Class::IN as u16);

    Ok(request.to_vec())
}

const DNS_PTR_V4_DOMAIN: &str = "in-addr.arpa";
const DNS_PTR_V6_DOMAIN: &str = "ip6.arpa";
pub fn make_dns_ptr_lookup_request(
    ip: IpAddr,
    transaction_id: Option<u16>,
) -> Result<Vec<u8>, String> {
    let name = dns_ptr_encode(ip);
    make_dns_lookup_request(name, QueryType::PTR, transaction_id)
}

#[cfg(test)]
mod test {
    use common::test_utils::test_dir;
    use common_wasm::timeseries_stats::ExportedStatRegistry;
    use dns_parser::QueryType;
    use etherparse::TransportHeader;
    use tokio::sync::mpsc::channel;

    use crate::{
        connection_tracker::ConnectionTracker, owned_packet::OwnedParsedPacket,
        pcap::MockRawSocketProber,
    };

    use super::*;
    use chrono::TimeZone;
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
        let t0 = Utc.timestamp_opt(0, 0).unwrap();
        dns_tracker
            .parse_dns(key.clone(), t0, request.to_vec(), true)
            .await;
        assert_eq!(dns_tracker.pending.len(), 1);
        assert_eq!(dns_tracker.reverse_map.len(), 0);
        let t1 = Utc.timestamp_opt(0, 100_000).unwrap();
        dns_tracker.parse_dns(key, t1, reply.to_vec(), true).await;
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
            assert!(!entry.from_ptr_record);
            assert_eq!(entry.rtt.unwrap(), t1 - t0); // RTT is the second timestamp b/c first is zero
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
                from_ptr_record: false,
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
        let mut capture =
            pcap::Capture::from_file(test_dir("libconntrack", "tests/dns_traces.pcap")).unwrap();
        // grab each packet and dump it into the dns tracker
        while let Ok(pkt) = capture.next_packet() {
            let pkt = OwnedParsedPacket::try_from(pkt).unwrap();
            let udp = match &pkt.transport {
                Some(TransportHeader::Udp(udp)) => udp,
                _ => panic!("Non-UDP packet in the DNS+UDP only trace"),
            };
            assert!(udp.source_port == UDP_DNS_PORT || udp.destination_port == UDP_DNS_PORT);
            let (key, src_is_local) = pkt.to_connection_key(&local_addrs).unwrap();
            dns_tracker
                .parse_dns(key, pkt.timestamp, pkt.payload, src_is_local)
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
        let input = File::open(test_dir(
            "libconntrack",
            "tests/windows_get_dnsclientcache.txt",
        ))
        .unwrap();
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
        let storage_service_client = None;
        let max_connections_per_tracker = 32;
        let mock_prober = MockRawSocketProber::new();
        let mut connection_tracker = ConnectionTracker::new(
            storage_service_client,
            max_connections_per_tracker,
            local_addrs,
            mock_prober.tx.clone(),
            128,
            ExportedStatRegistry::new("conn_tracker", std::time::Instant::now()),
        );
        connection_tracker.set_dns_tracker(dns_tx.clone());
        dns_tx
            .send(DnsTrackerMessage::CacheForever {
                ip: IpAddr::from_str("192.168.1.103").unwrap(),
                hostname: "localhost".to_string(),
            })
            .unwrap();

        // dump all the packets from the trace into the connection tracker; they will send all to DNS
        let mut capture =
            pcap::Capture::from_file(test_dir("libconntrack", "tests/lost_dns.pcap")).unwrap();
        while let Ok(pkt) = capture.next_packet() {
            let owned_pkt = OwnedParsedPacket::try_from(pkt).unwrap();
            connection_tracker.add(owned_pkt);
        }
        // NOTE that 'tests/lost_dns.ips_all' includes IPs that we don't see in DNS!
        let addrs =
            BufReader::new(File::open(test_dir("libconntrack", "tests/lost_dns.ips_all")).unwrap())
                .lines()
                .map(|s| IpAddr::from_str(s.unwrap().as_str()).unwrap())
                .collect::<Vec<IpAddr>>();
        let working_addrs =
            BufReader::new(File::open(test_dir("libconntrack", "tests/lost_dns.ips")).unwrap())
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

    #[test]
    fn test_make_dns_request() {
        let buf =
            make_dns_lookup_request("example.com".to_string(), QueryType::A, Some(0x0102)).unwrap();

        let request = dns_parser::Packet::parse(&buf).unwrap();
        assert_eq!(request.questions.len(), 1);
        let question = request.questions.iter().next().unwrap();
        assert_eq!(question.qtype, QueryType::A);
        assert_eq!(question.qclass, dns_parser::QueryClass::IN);
        assert_eq!(question.qname.to_string(), "example.com".to_string());
        assert_eq!(request.answers.len(), 0);
        assert_eq!(request.additional.len(), 0);
        assert_eq!(request.header.id, 0x0102);
        assert_eq!(request.header.recursion_desired, true);

        let buf = make_dns_lookup_request("example.com.".to_string(), QueryType::A, Some(0x0102))
            .unwrap();
        let request_trailing_period = dns_parser::Packet::parse(&buf).unwrap();
        let new_question = request_trailing_period.questions.iter().next().unwrap();
        assert_eq!(question.qname.to_string(), new_question.qname.to_string());

        // last, make sure we get an error if we have too long of a label
        let evil_hostname = format!("www.{}.com", "x".to_string().repeat(64));
        let err = make_dns_lookup_request(evil_hostname, QueryType::A, None);
        assert!(err.is_err());
    }

    #[test]
    fn dns_ptr_lookup() {
        let v4_addr = IpAddr::from_str("1.2.3.4").unwrap();
        let buf = make_dns_ptr_lookup_request(v4_addr, None).unwrap();
        let request = dns_parser::Packet::parse(&buf).unwrap();
        let question = request.questions.iter().next().unwrap();
        assert_eq!(
            question.qname.to_string(),
            "4.3.2.1.in-addr.arpa".to_string()
        );
        let v6_addr = IpAddr::from_str("0011:2233:4455:6677:8899:aabb:ccdd:effe").unwrap();
        let buf = make_dns_ptr_lookup_request(v6_addr, None).unwrap();
        let request = dns_parser::Packet::parse(&buf).unwrap();
        let question = request.questions.iter().next().unwrap();
        assert_eq!(
            question.qname.to_string(),
            // from `dig -x 0011:2233:4455:6677:8899:aabb:ccdd:effe`
            "e.f.f.e.d.d.c.c.b.b.a.a.9.9.8.8.7.7.6.6.5.5.4.4.3.3.2.2.1.1.0.0.ip6.arpa".to_string()
        );
    }

    #[test]
    fn dns_ptr_encode_decode() {
        for ip in [
            IpAddr::from_str("127.0.0.1").unwrap(),
            IpAddr::from_str("2607:f8b0:4005:813::200e").unwrap(),
            IpAddr::from_str("128.8.128.38").unwrap(),
        ] {
            let test_ip = dns_ptr_decode(&dns_ptr_encode(ip)).unwrap();
            assert_eq!(ip, test_ip);
        }
    }

    #[tokio::test]
    async fn dns_ptr_cache() {
        let dns_ptr_ip = IpAddr::from_str("128.8.128.8").unwrap();
        let dns_ptr_hostname = "netman.cs.umd.edu".to_string();
        /*
         * 0000   00 02 81 80 00 01 00 01 00 00 00 00 01 38 03 31   .............8.1
         * 0010   32 38 01 38 03 31 32 38 07 69 6e 2d 61 64 64 72   28.8.128.in-addr
         * 0020   04 61 72 70 61 00 00 0c 00 01 c0 0c 00 0c 00 01   .arpa...........
         * 0030   00 00 0e 02 00 13 06 6e 65 74 6d 61 6e 02 63 73   .......netman.cs
         * 0040   03 75 6d 64 03 65 64 75 00                        .umd.edu.
         */
        let dns_ptr_reply = [
            0x00, 0x02, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x38,
            0x03, 0x31, 0x32, 0x38, 0x01, 0x38, 0x03, 0x31, 0x32, 0x38, 0x07, 0x69, 0x6e, 0x2d,
            0x61, 0x64, 0x64, 0x72, 0x04, 0x61, 0x72, 0x70, 0x61, 0x00, 0x00, 0x0c, 0x00, 0x01,
            0xc0, 0x0c, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x02, 0x00, 0x13, 0x06, 0x6e,
            0x65, 0x74, 0x6d, 0x61, 0x6e, 0x02, 0x63, 0x73, 0x03, 0x75, 0x6d, 0x64, 0x03, 0x65,
            0x64, 0x75, 0x00,
        ];
        let mut dns_tracker = DnsTracker::new(10);
        let key = ConnectionKey {
            local_ip: IpAddr::from_str("127.0.0.1").unwrap(),
            remote_ip: IpAddr::from_str("8.8.8.8").unwrap(),
            local_l4_port: 1234,
            remote_l4_port: 53,
            ip_proto: 6,
        };
        let timestamp = DateTime::<Utc>::UNIX_EPOCH;
        dns_tracker
            .parse_dns(key.clone(), timestamp, dns_ptr_reply.to_vec(), true)
            .await;
        assert_eq!(dns_tracker.reverse_map.len(), 1);
        assert!(dns_tracker.reverse_map.contains_key(&dns_ptr_ip));
        let entry = dns_tracker.reverse_map.get(&dns_ptr_ip).unwrap();
        assert_eq!(entry.hostname, dns_ptr_hostname);
        assert!(entry.from_ptr_record);
    }

    /**
     * Do a lookup on an empty cache, which should create a pending entry,
     * and then fake the reply and verify we get notified about the new
     * entry (what we asked for) and that the pending entry got cleared.
     *
     * Running this test will actually call the code (``DnsTracker::send_dns_ptr_lookup``)
     * to send a PTR request out, but it's 'if cfg!(test)'d to not send packets so
     * that's harmless.
     */

    #[tokio::test]
    async fn dns_pending_lookup() {
        let dns_ptr_ip = IpAddr::from_str("128.8.128.8").unwrap();
        let dns_ptr_hostname = "netman.cs.umd.edu".to_string();
        let (tx, mut rx) = channel(128);
        /*
         * 0000   00 02 81 80 00 01 00 01 00 00 00 00 01 38 03 31   .............8.1
         * 0010   32 38 01 38 03 31 32 38 07 69 6e 2d 61 64 64 72   28.8.128.in-addr
         * 0020   04 61 72 70 61 00 00 0c 00 01 c0 0c 00 0c 00 01   .arpa...........
         * 0030   00 00 0e 02 00 13 06 6e 65 74 6d 61 6e 02 63 73   .......netman.cs
         * 0040   03 75 6d 64 03 65 64 75 00                        .umd.edu.
         */
        let dns_ptr_reply = [
            0x00, 0x02, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x38,
            0x03, 0x31, 0x32, 0x38, 0x01, 0x38, 0x03, 0x31, 0x32, 0x38, 0x07, 0x69, 0x6e, 0x2d,
            0x61, 0x64, 0x64, 0x72, 0x04, 0x61, 0x72, 0x70, 0x61, 0x00, 0x00, 0x0c, 0x00, 0x01,
            0xc0, 0x0c, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x02, 0x00, 0x13, 0x06, 0x6e,
            0x65, 0x74, 0x6d, 0x61, 0x6e, 0x02, 0x63, 0x73, 0x03, 0x75, 0x6d, 0x64, 0x03, 0x65,
            0x64, 0x75, 0x00,
        ];
        let mut dns_tracker = DnsTracker::new(10);
        let key = ConnectionKey {
            local_ip: IpAddr::from_str("127.0.0.1").unwrap(),
            remote_ip: IpAddr::from_str("8.8.8.8").unwrap(),
            local_l4_port: 1234,
            remote_l4_port: 53,
            ip_proto: 6,
        };
        dns_tracker
            .lookup_for_connection_tracker(dns_ptr_ip, key.clone(), tx)
            .await;
        assert_eq!(dns_tracker.pending_lookups.len(), 1);

        let timestamp = DateTime::<Utc>::UNIX_EPOCH;
        dns_tracker
            .parse_dns(key.clone(), timestamp, dns_ptr_reply.to_vec(), true)
            .await;
        assert_eq!(dns_tracker.reverse_map.len(), 1);
        assert!(dns_tracker.reverse_map.contains_key(&dns_ptr_ip));
        let entry = dns_tracker.reverse_map.get(&dns_ptr_ip).unwrap();
        assert_eq!(entry.hostname, dns_ptr_hostname);
        assert!(entry.from_ptr_record);
        // now verify we got the notification
        use ConnectionTrackerMsg::*;
        match rx.try_recv().unwrap().skip_perf_check() {
            SetConnectionRemoteHostnameDns {
                keys: test_key,
                remote_hostname,
            } => {
                assert_eq!(test_key, vec![key]);
                assert_eq!(remote_hostname.unwrap(), dns_ptr_hostname);
            }
            _other => panic!("Got unexpected notification: {:?}", _other),
        }
        assert_eq!(dns_tracker.pending_lookups.len(), 0);
    }

    #[test]
    fn dns_upper_case_domains() {
        // from garbage DNS services
        let test_data = vec![
            (
                "203.135.235.44.IN-ADDR.arpa".to_string(),
                IpAddr::from([44, 235, 135, 203]),
            ),
            (
                "1.7.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.0.c.0.2.0.0.4.0.b.8.f.7.0.6.2.ip6.ARPA"
                    .to_string(),
                IpAddr::from([
                    0x26, 0x07, 0xf8, 0xb0, 0x40, 0x02, 0x0c, 0x0c, 0, 0, 0, 0, 0, 0, 0, 0x71,
                ]),
            ),
        ];
        for (test, valid) in test_data {
            assert_eq!(dns_ptr_decode(&test).unwrap(), valid);
        }
    }
}
