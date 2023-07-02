use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
};

use common::{ProbeReport, ProbeReportEntry, PROBE_MAX_TTL};
use etherparse::{IpHeader, TcpHeader, TransportHeader};
use log::{info, warn};

use crate::{
    context::Context,
    in_band_probe::tcp_inband_probe,
    owned_packet::OwnedParsedPacket,
    pcap::RawSocketWriter,
    utils::{calc_rtt_ms, etherparse_ipheaders2ipaddr, timeval_to_ms},
};

#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd)]
pub struct ConnectionKey {
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
    pub local_l4_port: u16,
    pub remote_l4_port: u16,
    pub ip_proto: u8,
}

impl std::fmt::Display for ConnectionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let proto_desc = format!("ip_proto={}", self.ip_proto);
        write!(
            f,
            "{} [{}]::{} --> [{}]::{} ",
            proto_desc, self.local_ip, self.local_l4_port, self.remote_ip, self.remote_l4_port,
        )
    }
}

impl ConnectionKey {
    /**
     * Create a ConnectionKey from a remote socket addr and the global context
     */
    pub async fn new(context: &Context, addr: &SocketAddr, ip_proto: u8) -> Self {
        // Annoying - it turns out it's hard in Warp to figure out which local IP a given
        // connection is talking to - this technique should be close, but might
        // have problems with funky routing tables, e.g., where the packets
        // are coming in one interface but going out another

        let remote_ip = addr.ip();
        let local_ip = crate::utils::remote_ip_to_local(remote_ip).unwrap();
        let c = context.read().await;
        let local_l4_port = c.local_tcp_listen_port;

        ConnectionKey {
            local_ip,
            remote_ip,
            local_l4_port,
            remote_l4_port: addr.port(),
            ip_proto,
        }
    }
}

/**
 * ConnectionTracker uses the Agent model :: https://en.wikipedia.org/wiki/Agent-oriented_programming
 * which simplifies multithreading and state management.
 *
 * When a piece of code wants to interact with a ConnectionTracker, get the sender from the
 * global context and send it an async message
 */
#[derive(Debug)]
pub enum ConnectionTrackerMsg {
    Pkt(OwnedParsedPacket), // send the connecti
    ProbeReport {
        key: ConnectionKey,
        clear_state: bool,
        tx: tokio::sync::mpsc::Sender<ProbeReport>,
    },
}

/***
 * Maintain the state for a bunch of connections.   Also, cache some information
 * that doesn't change often, e.g. ,the local IP addresses and listen port of
 * the webserver so we don't need to get the information from the WebServerContext every
 * packet.  The assumption is that if that information changes (e.g., new IP address),
 * then we would spin up new ConnectionTracker instances.
 */

pub struct ConnectionTracker<R>
where
    R: RawSocketWriter,
{
    context: Context,
    connections: HashMap<ConnectionKey, Connection>,
    local_addrs: HashSet<IpAddr>,
    local_tcp_ports: HashSet<u16>,
    raw_sock: R,
}
impl<R> ConnectionTracker<R>
where
    R: RawSocketWriter,
{
    pub async fn new(
        context: Context,
        local_addrs: HashSet<IpAddr>,
        raw_sock: R,
    ) -> ConnectionTracker<R> {
        let mut local_tcp_ports = HashSet::new();
        local_tcp_ports.insert(context.read().await.local_tcp_listen_port);
        ConnectionTracker {
            context,
            connections: HashMap::new(),
            local_addrs,
            local_tcp_ports,
            raw_sock,
        }
    }

    pub async fn rx_loop(
        &mut self,
        mut rx: tokio::sync::mpsc::UnboundedReceiver<ConnectionTrackerMsg>,
    ) {
        while let Some(msg) = rx.recv().await {
            use ConnectionTrackerMsg::*;
            match msg {
                Pkt(pkt) => self.add(pkt),
                ProbeReport {
                    key,
                    clear_state,
                    tx,
                } => self.generate_report(key, clear_state, tx).await,
            }
        }
        info!("ConnectionTracker exiting rx_loop()");
    }

    pub fn add(&mut self, packet: OwnedParsedPacket) {
        if let Some((key, src_is_local)) =
            packet.to_connection_key(&self.local_addrs, &self.local_tcp_ports)
        {
            if let Some(connection) = self.connections.get_mut(&key) {
                connection.update(
                    &self.context,
                    packet,
                    &mut self.raw_sock,
                    &key,
                    src_is_local,
                )
            } else {
                self.new_connection(packet, key, src_is_local)
            }
        }
        // if we got here, the packet didn't have enough info to be called a 'connection'
        // just return and move on for now
    }

    fn new_connection(
        &mut self,
        packet: OwnedParsedPacket,
        key: ConnectionKey,
        src_is_local: bool,
    ) {
        let mut connection = Connection {
            local_syn: None,
            remote_syn: None,
            local_seq: None,
            local_ack: None,
            local_data: None,
            outgoing_probe_timestamps: HashMap::new(),
            incoming_reply_timestamps: HashMap::new(),
        };
        info!("Tracking new connection: {}", &key);

        connection.update(
            &self.context,
            packet,
            &mut self.raw_sock,
            &key,
            src_is_local,
        );
        self.connections.insert(key, connection);
    }

    /**
     * Generate a ProbeReport from the given connection/key
     *
     * If called with a bad key, caller will get back None from rx.recv() if we exit without
     */

    async fn generate_report(
        &mut self,
        key: ConnectionKey,
        clear_state: bool,
        tx: tokio::sync::mpsc::Sender<ProbeReport>,
    ) {
        if let Some(connection) = self.connections.get_mut(&key) {
            let report = connection.generate_probe_report(clear_state).await;
            if let Err(e) = tx.send(report).await {
                warn!("Error sending back report: {}", e);
            }
        } else {
            warn!("Found no connection matching key {}", key);
            // sending nothing will close the connection and thus return None to the report receiver
        }
    }
}

type ProbeId = u8;
#[derive(Clone, Debug)]
pub struct Connection {
    pub local_syn: Option<OwnedParsedPacket>,
    pub remote_syn: Option<OwnedParsedPacket>,
    pub local_seq: Option<u32>,
    pub local_ack: Option<u32>,
    pub local_data: Option<Vec<u8>>, // data sent for retransmits
    pub outgoing_probe_timestamps: HashMap<ProbeId, HashSet<OwnedParsedPacket>>,
    pub incoming_reply_timestamps: HashMap<ProbeId, HashSet<OwnedParsedPacket>>,
}
impl Connection {
    fn update<R>(
        &mut self,
        context: &Context,
        packet: OwnedParsedPacket,
        raw_sock: &mut R,
        key: &ConnectionKey,
        src_is_local: bool,
    ) where
        R: RawSocketWriter,
    {
        match &packet.transport {
            Some(TransportHeader::Tcp(tcp)) => {
                if src_is_local {
                    self.update_tcp_local(context, &packet, tcp, raw_sock);
                } else {
                    self.update_tcp_remote(&packet, tcp);
                }
            }
            Some(TransportHeader::Icmpv4(icmp4)) => {
                if src_is_local {
                    warn!(
                        "Ignoring weird ICMP4 from our selves but for this connection: {} : {:?}",
                        key, packet
                    );
                } else {
                    self.update_icmp4_remote(context, &packet, icmp4);
                }
            }
            Some(TransportHeader::Icmpv6(_icmp6)) => {
                todo!("Need to implement icmp6 handling")
            }
            _ => warn!("Got Connection::update() for non-TCP packet - ignoring for now"),
        }
    }

    /**
     * To avoid storing copies of all data, particularly in a high-speed connection,
     * we need a heuristic to separate outgoing probe packets and incoming incoming_reply_timestamps
     * from regular traffic...
     * .. but one that isn't obviously different enought to concern an IDS.
     *
     * It's performance issue if we mark too many packets as probes, so err on the
     * inclusive side and just say "any packet with a small payload" is a probe.
     *
     * Use the payload length to encode the probe ID/ttl
     */

    fn is_probe_heuristic(
        &self,
        src_is_local: bool,
        packet: &OwnedParsedPacket,
    ) -> Option<ProbeId> {
        // any packet with a small payload is a probe
        if packet.payload.len() <= PROBE_MAX_TTL as usize {
            if src_is_local {
                // for outgoing packets, the TTL of the probe is the ttl of the outer packet
                let ttl = match &packet.ip {
                    None => None, // no IP header, not a probe
                    Some(IpHeader::Version4(ip4, _)) => Some(ip4.time_to_live),
                    Some(IpHeader::Version6(ip6, _)) => Some(ip6.hop_limit),
                };
                if let Some(t) = ttl {
                    if t > PROBE_MAX_TTL {
                        return None; // can't have a probe with a ttl larger than we would send
                    }
                }
                return ttl; // else assume the heuristicis correct
            }
        } else {
            // TODO: need to parse into the packet to extract the encapped payload and thus the probe ID
            return None;
        }
        None
    }

    fn update_tcp_local<R>(
        &mut self,
        context: &Context,
        packet: &OwnedParsedPacket,
        tcp: &TcpHeader,
        raw_sock: &mut R,
    ) where
        R: RawSocketWriter,
    {
        // record the SYN to see which TCP options are negotiated
        if tcp.syn {
            self.local_syn = Some(packet.clone()); // memcpy() but doesn't happen that much or with much data
        }

        // record how far the local side has acknowledged
        if tcp.ack {
            self.local_ack = Some(tcp.acknowledgment_number);
        }

        // did we send some payload?
        if !packet.payload.is_empty() {
            let mut first_time = false;
            if self.local_data.is_none() {
                // this is the first time in the connection lifetime we sent some payload
                // spawn an inband probe
                first_time = true;
            }
            self.local_data = Some(packet.payload.clone());
            if first_time {
                let packet_clone = packet.clone();
                let context_clone = context.clone();
                tcp_inband_probe(context_clone, packet_clone, raw_sock).unwrap();
            }
        }
        if let Some(ttl) = self.is_probe_heuristic(true, packet) {
            // there's some super clean rust-ish way to compress this; don't care for now
            if let Some(probes) = self.outgoing_probe_timestamps.get_mut(&ttl) {
                probes.insert(packet.clone());
            } else {
                let mut probes = HashSet::new();
                probes.insert(packet.clone());
                self.outgoing_probe_timestamps.insert(ttl, probes);
            }
        }
        // TODO: look for outgoing selective acks (indicates packet loss)
    }

    fn update_tcp_remote(&mut self, packet: &OwnedParsedPacket, tcp: &TcpHeader) {
        if tcp.syn {
            self.remote_syn = Some(packet.clone()); // memcpy() but doesn't happen that much or with much data
        }
        // TODO: look for incoming selective acks (indicates packet loss)
    }

    fn update_icmp4_remote(
        &mut self,
        _context: &Context,
        packet: &OwnedParsedPacket,
        icmp4: &etherparse::Icmpv4Header,
    ) {
        match icmp4.icmp_type {
            etherparse::Icmpv4Type::Unknown {
                type_u8: _,
                code_u8: _,
                bytes5to8: _,
            }
            | etherparse::Icmpv4Type::EchoRequest(_)
            | etherparse::Icmpv4Type::EchoReply(_)
            | etherparse::Icmpv4Type::TimestampRequest(_)
            | etherparse::Icmpv4Type::TimestampReply(_) => (),
            etherparse::Icmpv4Type::DestinationUnreachable(_)
            | etherparse::Icmpv4Type::Redirect(_)
            | etherparse::Icmpv4Type::TimeExceeded(_)
            | etherparse::Icmpv4Type::ParameterProblem(_) => {
                // TODO figure out how to cache this from the connection_key() computation
                // if it's a perf problem - ignore for now
                // but right now we're creating this embedded packet twice!
                match OwnedParsedPacket::from_partial_embedded_ip_packet(
                    &packet.payload,
                    Some(packet.pcap_header),
                ) {
                    Ok((pkt, _partial)) => {
                        if let Some(probe_id) = self.is_reply_heuristic(&pkt) {
                            if let Some(hash) = self.incoming_reply_timestamps.get_mut(&probe_id) {
                                hash.insert(pkt);
                            } else {
                                self.incoming_reply_timestamps
                                    // careful to store the original packet and not the embedded one
                                    .insert(probe_id, HashSet::from([packet.clone()]));
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Failed to parsed update_icmp4_remote() {} for {:?}",
                            e, packet
                        );
                    }
                }
            }
        }
    }

    /**
     * Call on a packet which is potentially a reply to a probe and if it is,
     * extract the probe ID;  this should be called on the embedded packet
     * of an ICMP TTL exceeded
     *
     * TODO: suppoort matching a TCP ACK from the end host
     *
     * Something is a probe is (1) it's old data and (2) if the payload
     * length (which we don't have but can reconstruct) is < PROBE_MAX_TTL
     *
     * This is a "heuristic" because there's possibly pathological behavior
     * in the network such that we falsely identify a regular packet as a reply
     */

    fn is_reply_heuristic(&self, pkt: &OwnedParsedPacket) -> Option<ProbeId> {
        match &pkt.transport {
            Some(TransportHeader::Tcp(_tcp)) => {
                // TODO: convert to SEQ-based probe-id encoding
                let (total_len, iph_len) = match &pkt.ip {
                    Some(IpHeader::Version4(ip4, _)) => {
                        // NOTE: etherparse "smartly" already returns hdr_len * 4
                        (ip4.total_len(), ip4.header_len() as u16)
                    }
                    Some(IpHeader::Version6(ip6, _)) => {
                        // NOTE: etherparse "smartly" already returns hdr_len * 4
                        (ip6.payload_length, ip6.header_len() as u16)
                    }
                    None => {
                        warn!("No IP packet with a TCP packet!?");
                        return None;
                    }
                };
                // probe-Id = total_len - sizeof(iph) - sizeof(tcph)
                // Outgoing probes have no TCP options; so are exactly 20 bytes
                // which makes them look weird to an IDS and we lose precision
                let probe_id = total_len - iph_len - 20;

                if probe_id < PROBE_MAX_TTL as u16 {
                    Some(probe_id as u8)
                } else {
                    None
                }
            }
            Some(_) | None => None,
        }
    }

    /**
     * Match up the outgoing probes vs. incoming replies and generate a
     * report.  If 'clear' is set, reset the connection's state so we can do a new set
     * of probes on the next data packet
     */
    #[allow(dead_code)] // TODO: remove once we're calling this properly from the client
    async fn generate_probe_report(&mut self, clear: bool) -> ProbeReport {
        let mut report = Vec::new();
        for ttl in 1..=PROBE_MAX_TTL {
            let mut comment = String::new(); // no comment by default
            if let Some(probe_set) = self.outgoing_probe_timestamps.get(&ttl) {
                if probe_set.len() != 1 {
                    comment.push_str(
                        format!(
                            "Weird: {} probes found; guessing first one.",
                            probe_set.len()
                        )
                        .as_str(),
                    );
                }
                let probe = probe_set.iter().next().unwrap();
                let out_timestamp_ms = timeval_to_ms(probe.pcap_header.ts);
                if let Some(reply_set) = self.incoming_reply_timestamps.get(&ttl) {
                    if reply_set.len() != 1 {
                        comment.push_str(
                            format!(
                                " Weird: {} replies found; guessing first one.",
                                reply_set.len()
                            )
                            .as_str(),
                        );
                    }
                    // found a probe and a reply!
                    let reply = reply_set.iter().next().unwrap();
                    let rtt_ms = calc_rtt_ms(reply.pcap_header, probe.pcap_header);
                    // unwrap is ok here b/c we would have never stored a non-IP packet as a reply
                    let (src_ip, _dst_ip) = etherparse_ipheaders2ipaddr(&reply.ip).unwrap();
                    report.push(ProbeReportEntry::ReplyFound {
                        ttl,
                        out_timestamp_ms,
                        rtt_ms,
                        src_ip,
                        comment,
                    })
                } else {
                    // missing reply - unfortunately common
                    report.push(ProbeReportEntry::NoReply {
                        ttl,
                        out_timestamp_ms,
                        comment,
                    });
                }
            } else {
                // sigh, duplicate code
                if let Some(reply_set) = self.incoming_reply_timestamps.get(&ttl) {
                    if reply_set.len() != 1 {
                        comment.push_str(
                            format!(
                                " Weird: {} replies found; guessing first one.",
                                reply_set.len()
                            )
                            .as_str(),
                        );
                    }
                    // found a reply with out a probe (?) - can happen when pcap drops packets
                    let reply = reply_set.iter().next().unwrap();
                    // unwrap is ok here b/c we would have never stored a non-IP packet as a reply
                    let in_timestamp_ms = timeval_to_ms(reply.pcap_header.ts);
                    let (src_ip, _dst_ip) = etherparse_ipheaders2ipaddr(&reply.ip).unwrap();
                    report.push(ProbeReportEntry::ReplyNoProbe {
                        ttl,
                        in_timestamp_ms,
                        src_ip,
                        comment,
                    });
                } else {
                    // missing both reply and probe - a bad day
                    report.push(ProbeReportEntry::NoOutgoing { ttl, comment });
                }
            }
        }
        if clear {
            // reset the state so that the next outgoing data packet triggers another set of probes
            self.incoming_reply_timestamps.clear();
            self.outgoing_probe_timestamps.clear();
            self.local_data = None;
        }
        ProbeReport::new(report)
    }
}
#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    use crate::context::test::make_test_context;
    use crate::in_band_probe::test::test_tcp_packet_ports;
    use crate::owned_packet::OwnedParsedPacket;
    use crate::pcap::MockRawSocketWriter;
    /**
     *  ConnectionKey should be a direction agnostic key for mapping packets
     * to a flow identifier.  but, the logic around "is the src of the packet"
     * from the "local process" is complicated - test all of the permutations
     */
    #[tokio::test]
    async fn src_is_local() {
        let local_ip = IpAddr::from_str("192.168.1.1").unwrap();
        let remote_ip = IpAddr::from_str("192.168.1.2").unwrap();
        let localhost_ip = IpAddr::from_str("127.0.0.1").unwrap();
        let mut local_addrs = HashSet::new();
        local_addrs.insert(local_ip);
        local_addrs.insert(localhost_ip); // both the local ip and the localhost ip are 'local'
        let mut local_tcp_ports = HashSet::new();
        local_tcp_ports.insert(3030);

        let local_pkt = test_tcp_packet_ports(local_ip, remote_ip, 21, 12345);
        let (l_key, src_is_local) = local_pkt
            .to_connection_key(&local_addrs, &local_tcp_ports)
            .unwrap();
        assert!(src_is_local);

        let remote_pkt = test_tcp_packet_ports(remote_ip, local_ip, 12345, 21);
        let (r_key, src_is_local) = remote_pkt
            .to_connection_key(&local_addrs, &local_tcp_ports)
            .unwrap();
        assert!(!src_is_local);

        assert_eq!(l_key, r_key);

        let local_localhost_pkt = test_tcp_packet_ports(localhost_ip, localhost_ip, 3030, 12345);
        let (ll_key, src_is_local) = local_localhost_pkt
            .to_connection_key(&local_addrs, &local_tcp_ports)
            .unwrap();
        assert!(src_is_local);

        let remote_localhost_pkt = test_tcp_packet_ports(localhost_ip, localhost_ip, 12345, 3030);
        let (rl_key, src_is_local) = remote_localhost_pkt
            .to_connection_key(&local_addrs, &local_tcp_ports)
            .unwrap();
        assert!(!src_is_local);

        assert_eq!(ll_key, rl_key);
    }

    #[tokio::test]
    async fn connection_tracker_one_flow_outgoing() {
        let context = make_test_context();
        let raw_sock = MockRawSocketWriter::new();
        let mut local_addrs = HashSet::new();
        let localhost_ip = IpAddr::from_str("127.0.0.1").unwrap();
        local_addrs.insert(localhost_ip);
        let mut connection_tracker = ConnectionTracker::new(context, local_addrs, raw_sock).await;

        let mut capture =
            pcap::Capture::from_file("tests/simple_websocket_cleartxt_out_probes.pcap").unwrap();
        // take all of the packets in the capture and pipe them into the connection tracker
        while let Ok(pkt) = capture.next_packet() {
            let owned_pkt = OwnedParsedPacket::try_from(pkt).unwrap();
            connection_tracker.add(owned_pkt);
        }
        assert_eq!(connection_tracker.connections.len(), 1);
        let connection = connection_tracker.connections.values().next().unwrap();
        // TODO; verify more about these pkts
        let _local_syn = connection.local_syn.as_ref().unwrap();
        let _remote_syn = connection.remote_syn.as_ref().unwrap();

        // verify we captured each of the outgoing probes
        assert_eq!(
            connection.outgoing_probe_timestamps.len(),
            PROBE_MAX_TTL as usize
        );
        for probes in connection.outgoing_probe_timestamps.values() {
            assert_eq!(probes.len(), 1);
        }
    }

    const TEST_PROBE: [u8; 61] = [
        0x06, 0x25, 0x76, 0xbf, 0x7a, 0x4f, 0x06, 0x2e, 0x63, 0x19, 0xe4, 0xd3, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x2f, 0x00, 0x00, 0x40, 0x00, 0x07, 0x06, 0x70, 0xf6, 0xac, 0x1f, 0x02, 0x3d,
        0x4b, 0x0b, 0x09, 0x6c, 0x01, 0xbb, 0xa1, 0x0e, 0x13, 0x87, 0x86, 0x22, 0x00, 0x00, 0x00,
        0x00, 0x50, 0x00, 0x01, 0xe6, 0x74, 0xdb, 0x00, 0x00, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31,
        0x2e,
    ];

    const TEST_REPLY: [u8; 70] = [
        0x06, 0x2e, 0x63, 0x19, 0xe4, 0xd3, 0x06, 0x25, 0x76, 0xbf, 0x7a, 0x4f, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0xf5, 0x01, 0x56, 0x0b, 0x34, 0x5d, 0x8d, 0x00,
        0xac, 0x1f, 0x02, 0x3d, 0x0b, 0x00, 0xb8, 0x8c, 0x00, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00,
        0x2f, 0x00, 0x00, 0x40, 0x00, 0x01, 0x06, 0x76, 0xf6, 0xac, 0x1f, 0x02, 0x3d, 0x4b, 0x0b,
        0x09, 0x6c, 0x01, 0xbb, 0xa1, 0x0e, 0x13, 0x87, 0x86, 0x22,
    ];

    #[tokio::test]
    /**
     * Follow a TCP stream with outgoing probes and incoming replies and make sure
     * we can match them up to calculate RTTs, etc.
     */
    async fn connection_tracker_one_flow_out_and_in() {
        pretty_env_logger::init();
        let context = make_test_context();
        let raw_sock = MockRawSocketWriter::new();
        let mut local_addrs = HashSet::new();
        let local_ip = IpAddr::from_str("172.31.2.61").unwrap();
        local_addrs.insert(local_ip);
        let mut local_tcp_ports = HashSet::new();
        local_tcp_ports.insert(3030);
        let mut connection_tracker =
            ConnectionTracker::new(context, local_addrs.clone(), raw_sock).await;

        let mut connection_key: Option<ConnectionKey> = None;
        let mut capture =
            pcap::Capture::from_file("tests/simple_websocket_cleartext_remote_probe_replies.pcap")
                .unwrap();
        // take all of the packets in the capture and pipe them into the connection tracker
        while let Ok(pkt) = capture.next_packet() {
            let owned_pkt = OwnedParsedPacket::try_from(pkt).unwrap();
            let (key, _) = owned_pkt
                .to_connection_key(&local_addrs, &local_tcp_ports)
                .unwrap();
            if let Some(prev_key) = connection_key {
                assert_eq!(prev_key, key);
            }
            connection_key = Some(key);
            connection_tracker.add(owned_pkt);
        }
        assert_eq!(connection_tracker.connections.len(), 1);
        let connection = connection_tracker.connections.values_mut().next().unwrap();
        // TODO; verify more about these pkts
        let _local_syn = connection.local_syn.as_ref().unwrap();
        let _remote_syn = connection.remote_syn.as_ref().unwrap();

        // verify we captured each of the outgoing probes
        assert_eq!(
            connection.outgoing_probe_timestamps.len(),
            PROBE_MAX_TTL as usize
        );
        // verify we captured each of the incoming replies - note that we only got six replies!
        assert_eq!(connection.incoming_reply_timestamps.len(), 6);
        for probes in connection.outgoing_probe_timestamps.values() {
            assert_eq!(probes.len(), 1);
        }

        let report = connection.generate_probe_report(false).await;
        println!("Report:\n{}", report);
    }

    #[tokio::test]
    /**
     * Follow a TCP stream with outgoing probes and incoming replies and make sure
     * we can match them up to calculate RTTs, etc.
     */
    async fn connection_tracker_probe_and_reply() {
        let context = make_test_context();
        let raw_sock = MockRawSocketWriter::new();
        let mut local_addrs = HashSet::new();
        let local_ip = IpAddr::from_str("172.31.2.61").unwrap();
        local_addrs.insert(local_ip);
        let mut local_tcp_ports = HashSet::new();
        local_tcp_ports.insert(3030);
        let mut connection_tracker =
            ConnectionTracker::new(context, local_addrs.clone(), raw_sock).await;

        let probe = OwnedParsedPacket::try_from_fake_time(TEST_PROBE.to_vec()).unwrap();

        let icmp_reply = OwnedParsedPacket::try_from_fake_time(TEST_REPLY.to_vec()).unwrap();

        connection_tracker.add(probe);
        connection_tracker.add(icmp_reply);

        assert_eq!(connection_tracker.connections.len(), 1);
        let connection = connection_tracker.connections.values().next().unwrap();
        assert_eq!(connection.outgoing_probe_timestamps.len(), 1);
        assert_eq!(connection.incoming_reply_timestamps.len(), 1);
        let probe_id = connection.outgoing_probe_timestamps.keys().next().unwrap();
        let reply_id = connection.incoming_reply_timestamps.keys().next().unwrap();
        // probe and reply match!
        assert_eq!(*probe_id, 7);
        assert_eq!(*reply_id, 7);
    }

    #[tokio::test]
    /**
     * Make sure a probe and the corresponding ICMPv4 reply map to the same
     * connection key and the src_is_local logic is correct for both
     *
     * TODO: add ICMPv6 version of this test
     */
    async fn icmp4_to_connection_key() {
        let mut local_addrs = HashSet::new();
        local_addrs.insert(IpAddr::from_str("172.31.2.61").unwrap());
        let mut local_tcp_ports = HashSet::new();
        local_tcp_ports.insert(3030);
        let probe = OwnedParsedPacket::try_from_fake_time(TEST_PROBE.to_vec()).unwrap();

        let icmp_reply = OwnedParsedPacket::try_from_fake_time(TEST_REPLY.to_vec()).unwrap();
        let (probe_key, src_is_local) = probe
            .to_connection_key(&local_addrs, &local_tcp_ports)
            .unwrap();
        assert!(src_is_local);

        let (reply_key, src_is_local) = icmp_reply
            .to_connection_key(&local_addrs, &local_tcp_ports)
            .unwrap();
        assert!(!src_is_local);

        assert_eq!(probe_key, reply_key);
    }
}
