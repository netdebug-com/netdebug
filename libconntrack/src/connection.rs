use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
};

use chrono::{DateTime, Duration, Utc};
use common_wasm::{
    timeseries_stats::StatHandleDuration, ProbeId, ProbeReportEntry, ProbeReportSummary,
    ProbeRoundReport, PROBE_MAX_TTL,
};

use derive_getters::Getters;
use etherparse::{IpHeader, TcpHeader, TransportHeader, UdpHeader};
use libconntrack_wasm::{
    traffic_stats::BidirectionalStats, AggregateStatKind, ConnectionIdString, ConnectionKey,
    IpProtocol,
};
#[cfg(not(test))]
use log::{debug, warn};
use netstat2::ProtocolSocketInfo;
use tokio::{sync::mpsc, time::Instant};

#[cfg(test)]
use std::{println as debug, println as warn}; // Workaround to use prinltn! for logs.

use serde::{Deserialize, Serialize};

use crate::{
    dns_tracker::{DnsTrackerMessage, UDP_DNS_PORT},
    in_band_probe::ProbeMessage,
    owned_packet::OwnedParsedPacket,
    prober_helper::ProberHelper,
    utils::{calc_rtt_ms, etherparse_ipheaders2ipaddr, timestamp_to_ms, PerfMsgCheck},
    ConnectionSide, TcpSeq64, UnidirectionalTcpState,
};

pub const MAX_BURST_RATE_TIME_WINDOW_MILLIS: u64 = 10;

/**
 * Create a ConnectionKey from a remote socket addr and the global context
 *
 * NOTE: this code will not work in WASM b/c of the udp call
 */
pub async fn connection_key_from_remote_sockaddr(
    local_l4_port: u16,
    addr: &SocketAddr,
    ip_proto: u8,
) -> ConnectionKey {
    // Annoying - it turns out it's hard in Warp to figure out which local IP a given
    // connection is talking to - this technique should be close, but might
    // have problems with funky routing tables, e.g., where the packets
    // are coming in one interface but going out another

    let remote_ip = addr.ip();
    let local_ip = crate::utils::remote_ip_to_local(remote_ip).unwrap();

    ConnectionKey {
        local_ip,
        remote_ip,
        local_l4_port,
        remote_l4_port: addr.port(),
        ip_proto: IpProtocol::from_wire(ip_proto),
    }
}

pub fn connection_key_from_protocol_socket_info(proto_info: &ProtocolSocketInfo) -> ConnectionKey {
    match proto_info {
        ProtocolSocketInfo::Tcp(tcp) => {
            if tcp.local_addr != tcp.remote_addr {
                ConnectionKey {
                    local_ip: tcp.local_addr,
                    remote_ip: tcp.remote_addr,
                    local_l4_port: tcp.local_port,
                    remote_l4_port: tcp.remote_port,
                    ip_proto: IpProtocol::TCP,
                }
            } else {
                // this is commonly local_ip=remote_ip=localhost
                // so sort the ports to create a cannoical key
                let local_port = std::cmp::min(tcp.local_port, tcp.remote_port);
                let remote_port = std::cmp::max(tcp.local_port, tcp.remote_port);
                ConnectionKey {
                    local_ip: tcp.local_addr,
                    remote_ip: tcp.remote_addr,
                    local_l4_port: local_port,
                    remote_l4_port: remote_port,
                    ip_proto: IpProtocol::TCP,
                }
            }
        }
        ProtocolSocketInfo::Udp(_udp) => {
            panic!("Not supported for UDP yet - check out https://github.com/ohadravid/netstat2-rs/issues/11")
        }
    }
}

/**
 * TODO: move Probe stuff to a separate file.
 *
 * There are 'ProbeRounds' which is the state for an active set ("round") of probes
 * while it's in process.  A "ProbeReport" which is a finished set of probes where
 * we match the incoming replies to the outgoing original packets ("probes").  There
 * is also a "ProbeReportSummary" which summarizes multiple probe reports.
 */

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeRound {
    pub round_number: usize,
    pub start_time: DateTime<Utc>,
    /// The 64bit sequqnce number of the probe packets.
    pub probe_pkt_seq_no: TcpSeq64,
    pub next_end_host_reply: ProbeId, // used for idle probes
    // current probes: outgoing probes and incoming replies
    pub outgoing_probe_timestamps: HashMap<ProbeId, HashSet<OwnedParsedPacket>>,
    pub incoming_reply_timestamps: HashMap<ProbeId, HashSet<OwnedParsedPacket>>,
}
impl ProbeRound {
    fn new(round_number: usize, probe_pkt_seq_no: TcpSeq64) -> ProbeRound {
        ProbeRound {
            round_number,
            probe_pkt_seq_no,
            start_time: Utc::now(),
            next_end_host_reply: PROBE_MAX_TTL - 1,
            outgoing_probe_timestamps: HashMap::new(),
            incoming_reply_timestamps: HashMap::new(),
        }
    }
}

/**
 * Main connection tracking structure - one per connection.
 *
 * NOTE: everything in this struct will get serialized to a logfile on the connection's close
 * for analysis, so be thoughtful what you add here.
 */
#[derive(Clone, Debug, Getters)]
pub struct Connection {
    connection_key: ConnectionKey,
    /// System clock
    start_tracking_time: DateTime<Utc>,
    /// monotonic clock, also respects tokio::sleep::pause() for testing
    start_tracking_time_instant: Instant,
    /// Human readable time of the last packet for logging
    last_packet_time: DateTime<Utc>,
    /// The time of the last packet used for evictions and statekeeping
    last_packet_instant: tokio::time::Instant,
    /// data packet sent from the local side, used for probe retransmits
    local_data: Option<OwnedParsedPacket>,
    probe_round: Option<ProbeRound>,
    probe_report_summary: ProbeReportSummary,
    pub(crate) user_annotation: Option<String>, // an human supplied comment on this connection
    pub(crate) user_agent: Option<String>, // when created via a web request, store the user-agent header
    pub(crate) associated_apps: Option<HashMap<u32, Option<String>>>, // PID --> ProcessName, if we know it
    pub(crate) remote_hostname: Option<String>, // the FQDN of the remote host, if we know it
    traffic_stats: BidirectionalStats,
    // which counter groups does this flow belong to, e.g., "google.com" and "chrome"
    pub(crate) aggregate_groups: HashSet<AggregateStatKind>,
    local_tcp_state: Option<UnidirectionalTcpState>,
    remote_tcp_state: Option<UnidirectionalTcpState>,
}

impl Connection {
    pub(crate) fn new(key: ConnectionKey, ts: DateTime<Utc>) -> Connection {
        Connection {
            connection_key: key.clone(),
            local_data: None,
            probe_round: None,
            probe_report_summary: ProbeReportSummary::new(),
            user_annotation: None,
            user_agent: None,
            associated_apps: None,
            start_tracking_time: ts,
            start_tracking_time_instant: tokio::time::Instant::now(),
            last_packet_time: ts,
            last_packet_instant: tokio::time::Instant::now(),
            remote_hostname: None,
            traffic_stats: BidirectionalStats::new(std::time::Duration::from_millis(
                MAX_BURST_RATE_TIME_WINDOW_MILLIS,
            )),
            // all connections are part of the connection tracker counter group
            aggregate_groups: HashSet::from([AggregateStatKind::ConnectionTracker]),
            local_tcp_state: None,
            remote_tcp_state: None,
        }
    }

    pub(crate) fn update(
        &mut self,
        packet: Box<OwnedParsedPacket>,
        prober_helper: &mut ProberHelper,
        key: &ConnectionKey,
        src_is_local: bool,
        dns_tx: &Option<mpsc::UnboundedSender<DnsTrackerMessage>>,
        mut pcap_to_wall_delay: StatHandleDuration,
    ) {
        self.last_packet_time = packet.timestamp;
        let pcap_wall_dt = (Utc::now() - packet.timestamp).abs();
        pcap_to_wall_delay.add_duration_value(pcap_wall_dt.to_std().unwrap());
        self.last_packet_instant = tokio::time::Instant::now();
        self.traffic_stats
            .add_packet_with_time(src_is_local, packet.len as u64, packet.timestamp);
        match &packet.transport {
            Some(TransportHeader::Tcp(tcp)) => {
                self.update_tcp(src_is_local, &packet, tcp, prober_helper);
            }
            Some(TransportHeader::Icmpv4(icmp4)) => {
                if src_is_local {
                    warn!(
                        "Ignoring weird ICMP4 from our selves but for this connection: {} : {:?}",
                        key, packet
                    );
                } else {
                    self.update_icmp4_remote(&packet, icmp4);
                }
            }
            Some(TransportHeader::Icmpv6(icmp6)) => {
                if src_is_local {
                    warn!(
                        "Ignoring ICMP6 from our selves but for this connection: {} : {:?}",
                        key, packet
                    );
                } else {
                    self.update_icmp6_remote(&packet, icmp6);
                }
            }
            Some(TransportHeader::Udp(udp)) => {
                // logic is for both src_is_local and not, for now
                self.update_udp(key, &packet, udp, dns_tx, src_is_local);
            }
            None => {
                warn!(
                    "Ignoring unknown transport in IP protocol in packet {:?}",
                    packet
                );
            }
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
     *
     */

    pub(crate) fn is_probe_heuristic(
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

    pub fn update_tcp(
        &mut self,
        src_is_local: bool,
        packet: &OwnedParsedPacket,
        tcp: &TcpHeader,
        prober_helper: &mut ProberHelper,
    ) {
        let (state_opt, side) = if src_is_local {
            (&mut self.local_tcp_state, ConnectionSide::Local)
        } else {
            (&mut self.remote_tcp_state, ConnectionSide::Remote)
        };
        let state = state_opt.get_or_insert_with(|| {
            UnidirectionalTcpState::new(tcp.sequence_number, side, self.connection_key.clone())
        });
        state.process_pkt(packet, tcp);
        let pkt_seq_no = state.tcp_window().seq64(tcp.sequence_number);

        // Handle outgoind probes, if needed
        if src_is_local {
            if let Some(pkt_seq_no) = pkt_seq_no {
                self.tcp_process_local_probe(packet, pkt_seq_no, prober_helper);
            }
        }

        // A valid ACK packet. Do ACK processing on the state for the other side.
        if tcp.ack && !tcp.rst {
            let (other_state, other_side) = if src_is_local {
                (&mut self.remote_tcp_state, ConnectionSide::Remote)
            } else {
                (&mut self.local_tcp_state, ConnectionSide::Local)
            };
            let other_state = other_state.get_or_insert_with(|| {
                UnidirectionalTcpState::new(
                    tcp.acknowledgment_number,
                    other_side,
                    self.connection_key.clone(),
                )
            });
            // TODO: do we need to use `tcp_paylod_len` instead of `payload.is_empty()`??
            let is_dup_ack = other_state.process_rx_ack(packet.payload.is_empty(), tcp);

            // Dup-ack handling for possible probe replies
            if is_dup_ack {
                // The unwrap is safe. If `is_dup_ack` is true, than this segment's
                // ack_no is in window and it's equal to `other_state.recv_ack_no`
                let cur_pkt_ack = other_state.recv_ack_no().unwrap();
                debug_assert!(other_state.recv_ack_no().is_some()); // sanity check for myself that the above unwrap didn't move anything

                // TODO: we are re-extracting the SACK blocks from the packet (`process_rx_ack` already did it). Maybe
                // consider returning it from process_rx_ack to cut down the double processing.
                let sacks = other_state.extract_sacks(tcp);
                if !sacks.is_empty() {
                    // if there are more than 1 SACK block in the packet we assume it's not a probe response
                    let sack = sacks.first().unwrap();
                    // CRAZY: an out-of-sequence dupACK SHOULD contain a SACK option ala RFC2018, S4/page 5
                    // check whether the ACK sequence is ahead of the SACK range - that tells us it's a probe!
                    if sacks.len() == 1 && sack.right() <= cur_pkt_ack {
                        // this is a dupACK/probe reply! the right - left indicates the probe id
                        let probe_id = sack.bytes();
                        if let Some(active_probe_round) = self.probe_round.as_mut() {
                            if (active_probe_round.probe_pkt_seq_no == sack.left())
                                && (probe_id <= PROBE_MAX_TTL as u64)
                            {
                                // record the reply
                                let probe_id = probe_id as u8; // safe because we just checked
                                active_probe_round
                                    .incoming_reply_timestamps
                                    .entry(probe_id)
                                    .or_default()
                                    .insert(packet.clone());
                            } else {
                                debug!(
                                "Looks like we got a dupACK but it's not a probe response possible probe id: {} :: {:?}. Expected probe seq: {}, got SACK.LE: {}",
                                probe_id, packet, active_probe_round.probe_pkt_seq_no, sack.left()
                            );
                            }
                        }
                    }
                } else {
                    // Tested againstt all major stacks - everyone supports SACK so we
                    // don't need to handle the non-SACK case which can create noise
                    // the the code in place for now in case it's needed again (?)
                    //
                    // no SelectiveAck option, so asume this is a probe reply
                    // assume that inband ACK replies come from the highest TTL we sent
                    // and work backwards for each reply we received, e.g.,
                    // first reply is from TTL=max, second from TTL=max - 1, etc.
                    // this is a bit of a cheat as we really should try to match the
                    // reply to the actual outgoing probe that caused it, but there's not
                    // enough into the in ACK to infer the probe that caused it.  Working
                    // backwards adds some error to the RTT estimation, but it's on the
                    // order of the sent_time(probe_k) vs. sent_time(probe_n) which
                    // is extremely small (e.g., ~10 microseconds) because they are sent
                    // quickly back-to-back
                    /* if let Some(probe_id) = self.next_end_host_reply {
                        if let Some(replies) = self.incoming_reply_timestamps.get_mut(&probe_id)
                        {
                            replies.insert(packet.clone());
                        } else {
                            self.incoming_reply_timestamps
                                .insert(probe_id, HashSet::from([packet.clone()]));
                        }
                        // make sure the next probe goes in the next nearer TTL's slot
                        if probe_id > 1 {
                            self.next_end_host_reply = Some(probe_id - 1);
                        }
                    } else {
                        warn!("Looks like we got a inband ACK reply without next_end_host_reply set!? : {:?}", self);
                    } */
                }
            }
        }
    }

    /// For packets sent by the local side: do any processing for probes
    fn tcp_process_local_probe(
        &mut self,
        packet: &OwnedParsedPacket,
        pkt_seq_no: TcpSeq64,
        prober_helper: &mut ProberHelper,
    ) {
        // did we send some payload?
        if !packet.payload.is_empty() {
            let first_time = self.local_data.is_none();
            if first_time {
                debug!(
                    "Setting first_time local_data for connection {} (closing={}, probing={})",
                    self.connection_key,
                    self.close_has_started(),
                    self.probe_round.is_some(),
                );
            }
            self.local_data = Some(packet.clone());
            // this is the first time in the connection lifetime we sent some payload
            // spawn an inband probe
            if first_time && !self.close_has_started() {
                let dst_ip = packet.get_src_dst_ips().unwrap().1;
                if prober_helper.check_update_dst_ip(dst_ip) {
                    // reset the probe state
                    self.probe_round = Some(ProbeRound::new(
                        self.probe_report_summary.raw_reports.len(),
                        pkt_seq_no,
                    ));
                    // tcp_inband_probe(self.local_data.as_ref().unwrap(), raw_sock ).unwrap();
                    let min_ttl = prober_helper.get_min_ttl();
                    if let Err(e) =
                        prober_helper
                            .tx()
                            .try_send(PerfMsgCheck::new(ProbeMessage::SendProbe {
                                packet: packet.clone(),
                                min_ttl,
                            }))
                    {
                        warn!("Problem sending to prober queue: {}", e);
                    }
                }
            }
        }
        if let Some(active_probe_round) = self.probe_round.as_mut() {
            if active_probe_round.probe_pkt_seq_no == pkt_seq_no {
                if let Some(ttl) = Connection::is_probe_heuristic(true, packet) {
                    // there's some super clean rust-ish way to compress this; don't care for now
                    if let Some(probes) = active_probe_round.outgoing_probe_timestamps.get_mut(&ttl)
                    {
                        probes.insert(packet.clone());
                    } else {
                        let mut probes = HashSet::new();
                        probes.insert(packet.clone());
                        active_probe_round
                            .outgoing_probe_timestamps
                            .insert(ttl, probes);
                    }
                }
            } else {
                // warn! should be fine here. I think of a good reason why we should ever this case.
                warn!("Outgoing packet with low TTL. Looks like a probe but seq no mismatch: {} vs {}", 
                    active_probe_round.probe_pkt_seq_no, pkt_seq_no );
            }
        }
    }

    // Check if the connection has started to be closed. I.e., we've received either a syn or a fin
    // from either side.
    pub(crate) fn close_has_started(&self) -> bool {
        // without these temporary local vars, the auto fomratter produces some pretty ugly code, so
        // lets do it this was and keep things readable...
        let local_close_started = self
            .local_tcp_state
            .as_ref()
            .is_some_and(|s| *s.rst_seen() || s.fin_seq().is_some());
        let remote_close_started = self
            .remote_tcp_state
            .as_ref()
            .is_some_and(|s| *s.rst_seen() || s.fin_seq().is_some());
        local_close_started || remote_close_started
    }

    /// is this the final ACK of the threeway close?
    /// Three-way close is:
    /// 1) Alice send FIN for Alice_seq+1
    /// 2) Bob sends FIN for Bob_seq+1 and ACK for Alice_seq+1
    /// 3) Alice sends ACK (no FIN) for Bob_seq+1
    ///
    /// NOTE: rust allows us to compare two Option<u32>'s directly,
    /// but the way None compares to Some(u32) breaks my brain so this is more
    /// typing but IMHO clearer
    pub(crate) fn is_four_way_close_done_or_rst(&self) -> bool {
        match (
            self.remote_tcp_state.as_ref(),
            self.local_tcp_state.as_ref(),
        ) {
            (Some(remote_state), Some(local_state)) => {
                if *remote_state.rst_seen() || *local_state.rst_seen() {
                    return true;
                }
                // has everyone sent their FIN's? (e.g. are we at least at step 3?)
                if local_state.fin_seq().is_some()
                    && local_state.recv_ack_no().is_some()
                    && remote_state.fin_seq().is_some()
                    && remote_state.recv_ack_no().is_some()
                {
                    // if we are at step 3, has everyone ACK'd everyone's FIN's?
                    // if yes, mark as closed
                    remote_state.recv_ack_no() > remote_state.fin_seq()
                        && local_state.recv_ack_no() > local_state.fin_seq()
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn update_icmp6_remote(
        &mut self,
        packet: &OwnedParsedPacket,
        icmp6: &etherparse::Icmpv6Header,
    ) {
        match icmp6.icmp_type {
            etherparse::Icmpv6Type::Unknown { .. }
            | etherparse::Icmpv6Type::ParameterProblem(_)
            | etherparse::Icmpv6Type::EchoRequest(_)
            | etherparse::Icmpv6Type::EchoReply(_)
            | etherparse::Icmpv6Type::PacketTooBig { .. } => (),
            etherparse::Icmpv6Type::DestinationUnreachable(_)
            | etherparse::Icmpv6Type::TimeExceeded(_) => self.store_icmp_reply(packet),
        }
    }

    fn update_icmp4_remote(
        &mut self,
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
            | etherparse::Icmpv4Type::ParameterProblem(_) => self.store_icmp_reply(packet),
        }
    }

    fn store_icmp_reply(&mut self, packet: &OwnedParsedPacket) {
        // TODO figure out how to cache this from the connection_key() computation
        // if it's a perf problem - ignore for now
        // but right now we're creating this embedded packet twice!
        match OwnedParsedPacket::from_partial_embedded_ip_packet(
            &packet.payload,
            packet.timestamp,
            packet.len, // TODO: should we adjust the length here? But not clear to what w/o first parsing the pkt
        ) {
            Ok((pkt, _partial)) => {
                if let Some(probe_id) = self.is_reply_heuristic(&pkt) {
                    if let Some(active_probe_round) = self.probe_round.as_mut() {
                        if let Some(hash) = active_probe_round
                            .incoming_reply_timestamps
                            .get_mut(&probe_id)
                        {
                            hash.insert(pkt);
                        } else {
                            active_probe_round
                                .incoming_reply_timestamps
                                // careful to store the original packet and not the embedded one
                                .insert(probe_id, HashSet::from([packet.clone()]));
                        }
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

    /**
     * Call on a packet which is potentially a reply to a probe and if it is,
     * extract the probe ID;  this should be called on the embedded packet
     * of an ICMP TTL exceeded
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
                        // any icmp6 doesn't have ip6.total_len() so fake it
                        (
                            ip6.payload_length + ip6.header_len() as u16,
                            ip6.header_len() as u16,
                        )
                    }
                    None => {
                        warn!("No IP packet with a TCP packet!?");
                        return None;
                    }
                };
                // probe-Id = total_len - sizeof(iph) - sizeof(tcph)
                // but we don't have sizeof(tcph) here b/c it might be truncated
                // ASSUME Outgoing probes have no TCP options; so are exactly 20 bytes
                // which makes them look weird to an IDS and we lose precision
                let probe_id = total_len - iph_len - 20;

                if probe_id <= PROBE_MAX_TTL as u16 {
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
    pub(crate) fn generate_probe_report(
        &mut self,
        probe_round: u32,
        application_rtt: Option<f64>,
        should_probe_again: bool,
    ) -> ProbeRoundReport {
        debug!(
            "Generating probe report for {} (pending report = {})",
            self.connection_key,
            self.probe_round.is_some()
        );
        let mut report = HashMap::new();
        if let Some(probe_round) = self.probe_round.as_mut() {
            if probe_round.outgoing_probe_timestamps.len() > PROBE_MAX_TTL as usize {
                warn!(
                    "Extra probes {} in {:?}",
                    probe_round.outgoing_probe_timestamps.len(),
                    self.connection_key,
                );
            }
            if probe_round.incoming_reply_timestamps.len() > PROBE_MAX_TTL as usize {
                warn!(
                    "Extra replies {} in {:?}",
                    probe_round.incoming_reply_timestamps.len(),
                    self.connection_key,
                );
            }
            for ttl in 1..=PROBE_MAX_TTL {
                let mut comment = String::new(); // no comment by default
                if let Some(probe_set) = probe_round.outgoing_probe_timestamps.get(&ttl) {
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
                    let out_timestamp_ms = timestamp_to_ms(probe.timestamp);
                    if let Some(reply_set) = probe_round.incoming_reply_timestamps.get(&ttl) {
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
                        let rtt_ms = calc_rtt_ms(reply.timestamp, probe.timestamp);
                        if matches!(&reply.transport, Some(TransportHeader::Tcp(_tcph))) {
                            report.insert(
                                ttl,
                                ProbeReportEntry::EndHostReplyFound {
                                    ttl,
                                    out_timestamp_ms,
                                    rtt_ms,
                                    comment,
                                },
                            );
                        } else {
                            // else is an ICMP reply
                            // unwrap is ok here b/c we would have never stored a non-IP packet as a reply
                            let (src_ip, _dst_ip) = etherparse_ipheaders2ipaddr(&reply.ip).unwrap();
                            // NAT check - does the dst of the connection key == this src_ip?
                            if src_ip == self.connection_key.remote_ip {
                                report.insert(
                                    ttl,
                                    ProbeReportEntry::NatReplyFound {
                                        ttl,
                                        out_timestamp_ms,
                                        rtt_ms,
                                        src_ip,
                                        comment,
                                    },
                                );
                            } else {
                                report.insert(
                                    ttl,
                                    ProbeReportEntry::RouterReplyFound {
                                        ttl,
                                        out_timestamp_ms,
                                        rtt_ms,
                                        src_ip,
                                        comment,
                                    },
                                );
                            }
                        }
                    } else {
                        // missing reply - unfortunately common
                        report.insert(
                            ttl,
                            ProbeReportEntry::NoReply {
                                ttl,
                                out_timestamp_ms,
                                comment,
                            },
                        );
                    }
                } else {
                    // sigh, duplicate code
                    if let Some(reply_set) = probe_round.incoming_reply_timestamps.get(&ttl) {
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
                        let in_timestamp_ms = timestamp_to_ms(reply.timestamp);
                        if matches!(&reply.transport, Some(TransportHeader::Tcp(_tcp))) {
                            report.insert(
                                ttl,
                                ProbeReportEntry::EndHostNoProbe {
                                    ttl,
                                    in_timestamp_ms,
                                    comment,
                                },
                            );
                        } else {
                            // ICMP reply
                            let (src_ip, _dst_ip) = etherparse_ipheaders2ipaddr(&reply.ip).unwrap();
                            // NAT check - does the dst of the connection key == this src_ip?
                            if src_ip == self.connection_key.remote_ip {
                                report.insert(
                                    ttl,
                                    ProbeReportEntry::NatReplyNoProbe {
                                        ttl,
                                        in_timestamp_ms,
                                        src_ip,
                                        comment,
                                    },
                                );
                            } else {
                                report.insert(
                                    ttl,
                                    ProbeReportEntry::RouterReplyNoProbe {
                                        ttl,
                                        in_timestamp_ms,
                                        src_ip,
                                        comment,
                                    },
                                );
                            }
                        }
                    } else {
                        // missing both reply and probe - a bad day
                        report.insert(ttl, ProbeReportEntry::NoOutgoing { ttl, comment });
                    }
                }
            }
        }
        // whether or not we had valid probe data; reset the probe data if asked
        // this is important because we could have had a completely failed probe run but
        // still want to be able to start another.
        if should_probe_again {
            self.local_data = None;
        }
        // Always clear out the stored state to make sure that multiple calls to this function
        // don't create fake ProbeReports (or leak mem!)
        self.probe_round = None;
        let probe_report = ProbeRoundReport::new(report, probe_round, application_rtt);
        // one copy for us and one for the caller
        // the one for us will get logged to disk; the caller's will get sent to the remote client
        self.probe_report_summary.update(probe_report.clone());
        probe_report
    }

    fn update_udp(
        &self,
        key: &ConnectionKey,
        packet: &OwnedParsedPacket,
        udp: &UdpHeader,
        dns_tx: &Option<mpsc::UnboundedSender<DnsTrackerMessage>>,
        src_is_local: bool,
    ) {
        if (src_is_local && udp.destination_port == UDP_DNS_PORT)
            || (!src_is_local && udp.source_port == UDP_DNS_PORT)
        {
            // are we tracking DNS?
            if let Some(dns_tx) = dns_tx {
                if let Err(e) = dns_tx.send(DnsTrackerMessage::NewEntry {
                    key: key.clone(),
                    data: packet.payload.clone(),
                    timestamp: packet.timestamp,
                    src_is_local,
                }) {
                    warn!("Error sending to DNS Tracker: {}", e);
                }
            }
        } else {
            // Noop - don't do anything special for other UDP connections -yet
            // TODO: handle QUIC connections - there are a lot of them
            debug!("Ignoring untracked UDP connection: {}", key);
        }
    }

    /**
     * Convert a `struct Connection` which has a lot of operational state to
     * a `struct ConnectionMeasurements` which only has the measurement info
     * that we want to export
     */

    pub fn to_connection_measurements(
        &mut self,
        now: DateTime<Utc>,
        probe_timeout: Option<Duration>,
    ) -> libconntrack_wasm::ConnectionMeasurements {
        // if there's an active probe round going, finish it/generate the report if it's been longer
        // then probe_timeout
        if let Some(probe_round) = self.probe_round.as_ref() {
            let now_instant = tokio::time::Instant::now();
            // Use the monotonic clock not the system clock as it respects
            // tokio::time::pause() which is required for some tests, e.g.,
            // connection_tracker::test::test_time_wait_eviction()
            let delta = now_instant - self.start_tracking_time_instant;
            let timeout = match probe_timeout {
                Some(timeout) => timeout.to_std().unwrap(),
                None => Duration::milliseconds(500).to_std().unwrap(),
            };
            if delta > timeout {
                self.generate_probe_report(probe_round.round_number as u32, None, false);
            }
        }
        libconntrack_wasm::ConnectionMeasurements {
            tx_stats: self.traffic_stats.tx_stats_summary(now),
            rx_stats: self.traffic_stats.rx_stats_summary(now),
            local_hostname: Some("localhost".to_string()),
            key: self.connection_key.clone(),
            id: Some(ConnectionIdString::from(&self.connection_key)),
            remote_hostname: self.remote_hostname.clone(),
            probe_report_summary: self.probe_report_summary.clone(),
            user_annotation: self.user_annotation.clone(),
            user_agent: self.user_agent.clone(),
            associated_apps: self.associated_apps.clone(),
            start_tracking_time: self.start_tracking_time,
            last_packet_time: self.last_packet_time,
            close_has_started: self.close_has_started(),
            four_way_close_done: self.is_four_way_close_done_or_rst(),
        }
    }
}

#[cfg(test)]
pub mod test {
    use std::net::IpAddr;
    use std::str::FromStr;

    use super::*;

    use crate::in_band_probe::test::test_tcp_packet_ports;
    use crate::owned_packet::OwnedParsedPacket;
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

        let local_pkt = test_tcp_packet_ports(local_ip, remote_ip, 21, 12345);
        let (l_key, src_is_local) = local_pkt.to_connection_key(&local_addrs).unwrap();
        assert!(src_is_local);

        let remote_pkt = test_tcp_packet_ports(remote_ip, local_ip, 12345, 21);
        let (r_key, src_is_local) = remote_pkt.to_connection_key(&local_addrs).unwrap();
        assert!(!src_is_local);

        assert_eq!(l_key, r_key);

        let local_localhost_pkt = test_tcp_packet_ports(localhost_ip, localhost_ip, 3030, 12345);
        let (ll_key, src_is_local) = local_localhost_pkt.to_connection_key(&local_addrs).unwrap();
        assert!(src_is_local);

        let remote_localhost_pkt = test_tcp_packet_ports(localhost_ip, localhost_ip, 12345, 3030);
        let (rl_key, src_is_local) = remote_localhost_pkt
            .to_connection_key(&local_addrs)
            .unwrap();
        assert!(!src_is_local);

        assert_eq!(ll_key, rl_key);
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
     * Make sure a probe and the corresponding ICMPv4 reply map to the same
     * connection key and the src_is_local logic is correct for both
     *
     * TODO: add ICMPv6 version of this test
     */
    async fn icmp4_to_connection_key() {
        let mut local_addrs = HashSet::new();
        local_addrs.insert(IpAddr::from_str("172.31.2.61").unwrap());
        let probe = Box::new(OwnedParsedPacket::try_from_fake_time(TEST_PROBE.to_vec()).unwrap());

        let icmp_reply =
            Box::new(OwnedParsedPacket::try_from_fake_time(TEST_REPLY.to_vec()).unwrap());
        let (probe_key, src_is_local) = probe.to_connection_key(&local_addrs).unwrap();
        assert!(src_is_local);

        let (reply_key, src_is_local) = icmp_reply.to_connection_key(&local_addrs).unwrap();
        assert!(!src_is_local);

        assert_eq!(probe_key, reply_key);
    }

    #[test]
    fn options_cmp() {
        // it looks like you can compare inside options!?
        // some of the ack vs. seq comparisons assume this, so write a test just to make sure this
        // behavior doesn't change/go away
        //
        // https://doc.rust-lang.org/src/core/option.rs.html#560
        // apparently it's implemented by #[derive(Ord)] !?!
        let a = Some(10);
        let b = Some(20);
        let c: Option<i32> = None;

        assert!(a < b);
        assert!(b > a);
        assert!(a != c);
        assert!(a > c); // seems like None is less than everything!?
        assert!(b > c);
    }

    // as copied from the first few packets of 'aws-sjc-ist-one-stream.pcap'
    pub const TEST_1_LOCAL_SYN: [u8; 74] = [
        0xc8, 0x54, 0x4b, 0x43, 0xda, 0x3e, 0x98, 0x8d, 0x46, 0xc5, 0x03, 0x82, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x3c, 0xeb, 0x19, 0x40, 0x00, 0x40, 0x06, 0xbd, 0xf0, 0xc0, 0xa8, 0x01, 0x25,
        0x34, 0x35, 0x9b, 0xaf, 0x94, 0x62, 0x01, 0xbb, 0xd9, 0xe4, 0x72, 0xe2, 0x00, 0x00, 0x00,
        0x00, 0xa0, 0x02, 0xfa, 0xf0, 0x91, 0xe0, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02,
        0x08, 0x0a, 0x1a, 0xbf, 0x4f, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
    ];

    /**
     * Verify that we can extract the probe_id's from probes off of the wire correctly
     */
    #[tokio::test]
    async fn probe_id_off_by_one() {
        let ttl1_probe = [
            0x06, 0x50, 0x3e, 0xb8, 0xcf, 0xe9, 0x06, 0x95, 0x86, 0x20, 0x25, 0x41, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x29, 0x00, 0x00, 0x40, 0x00, 0x01, 0x06, 0x86, 0x69, 0xac, 0x1f,
            0x0a, 0xe8, 0x51, 0xd7, 0xea, 0x87, 0x01, 0xbb, 0x63, 0x7e, 0x0a, 0xf0, 0x8c, 0x3c,
            0x7d, 0x62, 0x09, 0xd2, 0x50, 0x18, 0x01, 0xfa, 0xee, 0xd0, 0x00, 0x00, 0x48,
        ];
        let probe1 = OwnedParsedPacket::try_from_fake_time(ttl1_probe.to_vec()).unwrap();

        let probe_id = Connection::is_probe_heuristic(true, &probe1).unwrap();
        assert_eq!(probe_id, 1);

        let ttl32_probe = [
            0x06, 0x50, 0x3e, 0xb8, 0xcf, 0xe9, 0x06, 0x95, 0x86, 0x20, 0x25, 0x41, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x48, 0x00, 0x00, 0x40, 0x00, 0x20, 0x06, 0x67, 0x4a, 0xac, 0x1f,
            0x0a, 0xe8, 0x51, 0xd7, 0xea, 0x87, 0x01, 0xbb, 0x63, 0x7e, 0x0a, 0xf0, 0x8c, 0x3c,
            0x7d, 0x62, 0x09, 0xd2, 0x50, 0x18, 0x01, 0xfa, 0xf7, 0xad, 0x00, 0x00, 0x48, 0x54,
            0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d,
            0x0a, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x3a,
            0x20, 0x74,
        ];
        let probe32 = OwnedParsedPacket::try_from_fake_time(ttl32_probe.to_vec()).unwrap();

        let probe_id = Connection::is_probe_heuristic(true, &probe32).unwrap();
        assert_eq!(probe_id, 32);
    }

    // Create a DateTime that's in the past. This should help uncover cases where our
    // logic uses Utc::now() directly instead of using packet timestamps
    fn mk_start_time() -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1699559714, 123456).unwrap() // 2023-11-10
    }

    fn dur_micros(dt_micros: i64) -> chrono::Duration {
        chrono::Duration::microseconds(dt_micros)
    }

    fn mk_packet(
        src_is_local: bool,
        timestamp: DateTime<Utc>,
        payload_len: usize,
    ) -> Box<OwnedParsedPacket> {
        let mut pkt_bytes: Vec<u8> = Vec::new();
        let local_mac = [1, 2, 3, 4, 5, 6];
        let remote_mac = [7, 8, 9, 10, 11, 12];
        let local_ip: [u8; 4] = [192, 168, 1, 1];
        let remote_ip: [u8; 4] = [192, 168, 1, 2];
        let local_port = 123;
        let remote_port = 443;
        let payload: Vec<u8> = vec![42u8; payload_len];

        if src_is_local {
            etherparse::PacketBuilder::ethernet2(local_mac, remote_mac)
                .ipv4(local_ip, remote_ip, 64)
                .udp(local_port, remote_port)
                .write(&mut pkt_bytes, &payload)
                .unwrap();
        } else {
            etherparse::PacketBuilder::ethernet2(remote_mac, local_mac)
                .ipv4(remote_ip, local_ip, 64)
                .udp(remote_port, local_port)
                .write(&mut pkt_bytes, &payload)
                .unwrap();
        }
        assert_eq!(pkt_bytes.len(), 14 + 20 + 8 + payload_len);
        let pkt_headers = etherparse::PacketHeaders::from_ethernet_slice(&pkt_bytes).unwrap();
        Box::new(OwnedParsedPacket::from_headers_and_ts(
            pkt_headers,
            timestamp,
            pkt_bytes.len() as u32,
        ))
    }

    /// Helper struct with all the stuff we need to call `Connection::update()`
    struct Helper {
        _prober_txrx: (
            mpsc::Sender<PerfMsgCheck<ProbeMessage>>,
            mpsc::Receiver<PerfMsgCheck<ProbeMessage>>,
        ),
        prober_helper: ProberHelper,
        pcap_to_wall_delay: StatHandleDuration,
        local_addrs: HashSet<IpAddr>,
    }

    impl Helper {
        fn new(local_addrs: HashSet<IpAddr>) -> Helper {
            use common_wasm::timeseries_stats::ExportedStatRegistry;
            use common_wasm::timeseries_stats::StatType;
            use common_wasm::timeseries_stats::Units;
            let mut registry = ExportedStatRegistry::new("testing", std::time::Instant::now());
            let prober_txrx = mpsc::channel(4096);
            let prober_tx = prober_txrx.0.clone();
            Helper {
                _prober_txrx: prober_txrx,
                prober_helper: ProberHelper::new(prober_tx, false),
                pcap_to_wall_delay: registry.add_duration_stat(
                    "pcap_to_wall_delay",
                    Units::Microseconds,
                    [StatType::AVG],
                ),
                local_addrs,
            }
        }

        fn update_conn(&mut self, conn: &mut Connection, pkt: Box<OwnedParsedPacket>) {
            let (key, src_is_local) = pkt.to_connection_key(&self.local_addrs).unwrap();
            conn.update(
                pkt,
                &mut self.prober_helper,
                &key,
                src_is_local,
                &None,
                self.pcap_to_wall_delay.clone(),
            )
        }
    }

    #[test]
    pub fn test_rate_calculation() {
        let local_addrs = HashSet::from([IpAddr::from_str("192.168.1.1").unwrap()]);
        let mut helper = Helper::new(local_addrs.clone());

        let start = mk_start_time();
        let pkt = mk_packet(true, start, 100);
        let (key, _) = pkt.to_connection_key(&local_addrs).unwrap();
        let mut conn = Connection::new(key, start);

        let conn_measurement = conn.to_connection_measurements(start, None);
        assert_eq!(conn_measurement.rx_stats.last_min_byte_rate, None);
        assert_eq!(conn_measurement.rx_stats.last_min_pkt_rate, None);
        assert_eq!(conn_measurement.tx_stats.last_min_byte_rate, None);
        assert_eq!(conn_measurement.tx_stats.last_min_pkt_rate, None);
        assert_eq!(conn_measurement.rx_stats.burst_byte_rate, None);
        assert_eq!(conn_measurement.rx_stats.burst_pkt_rate, None);
        assert_eq!(conn_measurement.tx_stats.burst_byte_rate, None);
        assert_eq!(conn_measurement.tx_stats.burst_pkt_rate, None);

        helper.update_conn(&mut conn, pkt);

        let mut t = start;
        for _ in 1..=15 {
            t += dur_micros(1000);
            let pkt = mk_packet(true, t, 100);
            helper.update_conn(&mut conn, pkt);
        }
        let conn_meas = conn.to_connection_measurements(t, None);
        // 16 packets, 142 bytes each over 15ms
        assert_eq!(
            conn_meas.tx_stats.last_min_byte_rate.unwrap(),
            16. * 142. / 0.015
        );
        // 16 packets over 15ms
        assert_eq!(conn_meas.tx_stats.last_min_pkt_rate.unwrap(), 16. / 0.015);
        assert_eq!(conn_meas.rx_stats.last_min_byte_rate, None);
        assert_eq!(conn_meas.rx_stats.last_min_pkt_rate, None);

        // One 142 byte packet per ms ==> 142KB/s
        assert_eq!(conn_meas.tx_stats.burst_byte_rate.unwrap(), 142e3);
        assert_eq!(conn_meas.tx_stats.burst_pkt_rate.unwrap(), 1000.);
        assert_eq!(conn_meas.rx_stats.burst_byte_rate, None);
        assert_eq!(conn_meas.rx_stats.burst_pkt_rate, None);

        //-----------
        // Lets receive some bytes too
        // 24 packets in 11.5 ms
        t = start + dur_micros(30_000);
        for _ in 1..=24 {
            t += dur_micros(500);
            let pkt = mk_packet(false, t, 200);
            helper.update_conn(&mut conn, pkt);
        }
        let conn_meas = conn.to_connection_measurements(t, None);

        // Average TX rate is unchanged since no more packets were received
        assert_eq!(
            conn_meas.tx_stats.last_min_byte_rate.unwrap(),
            16. * 142. / 0.015
        );
        assert_eq!(conn_meas.tx_stats.last_min_pkt_rate.unwrap(), 16. / 0.015);
        // 24 packets, 242 bytes each over 12.5ms
        assert_eq!(
            conn_meas.rx_stats.last_min_byte_rate.unwrap(),
            24. * 242. / 0.0115
        );
        assert_eq!(conn_meas.rx_stats.last_min_pkt_rate.unwrap(), 24. / 0.0115);

        // Burst TX rate is unchanged
        assert_eq!(conn_meas.tx_stats.burst_byte_rate.unwrap(), 142e3);
        assert_eq!(conn_meas.tx_stats.burst_pkt_rate.unwrap(), 1000.);
        // One 242 byte packet per 0.5ms ==> 484KB/s
        assert_eq!(conn_meas.rx_stats.burst_byte_rate.unwrap(), 484e3);
        assert_eq!(conn_meas.rx_stats.burst_pkt_rate.unwrap(), 2000.);
    }
}
