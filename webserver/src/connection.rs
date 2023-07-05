use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
};

use common::{ProbeReport, ProbeReportEntry, PROBE_MAX_TTL};
use etherparse::{IpHeader, TcpHeader, TcpOptionElement, TransportHeader};
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
    Pkt(OwnedParsedPacket), // send to the connection tracker to track
    ProbeReport {
        key: ConnectionKey,
        clear_state: bool,
        tx: tokio::sync::mpsc::Sender<ProbeReport>,
    },
    ProbeOnIdle {
        // launch a set of inband probes when the connection next goes idle
        // NOTE: idle is both remote_ack  == local_seq and a promise from the application not to send anymore data for a while
        key: ConnectionKey, // for this connection
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
    // TODO: change this to an LRUHashMap to avoid mem leaks!
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
                ProbeOnIdle { key } => {
                    self.set_probe_on_idle(key).await;
                }
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
            connection_key: key.clone(),
            local_syn: None,
            remote_syn: None,
            local_seq: None,
            local_ack: None,
            remote_ack: None,
            local_data: None,
            next_end_host_reply: None,
            outgoing_probe_timestamps: HashMap::new(),
            incoming_reply_timestamps: HashMap::new(),
            send_probes_on_idle: false,
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

    async fn set_probe_on_idle(&mut self, key: ConnectionKey) {
        if let Some(connection) = self.connections.get_mut(&key) {
            connection.probe_on_idle(&mut self.raw_sock).await;
        } else {
            warn!("Tried to set ProbeOnIdle for unknown connection {}", key);
        }
    }
}

type ProbeId = u8;
#[derive(Clone, Debug)]
pub struct Connection {
    pub connection_key: ConnectionKey,
    pub local_syn: Option<OwnedParsedPacket>,
    pub remote_syn: Option<OwnedParsedPacket>,
    pub local_seq: Option<u32>, // the most recent seq seen from local INCLUDING the TCP payload
    pub local_ack: Option<u32>,
    pub remote_ack: Option<u32>,
    pub local_data: Option<OwnedParsedPacket>, // data sent for retransmits
    pub next_end_host_reply: Option<ProbeId>,
    pub outgoing_probe_timestamps: HashMap<ProbeId, HashSet<OwnedParsedPacket>>,
    pub incoming_reply_timestamps: HashMap<ProbeId, HashSet<OwnedParsedPacket>>,
    pub send_probes_on_idle: bool, // should we send probes when the connection is idle?
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
                    self.update_tcp_remote(&packet, tcp, raw_sock);
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
            _ => warn!("Got Connection::update() for non-TCP/ICMPv4 packet - ignoring for now"),
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
        _context: &Context,
        packet: &OwnedParsedPacket,
        tcp: &TcpHeader,
        raw_sock: &mut R,
    ) where
        R: RawSocketWriter,
    {
        // NOTE: we can't just use packet.payload.len() b/c we might have a partial capture
        let payload_len = match &packet.ip {
            None => 0,
            Some(IpHeader::Version4(ip4, _)) => {
                ip4.total_len() - ip4.header_len() as u16 - tcp.header_len()
            }
            Some(IpHeader::Version6(ip6, _)) => {
                ip6.payload_length - ip6.header_len() as u16 - tcp.header_len()
            }
        };
        // every packet has a SEQ so just record the most recently one
        // we might thrash a bit if there's packet re-ordering but maybe that's OK?
        // currently this is only used for the self.is_idle_check()
        self.local_seq = Some(tcp.sequence_number + payload_len as u32);
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
            self.local_data = Some(packet.clone());
            if first_time {
                // reset the probe state
                self.next_end_host_reply = Some(PROBE_MAX_TTL - 1);
                tcp_inband_probe(self.local_data.as_ref().unwrap(), raw_sock).unwrap();
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
        // TODO: track FIN and RST to feedback to connectiontracker when it's time to delete this state!
    }

    fn update_tcp_remote<R: RawSocketWriter>(
        &mut self,
        packet: &OwnedParsedPacket,
        tcp: &TcpHeader,
        raw_sock: &mut R,
    ) {
        if tcp.syn {
            self.remote_syn = Some(packet.clone()); // memcpy() but doesn't happen that much or with much data
        }
        // record how far the remote side has acknowledged; check for old acks for outstanding probes
        if tcp.ack {
            // TODO: figure out if we need to implement Protection Against Wrapped Segments (PAWS) here
            // e.g., check to make sure that sequence space wraps are correctly handled
            // for now, wrapped segements show up as lost packets, so it's not the end of the world - I think
            // also make sure neither SYN or FIN are set as these can look like dupACKs if we're not careful
            if let Some(old_ack) = self.remote_ack {
                // Is this ACK a duplicate ACK?
                if old_ack == tcp.acknowledgment_number
                    && packet.payload.len() == 0
                    && !tcp.syn
                    && !tcp.fin
                {
                    if let Some(Ok(selective_ack)) = tcp.options_iterator().find(|opt| {
                        matches!(&opt, Ok(TcpOptionElement::SelectiveAcknowledgement(_, _)))
                    }) {
                        // CRAZY: an out-of-sequence dupACK SHOULD contain a SACK option ala RFC2018, S4/page 5
                        // check whether the ACK sequence is ahead of the SACK range - that tells us it's a probe!
                        if let TcpOptionElement::SelectiveAcknowledgement((left, right), acks) =
                            selective_ack
                        {
                            if acks[0].is_some() || right > tcp.acknowledgment_number {
                                // this is not a dupACK/probe reply but a legit indication of a lost packet
                                // TODO: use selective ack params to estimate packets lost
                            } else {
                                // this is a dupACK/probe reply! the right - left indicates the probe id
                                let probe_id = if right >= left {
                                    // PAWS check
                                    right - left + 1 // the +1 is due to the left includes the 'current' byte; TESTED!
                                } else {
                                    // SEQ wrapped!  (or maybe a malicious receiver?)
                                    (u32::MAX - left) + right + 1 // TODO: write a test for this, as we will panic if this goes negative
                                };
                                if probe_id <= PROBE_MAX_TTL as u32 {
                                    // record the reply
                                    let probe_id = probe_id as u8; // safe because we just checked
                                    if let Some(replies) =
                                        self.incoming_reply_timestamps.get_mut(&probe_id)
                                    {
                                        replies.insert(packet.clone());
                                    } else {
                                        self.incoming_reply_timestamps
                                            .insert(probe_id, HashSet::from([packet.clone()]));
                                    }
                                } else {
                                    info!("Looks like we got a dupACK but the probe_id is too big {} :: {:?}", probe_id, packet);
                                }
                            }
                        }
                    } else {
                        // TODO: test against all TCP stacks to see if this code path is needed
                        // or can be removed, e.g., does anyone not support SACK by default?
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
                        if let Some(probe_id) = self.next_end_host_reply {
                            if let Some(replies) = self.incoming_reply_timestamps.get_mut(&probe_id)
                            {
                                replies.insert(packet.clone());
                            } else {
                                self.incoming_reply_timestamps
                                    .insert(probe_id, HashSet::from([packet.clone()]));
                            }
                            // make sure the next probe goes in the next nearer TTL's slot
                            self.next_end_host_reply = Some(probe_id - 1);
                        } else {
                            warn!("Looks like we got a inband ACK reply without next_end_host_reply set!? : {:?}", self);
                        }
                    }
                }
            }
            // what ever the case, update the ack for next time
            // NOTE: this could be a NOOP in the dup ack case
            self.remote_ack = Some(tcp.acknowledgment_number);
            if self.idle_check() {
                // launch queued idle probes
                self.send_probes_on_idle = false;
                // unwrap is right as we should never send idle probes when self.local_data = None
                tcp_inband_probe(self.local_data.as_ref().unwrap(), raw_sock).unwrap_or_else(|e| {
                    warn!("tcp_inband_probe() returned :: {}", e);
                });
            }
        }
        // TODO: look for incoming selective acks (indicates packet loss)
        // TODO: track FIN and RST to feedback to connectiontracker when it's time to delete this state!
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
    async fn generate_probe_report(&mut self, clear: bool) -> ProbeReport {
        let mut report = Vec::new();
        if self.outgoing_probe_timestamps.len() > PROBE_MAX_TTL as usize {
            warn!(
                "Extra probes {} in {:?}",
                self.outgoing_probe_timestamps.len(),
                self
            );
        }
        if self.incoming_reply_timestamps.len() > PROBE_MAX_TTL as usize {
            warn!(
                "Extra replies {} in {:?}",
                self.incoming_reply_timestamps.len(),
                self
            );
        }
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
                    if matches!(&reply.transport, Some(TransportHeader::Tcp(_tcph))) {
                        report.push(ProbeReportEntry::EndHostReplyFound {
                            ttl,
                            out_timestamp_ms,
                            rtt_ms,
                            comment,
                        })
                    } else {
                        // else is an ICMP reply
                        // unwrap is ok here b/c we would have never stored a non-IP packet as a reply
                        let (src_ip, _dst_ip) = etherparse_ipheaders2ipaddr(&reply.ip).unwrap();
                        // NAT check - does the dst of the connection key == this src_ip?
                        if src_ip == self.connection_key.remote_ip {
                            report.push(ProbeReportEntry::NatReplyFound {
                                ttl,
                                out_timestamp_ms,
                                rtt_ms,
                                src_ip,
                                comment,
                            })
                        } else {
                            report.push(ProbeReportEntry::RouterReplyFound {
                                ttl,
                                out_timestamp_ms,
                                rtt_ms,
                                src_ip,
                                comment,
                            })
                        }
                    }
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
                    if matches!(&reply.transport, Some(TransportHeader::Tcp(_tcp))) {
                        report.push(ProbeReportEntry::EndHostNoProbe {
                            ttl,
                            in_timestamp_ms,
                            comment,
                        });
                    } else {
                        // ICMP reply
                        let (src_ip, _dst_ip) = etherparse_ipheaders2ipaddr(&reply.ip).unwrap();
                        // NAT check - does the dst of the connection key == this src_ip?
                        if src_ip == self.connection_key.remote_ip {
                            report.push(ProbeReportEntry::NatReplyNoProbe {
                                ttl,
                                in_timestamp_ms,
                                src_ip,
                                comment,
                            });
                        } else {
                            report.push(ProbeReportEntry::RouterReplyNoProbe {
                                ttl,
                                in_timestamp_ms,
                                src_ip,
                                comment,
                            });
                        }
                    }
                } else {
                    // missing both reply and probe - a bad day
                    report.push(ProbeReportEntry::NoOutgoing { ttl, comment });
                }
            }
        }
        if clear {
            self.clear_probe_data(true);
        }
        ProbeReport::new(report)
    }

    /**
     * If we're idle now, launch probes, else flag that we're looking for an outstanding ack
     */
    async fn probe_on_idle<R: RawSocketWriter>(&mut self, raw_sock: &mut R) {
        if self.local_seq.is_some() && self.remote_ack >= self.local_seq {
            // are we idle now?
            self.clear_probe_data(false);
            self.next_end_host_reply = Some(PROBE_MAX_TTL - 1);
            tcp_inband_probe(self.local_data.as_ref().unwrap(), raw_sock).unwrap();
        } else {
            self.send_probes_on_idle = true; // queue up that we want to send the probes
                                             // next time we're idle
        }
    }

    /**
     * Reset the state around a set of probes.  If we clear the local_data,
     * then we're saying "when you next get a valid data packet, launch a probe
     * again".  
     */

    fn clear_probe_data(&mut self, flush_local_data: bool) {
        // clear any old probe data
        self.incoming_reply_timestamps.clear();
        self.outgoing_probe_timestamps.clear();
        self.next_end_host_reply = Some(PROBE_MAX_TTL - 1);
        if flush_local_data {
            self.local_data = None;
        }
    }

    /**
     * Is the connection currently idle?
     *
     * Yes if:
     * 1) the application has said it's going to pause sending new data (e.g., send_probes_on_idle is set)
     * 2) If the remote has ACK'd everything we've sent so far
     */

    fn idle_check(&self) -> bool {
        // TODO: if we decide to use idle probes, may need to check the incoming direction as well, e.g.,
        // track and add self.local_ack == self.remote_seq
        self.send_probes_on_idle && self.remote_ack == self.local_seq
    }
}
#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;
    use std::path::Path;
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

    /**
     * Help tests find the testing directory - it's harder than it should be.
     *
     * If we invoke tests via 'cargo test', the base dir is netdebug/webserver
     * but if we start it from the vscode debug IDE, it's netdebug
     */

    pub fn test_dir(f: &str) -> String {
        use std::fs::metadata;
        if metadata(f).is_ok() {
            return f.to_string();
        }
        let p = Path::new("webserver").join(f);
        if metadata(&p).is_ok() {
            let p = p.into_os_string().to_str().unwrap().to_string();
            return p;
        } else {
            panic!("Couldn't find a test_dir for {}", f);
        }
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
            pcap::Capture::from_file(test_dir("tests/simple_websocket_cleartxt_out_probes.pcap"))
                .unwrap();
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
            16 as usize // NOTE: this should be the constant not PROBE_MAX_TTL because
                        // the ground truth is the packet capture, not the current const value
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
        let mut capture = pcap::Capture::from_file(test_dir(
            "tests/simple_websocket_cleartext_remote_probe_replies.pcap",
        ))
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
            16 as usize // this is hard coded by the pcap
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
    const TEST_1_LOCAL_SYN: [u8; 74] = [
        0xc8, 0x54, 0x4b, 0x43, 0xda, 0x3e, 0x98, 0x8d, 0x46, 0xc5, 0x03, 0x82, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x3c, 0xeb, 0x19, 0x40, 0x00, 0x40, 0x06, 0xbd, 0xf0, 0xc0, 0xa8, 0x01, 0x25,
        0x34, 0x35, 0x9b, 0xaf, 0x94, 0x62, 0x01, 0xbb, 0xd9, 0xe4, 0x72, 0xe2, 0x00, 0x00, 0x00,
        0x00, 0xa0, 0x02, 0xfa, 0xf0, 0x91, 0xe0, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02,
        0x08, 0x0a, 0x1a, 0xbf, 0x4f, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
    ];
    const TEST_1_REMOTE_SYNACK: [u8; 74] = [
        0x98, 0x8d, 0x46, 0xc5, 0x03, 0x82, 0xc8, 0x54, 0x4b, 0x43, 0xda, 0x3e, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x3c, 0x00, 0x00, 0x40, 0x00, 0x2c, 0x06, 0xbd, 0x0a, 0x34, 0x35, 0x9b, 0xaf,
        0xc0, 0xa8, 0x01, 0x25, 0x01, 0xbb, 0x94, 0x62, 0xa8, 0x48, 0xb3, 0x44, 0xd9, 0xe4, 0x72,
        0xe3, 0xa0, 0x12, 0xfe, 0x88, 0x0e, 0x7f, 0x00, 0x00, 0x02, 0x04, 0x05, 0xac, 0x04, 0x02,
        0x08, 0x0a, 0x29, 0xff, 0xd7, 0x00, 0x1a, 0xbf, 0x4f, 0x0c, 0x01, 0x03, 0x03, 0x07,
    ];
    const TEST_1_LOCAL_3WAY_ACK: [u8; 66] = [
        0xc8, 0x54, 0x4b, 0x43, 0xda, 0x3e, 0x98, 0x8d, 0x46, 0xc5, 0x03, 0x82, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x34, 0xeb, 0x1a, 0x40, 0x00, 0x40, 0x06, 0xbd, 0xf7, 0xc0, 0xa8, 0x01, 0x25,
        0x34, 0x35, 0x9b, 0xaf, 0x94, 0x62, 0x01, 0xbb, 0xd9, 0xe4, 0x72, 0xe3, 0xa8, 0x48, 0xb3,
        0x45, 0x80, 0x10, 0x01, 0xf6, 0x91, 0xd8, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x1a, 0xbf,
        0x4f, 0xd5, 0x29, 0xff, 0xd7, 0x00,
    ];
    const TEST_1_LOCAL_DATA: [u8; 588] = [
        0xc8, 0x54, 0x4b, 0x43, 0xda, 0x3e, 0x98, 0x8d, 0x46, 0xc5, 0x03, 0x82, 0x08, 0x00, 0x45,
        0x00, 0x02, 0x3e, 0xeb, 0x1b, 0x40, 0x00, 0x40, 0x06, 0xbb, 0xec, 0xc0, 0xa8, 0x01, 0x25,
        0x34, 0x35, 0x9b, 0xaf, 0x94, 0x62, 0x01, 0xbb, 0xd9, 0xe4, 0x72, 0xe3, 0xa8, 0x48, 0xb3,
        0x45, 0x80, 0x18, 0x01, 0xf6, 0x93, 0xe2, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x1a, 0xbf,
        0x4f, 0xd6, 0x29, 0xff, 0xd7, 0x00, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x77, 0x73, 0x20, 0x48,
        0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20,
        0x64, 0x65, 0x6d, 0x6f, 0x2e, 0x6e, 0x65, 0x74, 0x64, 0x65, 0x62, 0x75, 0x67, 0x2e, 0x63,
        0x6f, 0x6d, 0x3a, 0x34, 0x34, 0x33, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74,
        0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x55, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x0d, 0x0a, 0x50,
        0x72, 0x61, 0x67, 0x6d, 0x61, 0x3a, 0x20, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65,
        0x0d, 0x0a, 0x43, 0x61, 0x63, 0x68, 0x65, 0x2d, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
        0x3a, 0x20, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65, 0x0d, 0x0a, 0x55, 0x73, 0x65,
        0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x4d, 0x6f, 0x7a, 0x69, 0x6c, 0x6c,
        0x61, 0x2f, 0x35, 0x2e, 0x30, 0x20, 0x28, 0x58, 0x31, 0x31, 0x3b, 0x20, 0x4c, 0x69, 0x6e,
        0x75, 0x78, 0x20, 0x78, 0x38, 0x36, 0x5f, 0x36, 0x34, 0x29, 0x20, 0x41, 0x70, 0x70, 0x6c,
        0x65, 0x57, 0x65, 0x62, 0x4b, 0x69, 0x74, 0x2f, 0x35, 0x33, 0x37, 0x2e, 0x33, 0x36, 0x20,
        0x28, 0x4b, 0x48, 0x54, 0x4d, 0x4c, 0x2c, 0x20, 0x6c, 0x69, 0x6b, 0x65, 0x20, 0x47, 0x65,
        0x63, 0x6b, 0x6f, 0x29, 0x20, 0x43, 0x68, 0x72, 0x6f, 0x6d, 0x65, 0x2f, 0x31, 0x31, 0x34,
        0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x20, 0x53, 0x61, 0x66, 0x61, 0x72, 0x69, 0x2f, 0x35,
        0x33, 0x37, 0x2e, 0x33, 0x36, 0x0d, 0x0a, 0x55, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x3a,
        0x20, 0x77, 0x65, 0x62, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x0d, 0x0a, 0x4f, 0x72, 0x69,
        0x67, 0x69, 0x6e, 0x3a, 0x20, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x64, 0x65, 0x6d,
        0x6f, 0x2e, 0x6e, 0x65, 0x74, 0x64, 0x65, 0x62, 0x75, 0x67, 0x2e, 0x63, 0x6f, 0x6d, 0x3a,
        0x34, 0x34, 0x33, 0x0d, 0x0a, 0x53, 0x65, 0x63, 0x2d, 0x57, 0x65, 0x62, 0x53, 0x6f, 0x63,
        0x6b, 0x65, 0x74, 0x2d, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x31, 0x33,
        0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69,
        0x6e, 0x67, 0x3a, 0x20, 0x67, 0x7a, 0x69, 0x70, 0x2c, 0x20, 0x64, 0x65, 0x66, 0x6c, 0x61,
        0x74, 0x65, 0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x4c, 0x61, 0x6e, 0x67,
        0x75, 0x61, 0x67, 0x65, 0x3a, 0x20, 0x65, 0x6e, 0x2d, 0x55, 0x53, 0x2c, 0x65, 0x6e, 0x3b,
        0x71, 0x3d, 0x30, 0x2e, 0x39, 0x0d, 0x0a, 0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x3a, 0x20,
        0x44, 0x45, 0x4d, 0x4f, 0x5f, 0x43, 0x4f, 0x4f, 0x4b, 0x49, 0x45, 0x3d, 0x53, 0x55, 0x43,
        0x43, 0x45, 0x53, 0x53, 0x0d, 0x0a, 0x53, 0x65, 0x63, 0x2d, 0x57, 0x65, 0x62, 0x53, 0x6f,
        0x63, 0x6b, 0x65, 0x74, 0x2d, 0x4b, 0x65, 0x79, 0x3a, 0x20, 0x64, 0x42, 0x69, 0x64, 0x73,
        0x50, 0x58, 0x64, 0x64, 0x2b, 0x2f, 0x61, 0x6c, 0x77, 0x75, 0x38, 0x44, 0x33, 0x7a, 0x37,
        0x39, 0x77, 0x3d, 0x3d, 0x0d, 0x0a, 0x53, 0x65, 0x63, 0x2d, 0x57, 0x65, 0x62, 0x53, 0x6f,
        0x63, 0x6b, 0x65, 0x74, 0x2d, 0x45, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73,
        0x3a, 0x20, 0x70, 0x65, 0x72, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2d, 0x64, 0x65,
        0x66, 0x6c, 0x61, 0x74, 0x65, 0x3b, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x6d,
        0x61, 0x78, 0x5f, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x5f, 0x62, 0x69, 0x74, 0x73, 0x0d,
        0x0a, 0x0d, 0x0a,
    ];
    const TEST_1_REMOTE_ACK: [u8; 66] = [
        0x98, 0x8d, 0x46, 0xc5, 0x03, 0x82, 0xc8, 0x54, 0x4b, 0x43, 0xda, 0x3e, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x34, 0x6c, 0x45, 0x40, 0x00, 0x2c, 0x06, 0x50, 0xcd, 0x34, 0x35, 0x9b, 0xaf,
        0xc0, 0xa8, 0x01, 0x25, 0x01, 0xbb, 0x94, 0x62, 0xa8, 0x48, 0xb3, 0x45, 0xd9, 0xe4, 0x74,
        0xed, 0x80, 0x10, 0x01, 0xf9, 0x36, 0x36, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x29, 0xff,
        0xd7, 0xc9, 0x1a, 0xbf, 0x4f, 0xd6,
    ];

    /**
     * Verify that we can queue up a request to send probes when the connection is idle
     * that really only goes out once the connection goes idle
     *
     * NOTE: because this test manually triggers the idle probes, it ignores the
     * context.send_idle_probes flag
     */
    #[tokio::test]
    async fn probe_on_idle_queued() {
        let local_ip = Ipv4Addr::from_str("192.168.1.37").unwrap();
        let local_addrs = HashSet::from([IpAddr::from(local_ip)]);
        let local_tcp_ports = HashSet::from([443]);
        let raw_sock = MockRawSocketWriter::new();
        let context = make_test_context();

        context.write().await.local_tcp_listen_port = 443; // trace uses 443

        let syn = OwnedParsedPacket::try_from_fake_time(TEST_1_LOCAL_SYN.to_vec()).unwrap();
        let synack = OwnedParsedPacket::try_from_fake_time(TEST_1_REMOTE_SYNACK.to_vec()).unwrap();
        let threeway_ack =
            OwnedParsedPacket::try_from_fake_time(TEST_1_LOCAL_3WAY_ACK.to_vec()).unwrap();
        let local_data = OwnedParsedPacket::try_from_fake_time(TEST_1_LOCAL_DATA.to_vec()).unwrap();
        let remote_data_ack =
            OwnedParsedPacket::try_from_fake_time(TEST_1_REMOTE_ACK.to_vec()).unwrap();
        let dup_ack = remote_data_ack.clone();

        let (key, src_is_local) = syn
            .to_connection_key(&local_addrs, &local_tcp_ports)
            .unwrap();
        assert!(src_is_local); // not really important for this test, but still should be true
        for pkt in [&synack, &threeway_ack, &local_data, &remote_data_ack] {
            let (other_key, _src_is_local) = pkt
                .to_connection_key(&local_addrs, &local_tcp_ports)
                .unwrap();
            assert_eq!(key, other_key); // make sure all of the pkts map to the same key/connection
        }

        let mut connection_tracker =
            ConnectionTracker::new(context, local_addrs.clone(), raw_sock).await;

        connection_tracker.add(syn);
        connection_tracker.add(synack);
        connection_tracker.add(threeway_ack);

        // no data packet yet, so no probes
        assert_eq!(connection_tracker.raw_sock.captured.len(), 0);

        // add the data packet
        connection_tracker.add(local_data);
        assert_eq!(connection_tracker.connections.len(), 1); // sanity check
                                                             // should have lots of probes
        assert_eq!(
            connection_tracker.raw_sock.captured.len(),
            PROBE_MAX_TTL as usize
        );
        // reset the mock/forget the past probes
        connection_tracker.raw_sock.captured.clear();

        // schedule a 'probe on idle' -> shouldn't trigger yet as we have outstanding data/not idle
        connection_tracker.set_probe_on_idle(key.clone()).await;
        assert_eq!(connection_tracker.raw_sock.captured.len(), 0);

        // the process of adding this ACK should trigger the idle condition and send probes
        connection_tracker.add(remote_data_ack);
        assert_eq!(
            connection_tracker.raw_sock.captured.len(),
            PROBE_MAX_TTL as usize
        );

        // NOTE: if we wanted to, we could pull the packets out of the mock raw_socket and
        // feed them into the connection tracker so we test our EndHostReplyFound logic properly
        // ... consider for later, but not important enough to mark as TODO

        // now process the SAME remote_data_ack packet five times: this is what EndHost probe
        // replies look like and verify the resulting ProbeReport
        // captured them correctly
        //
        // NOTE: it seems a real duplicate ACK will have selective acknowlegements set which will
        // allow us to match the reply to the orignal probe; this test ACK doesn't have SACK
        for _ in 0..5 {
            connection_tracker.add(dup_ack.clone());
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        connection_tracker.generate_report(key, false, tx).await;
        let report = rx.recv().await.unwrap();

        // NOTE: because we didn't feed any outgoing probes into the connection_tracker, we will only get
        // ReplyNoProbe instead of ReplyFound
        let replies = report.report.iter().filter(|e| {
            matches!(
                e,
                ProbeReportEntry::EndHostNoProbe {
                    ttl: _,
                    in_timestamp_ms: _,
                    comment: _
                }
            )
        });
        assert_eq!(replies.count(), 5);
    }

    /**
     * Walk through a captured tcpdump of a single TCP stream, read all traffic
     * including the outgoing probes and incoming replies and make sure
     * that everything is read/processed correctly - including SACK from dup ACKs
     * to map replies back to probes
     */
    #[tokio::test]
    async fn full_probe_report() {
        let context = make_test_context();
        let raw_sock = MockRawSocketWriter::new();
        let local_addrs = HashSet::from([IpAddr::from_str("172.31.10.232").unwrap()]);
        let local_tcp_ports = HashSet::from([443]);
        let mut connection_tracker =
            ConnectionTracker::new(context, local_addrs.clone(), raw_sock).await;

        let mut connection_key: Option<ConnectionKey> = None;
        let mut capture = pcap::Capture::from_file(test_dir(
            "tests/aws-sfc-to-turkey-psh-dup-ack-sack-ones-stream.pcap",
        ))
        .unwrap();
        // take all of the packets in the capture and pipe them into the connection tracker
        while let Ok(pkt) = capture.next_packet() {
            let owned_pkt = OwnedParsedPacket::try_from(pkt).unwrap();
            let (key, _) = owned_pkt
                .to_connection_key(&local_addrs, &local_tcp_ports)
                .unwrap();
            // make sure every packet in trace maps to same connection key
            if let Some(prev_key) = connection_key {
                assert_eq!(prev_key, key);
            }
            connection_key = Some(key);
            connection_tracker.add(owned_pkt);
        }
        let connection_key = connection_key.unwrap();
        assert_eq!(connection_tracker.connections.len(), 1);
        let connection = connection_tracker
            .connections
            .get_mut(&connection_key)
            .unwrap();
        let report = connection.generate_probe_report(false).await;
        println!("{}", report); // useful for debugging

        // hand analysis via wireshark = which TTL's got which reply types?
        let no_replies = [1, 3, 5, 6, 9, 16, 18];
        let router_icmp_replies = [2, 4, 7, 8, 10, 11, 12, 13, 14, 15];
        let nat_icmp_replies = [17];
        let endhost_replies = [19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];

        // sanity check to make sure we didn't miss something
        let mut all_probes = no_replies.clone().to_vec();
        all_probes.append(&mut router_icmp_replies.clone().to_vec());
        all_probes.append(&mut nat_icmp_replies.clone().to_vec());
        all_probes.append(&mut endhost_replies.clone().to_vec());

        // make sure all probes are accounted for
        for probe_id in 1..=PROBE_MAX_TTL {
            assert!(all_probes
                .iter()
                .find(|x| **x == probe_id as usize)
                .is_some());
        }
        assert_eq!(report.report.len(), all_probes.len());
        // now check that probes are correctly catergorized
        for ttl in no_replies {
            assert!(matches!(
                report.report[ttl - 1],
                ProbeReportEntry::NoReply {
                    ttl: _,
                    out_timestamp_ms: _,
                    comment: _
                }
            ));
        }
        for ttl in router_icmp_replies {
            assert!(matches!(
                report.report[ttl - 1],
                ProbeReportEntry::RouterReplyFound {
                    ttl: _,
                    out_timestamp_ms: _,
                    rtt_ms: _,
                    src_ip: _,
                    comment: _
                }
            ));
        }
        for ttl in nat_icmp_replies {
            assert!(matches!(
                report.report[ttl - 1],
                ProbeReportEntry::NatReplyFound {
                    ttl: _,
                    out_timestamp_ms: _,
                    rtt_ms: _,
                    src_ip: _,
                    comment: _
                }
            ));
        }
        for ttl in endhost_replies {
            assert!(matches!(
                report.report[ttl - 1],
                ProbeReportEntry::EndHostReplyFound {
                    ttl: _,
                    out_timestamp_ms: _,
                    rtt_ms: _,
                    comment: _
                }
            ));
        }
    }
}
