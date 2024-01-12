use std::{collections::VecDeque, fmt::Display};

use chrono::{DateTime, Utc};
use derive_getters::Getters;
use etherparse::{IpHeader, TcpHeader, TcpOptionElement};
use libconntrack_wasm::ConnectionKey;
use log::{debug, warn};

use crate::{
    connection_tracker::ConnectionStatHandles, get_holes_from_sack,
    owned_packet::OwnedParsedPacket, remove_filled_holes, sort_and_merge_ranges, SeqRange,
    TcpSeq64, TcpWindow,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ConnectionSide {
    Local,
    Remote,
}

impl Display for ConnectionSide {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

const MAX_TIMESTAMP_HISTORY_LEN: usize = 64;
/// TODO: do something more intelligent. This is the alpha used to compute
/// the weighted RTT.
/// Note, that RFC6298 suggests using 1/8 for alpha.
/// RFC7323 (the one specifying timestamp option), Appendix G says alpha
/// should be scaled down by number of expected samples per RTT.
const RTT_DECAY_ALPHA: f64 = 0.1;

/// The state for one side of a TCP connections. We use a `TcpWindow` instance to track the current
/// window of allowed sequence numbers. Using `TcpWindow` we translate regular 32bit
/// sequence numbers and ack numbers into a 64bit space that won't wrap. So normaler operators
/// (+, -, <, ...) can be used on them w/o concern for wrapping
#[derive(Debug, Clone, Getters)]
pub struct UnidirectionalTcpState {
    connection_key: ConnectionKey,
    #[getter(skip)]
    stat_handles: ConnectionStatHandles,
    /// The SYN (if any) sent by this side
    syn_pkt: Option<OwnedParsedPacket>,
    tcp_window: TcpWindow,
    /// The first seq number we observed. Could be set by either seq or ack no.
    /// Might not truely by the initial_seq_no from the SYN (since we might not see a SYN)
    initial_seq_no: TcpSeq64,
    /// The highest seq no seen from this INCLUDING the TCP payload
    sent_seq_no: Option<TcpSeq64>,
    /// The highest cummulative ACK this side has *received* from the other side.
    /// So, if `recv_ack_no == sent_seq_no + 1` then there is no unacked data
    recv_ack_no: Option<TcpSeq64>,
    /// Have we seen a RST from this side?
    rst_seen: bool,
    /// If this side has sent a FIN segment, the seq no of the FIN
    fin_seq: Option<TcpSeq64>,
    /// The amount of lost bytes that have subsequently been ACKed. I.e., the other side first send SACKs
    /// related to these missing bytes, then received a retransmit, and then ACKed them.
    lost_bytes: u64,
    /// The total number of times we recorded packet loss events. I.e., we received a SACK that
    /// indicates packet loss. Note, that this might not correspond to the number of lost segments
    /// since multiple lost segments could be indicated in a single SACK.
    loss_events: u64,
    /// The list of current holes as computed from received SACKs. I.e., any hole between the highest
    /// ACK number received and any data indicated by SACK blocks. This Vec is sorted and the ranges
    /// are overlap free. Furthermore, when we advance `recv_ack_no` we remove any holes that have
    /// been 'closed'.
    holes: Vec<SeqRange>,
    /// A history of recent TCP timestamps observed in packets sent by this side. I.e.,
    /// the `tsval` fields. When ACK's are received and processes, entries are dropped
    /// from this history.
    timestamp_history: VecDeque<TimestampObservation>,
    /// A hack for now: The RTT estimate for segments sent by this side.
    /// Note that we expect that the RTT for segments sent the Local side to
    /// be the actual RTT through the network, while the measured RTT for segments
    /// sent by the Remote side should be <<1ms (since it's just processing on the
    /// local machine).
    /// TODO: do something more intelligent, track variance, etc.  
    /// Also, should probably aggregate per destination host??
    rtt_estimate_ms: f64,
    side: ConnectionSide,
}

/// Returned by `UnidrectionalTcpState::process_rx_ack()`. Inidcates if the processed
/// ACK was a duplicate ACK and if the ACK inidcated that any data was apparently lost
/// (via SACK blocks)
#[derive(Debug, Clone, Default, Copy, Eq, PartialEq)]
pub struct ProcessRxAckReturn {
    pub is_dup_ack: bool,
    pub new_lost_bytes: u64,
    /// If Some(rtt), it represents the most recent RTT measurements
    /// (for packets sent by this side to the corresponding ACKs).
    /// Based on TCP timestamp tracking
    pub rtt_sample: Option<chrono::Duration>,
}

impl UnidirectionalTcpState {
    pub fn new(
        raw_seq_or_ack: u32,
        side: ConnectionSide,
        connection_key: ConnectionKey,
        stat_handles: ConnectionStatHandles,
    ) -> Self {
        let window = TcpWindow::new(raw_seq_or_ack);
        let initial_seq_no = window.seq64(raw_seq_or_ack).unwrap(); // save becase seq is in window
        Self {
            connection_key,
            stat_handles,
            syn_pkt: None,
            tcp_window: window,
            initial_seq_no,
            sent_seq_no: None,
            recv_ack_no: None,
            rst_seen: false,
            fin_seq: None,
            lost_bytes: 0,
            loss_events: 0,
            holes: Vec::new(),
            timestamp_history: VecDeque::with_capacity(MAX_TIMESTAMP_HISTORY_LEN),
            rtt_estimate_ms: 0.0,
            side,
        }
    }

    /// Process a packet sent by this side
    pub fn process_pkt(&mut self, packet: &OwnedParsedPacket, tcp: &TcpHeader) {
        if tcp.rst {
            self.rst_seen = true;
            // TODO: I think the right thing is stop processing further. Any seq number in a
            // RST segment should probably be ignored ....
            return;
        }

        let cur_pkt_seq = match self.tcp_window.seq64_and_update(tcp.sequence_number) {
            Some(seq) => seq,
            None => {
                self.stat_handles.seq_out_of_window.bump();
                warn!(
                    "{}:{} seq number is out-of-window -- not processing packet further",
                    self.connection_key, self.side
                );
                return;
            }
        };
        let payload_len = tcp_payload_len(packet, tcp) as u64;
        if let Some((tsval, _tsecr)) = extract_tcp_timestamp(tcp) {
            let observation = TimestampObservation {
                pkt_time: packet.timestamp,
                tsval,
            };
            if self.timestamp_history.is_empty() {
                self.timestamp_history.push_back(observation);
            } else if self.timestamp_history.len() < MAX_TIMESTAMP_HISTORY_LEN {
                // Note, we choose to not add more timestamp history entries rather then evicting
                // old ones. We expect to get an ACK at least for every other packet (and thus)
                // timestamp. So we expect to still get tsecr's for at least half of the
                // entries in the history. If we evict the oldest entries and we
                // have more than MAX_TIMESTAMP_HISTORY_LEN packets in flight we might
                // never be able to match a response up with an outgoing timestamp.
                let prev = self.timestamp_history.back().unwrap();
                if prev.tsval.lt(observation.tsval) {
                    // If this timestamp is strictly larger then the previously
                    // observed one, record it. Otherwise ignore.
                    // Note, for many connections we see several packets with the
                    // same tsval, since e.g., on MacOs the timestamp clock has 1ms
                    // resolution.
                    self.timestamp_history.push_back(observation);
                }
            }
        }
        // None < Some(x) for every x, so this nicely does the right thing :-)
        self.sent_seq_no = self.sent_seq_no.max(Some(cur_pkt_seq + payload_len));
        if tcp.syn {
            if self.syn_pkt.is_some() {
                self.stat_handles.multiple_syns.bump();
                debug!(
                    "{}: {}: Multiple SYNs on the same connection. Likely retransmit",
                    self.connection_key, self.side,
                );
            }
            self.syn_pkt = Some(packet.clone()); // memcpy() but doesn't happen that much or with much data
        }
        if tcp.fin {
            // FIN's "use" a sequence number as if they sent a byte of data
            if let Some(fin_seq) = self.fin_seq {
                if fin_seq != cur_pkt_seq + payload_len {
                    self.stat_handles.multiple_fins_different_seqno.bump();
                    warn!(
                        "{}: {}: Weird: got multiple FIN seqnos: {} != {}",
                        self.connection_key,
                        self.side,
                        fin_seq,
                        cur_pkt_seq + payload_len
                    );
                }
                // else it's just a duplicate packet
            }
            self.fin_seq = Some(cur_pkt_seq + payload_len);
        }
    }

    /// Process an ACK segment sent by the other side. I.e., process anything the other
    /// side has ACK'ed
    pub fn process_rx_ack(
        &mut self,
        pkt_time: DateTime<Utc>,
        pkt_payload_empty: bool,
        tcp: &TcpHeader,
    ) -> ProcessRxAckReturn {
        assert!(tcp.ack);
        assert!(!tcp.rst);
        let cur_pkt_ack = match self.tcp_window.seq64_and_update(tcp.acknowledgment_number) {
            Some(ack) => ack,
            None => {
                self.stat_handles.ack_out_of_window.bump();
                warn!(
                    "{}:{} ack number is out-of-window -- not processing packet further",
                    self.connection_key, self.side
                );
                return ProcessRxAckReturn::default();
            }
        };
        let (is_dup_ack, acks_new_data) = match self.recv_ack_no {
            // Is this ACK a duplicate ACK?
            Some(old_ack) => {
                let dup_ack =
                    old_ack == cur_pkt_ack && pkt_payload_empty && !tcp.syn && !tcp.fin && !tcp.rst;
                let acks_new_data = cur_pkt_ack > old_ack;
                (dup_ack, acks_new_data)
            }
            None => (false, true),
        };

        // RTT calculation
        // Per RFC7323, Section 4.1, we can only use echoed timestamps if they are in packets
        // that ACK new data.
        let mut rtt = None;
        if acks_new_data {
            if let Some((_tsval, tsecr)) = extract_tcp_timestamp(tcp) {
                while let Some(observation) = self.timestamp_history.front() {
                    if observation.tsval.lt(tsecr) {
                        self.timestamp_history.pop_front();
                    } else if observation.tsval == tsecr {
                        let dt = pkt_time - observation.pkt_time;
                        if dt > chrono::Duration::zero() {
                            rtt = Some(dt);
                        }
                        self.timestamp_history.pop_front();
                        break;
                    } else {
                        // TODO: we remove a tsval from the history the first time we
                        // see a matching ACK. However, in busy connections we are likely to
                        // see several segments with the same timestamps. So we have a flight
                        // of packets with the same tsval (and we'll get several tsecr's with
                        // that value back). We could use this to compute latency variance inside
                        // flight of packets.
                        break;
                    }
                }
                if let Some(rtt) = rtt {
                    let rtt_ms = rtt.num_nanoseconds().unwrap() as f64 / 1e6;
                    if self.rtt_estimate_ms == 0.0 {
                        self.rtt_estimate_ms = rtt_ms;
                    } else {
                        self.rtt_estimate_ms = (1. - RTT_DECAY_ALPHA) * self.rtt_estimate_ms
                            + RTT_DECAY_ALPHA * rtt_ms;
                    }
                }
            }
        }

        // None < Some(x) for every x, so this nicely does the right thing :-)
        self.recv_ack_no = self.recv_ack_no.max(Some(cur_pkt_ack));
        // TOOD: should we use the highest ACK number received so far or the ACK number from the current
        // packet. In theory both should be the same unless there is some weird re-ordering going on. But
        // I think the highest received ACK number makes the most sense....
        let holes = get_holes_from_sack(self.recv_ack_no.unwrap(), self.extract_sacks(tcp));
        // NOTE(1): in theory the following can happen: we get (assume recv_ack_no == 0)
        //   1st segment: SACK(10, 20), SACK(30,40) --> we have holes 0--10, and 20--30
        //   2nd segment: SACK(10,20), SACK(50-60), i.e., the SACK(30,40) is not send anymore. in this
        //                case our update logic would treat this as a hole from 20 -- 50 and consider 30,40
        //                lost.
        // NOTE(2) `holes.extend() + sort_and_merge_ranges()` can only *increase* the amount of bytes in holes.
        // E.g., consider the case that we have SACK(10,20) and SACK(30,40). We have a hole
        // from (20--30). Next we receive another pkt with SACK(10,20), SACK(22,26), SACK(30,40).
        // However, `self.holes` will still be `20--30` since that was the size of the largest hole covering
        // that seq numer space.
        let prev_bytes_in_holes = self.bytes_in_holes();
        self.holes.extend(holes);
        self.holes = sort_and_merge_ranges(std::mem::take(&mut self.holes));
        let new_bytes_in_holes = self.bytes_in_holes();

        let new_lost_bytes = new_bytes_in_holes - prev_bytes_in_holes;
        self.lost_bytes += new_lost_bytes;
        if new_lost_bytes > 0 {
            self.stat_handles.packet_loss_event.bump();
            self.loss_events += 1;
            debug!(
                "Presumably packet loss: {}:{} at ACK {}",
                self.connection_key,
                self.side,
                cur_pkt_ack - self.initial_seq_no,
            );
        }
        // Note the order of operations. We remove filled holes first and only afterwards
        // (in the next call) will we `prev_bytes_in_holes`
        remove_filled_holes(self.recv_ack_no.unwrap(), &mut self.holes);

        ProcessRxAckReturn {
            is_dup_ack,
            new_lost_bytes,
            rtt_sample: rtt,
        }
    }

    // Return the number of bytes in holes
    fn bytes_in_holes(&self) -> u64 {
        self.holes.iter().fold(0, |acc, h| acc + h.bytes())
    }

    /// Helper, convert a raw sack block (tuple of u32 -- as we'd get it from a packet header) into
    /// 64bit seq numbers and if the SACK is valid (in the window and left < right), push it into the
    /// vector.
    pub fn push_raw_sack_as_range(&self, sacks: &mut Vec<SeqRange>, raw_sack: (u32, u32)) {
        if let Some(seq_range) = SeqRange::try_from_seq(&self.tcp_window, raw_sack) {
            sacks.push(seq_range);
        } else {
            self.stat_handles.invalid_sack.bump();
            warn!(
                "Invalid SACK {}: seq state: {:?}, sack block: {:?}",
                self.connection_key, self.tcp_window, raw_sack
            );
        }
    }

    /// Take a TCP header and current TcpSeqState and extract any SACK blocks from the
    /// header. Invalid SACK blocks (out of window, right >= left) are discarded. The
    /// returned SACK blocks are in 64bit seq space but are neither sorted nor merged.
    pub fn extract_sacks(&self, tcph: &TcpHeader) -> Vec<SeqRange> {
        assert!(tcph.ack);
        assert!(!tcph.rst);
        let sacks_opt: Option<Vec<SeqRange>> = tcph.options_iterator().find_map(|opt| {
            if let Ok(TcpOptionElement::SelectiveAcknowledgement(first_sack, other_sacks)) = opt {
                let mut ret = Vec::new();
                self.push_raw_sack_as_range(&mut ret, first_sack);
                other_sacks
                    .into_iter()
                    .flatten()
                    .for_each(|s| self.push_raw_sack_as_range(&mut ret, s));
                Some(ret)
            } else {
                None
            }
        });
        sacks_opt.unwrap_or_default()
    }
}

pub fn extract_tcp_timestamp(tcph: &TcpHeader) -> Option<(TcpTimestamp, TcpTimestamp)> {
    tcph.options_iterator().find_map(|opt| {
        if let Ok(TcpOptionElement::Timestamp(tsval, tsecr)) = opt {
            Some((TcpTimestamp(tsval), TcpTimestamp(tsecr)))
        } else {
            None
        }
    })
}

pub fn tcp_payload_len(packet: &OwnedParsedPacket, tcp: &TcpHeader) -> u16 {
    // NOTE: we can't just use packet.payload.len() b/c we might have a partial capture
    match &packet.ip {
        None => 0,
        Some(IpHeader::Version4(ip4, _)) => {
            match ip4
                .total_len()
                .checked_sub(ip4.header_len() as u16 + tcp.header_len())
            {
                Some(x) => x,
                None => {
                    warn!(
                                "Malformed TCP packet with ip4.payload ({}) < ip4.header_len({}) + tcp.header_len ({}) :: {:?}",
                                ip4.total_len(),
                                ip4.header_len(),
                                tcp.header_len(),
                                &packet
                        );
                    0
                }
            }
        }
        Some(IpHeader::Version6(ip6, _)) => {
            match ip6.payload_length.checked_sub(tcp.header_len()) {
                Some(x) => x,
                None => {
                    warn!(
                        "Malformed TCP packet with ip6.payload ({}) < tcp.header_len ({}) :: {:?}",
                        ip6.payload_length,
                        tcp.header_len(),
                        &packet
                    );
                    0
                }
            }
        }
    }
}

/// Represents a TCP timestampd and implements a less-than comparision
/// that takes wrapping into account. We don't implement `Ord` because this
/// comparision is not transitive.
/// Note, we could a separate `TcpWindow` instance to translate timestamps
/// into a 64-bit space like we do for sequence numbers, but I don't think that's
/// necessary
#[derive(Debug, Clone, Default, Copy, Eq, PartialEq, Hash)]
pub struct TcpTimestamp(u32);

impl TcpTimestamp {
    /// return true if self if less than other
    /// cf. https://datatracker.ietf.org/doc/html/rfc7323, Section 5.2
    pub fn lt(&self, other: TcpTimestamp) -> bool {
        let delta = other.0.wrapping_sub(self.0);
        0 < delta && delta < (1 << 31)
    }
}

impl Display for TcpTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.to_string())
    }
}

/// Tracks observed TcpTimestamps (as seen in tsval) and the packet
/// time when that TcpTimestamp was observed.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct TimestampObservation {
    pkt_time: DateTime<Utc>,
    tsval: TcpTimestamp,
}

#[cfg(test)]
mod test {
    use std::{collections::HashSet, net::IpAddr, str::FromStr};

    use approx::assert_relative_eq;
    use common::test_utils::test_dir;
    use common_wasm::timeseries_stats::{CounterProvider, ExportedStatRegistry};
    use libconntrack_wasm::IpProtocol;

    use super::*;

    fn mk_mock_connection_key() -> ConnectionKey {
        ConnectionKey {
            local_ip: IpAddr::from_str("1.2.3.4").unwrap(),
            remote_ip: IpAddr::from_str("5.6.7.8").unwrap(),
            local_l4_port: 42,
            remote_l4_port: 80,
            ip_proto: IpProtocol::TCP,
        }
    }

    fn mk_stat_handles() -> ConnectionStatHandles {
        let registry = ExportedStatRegistry::new("testing", std::time::Instant::now());
        ConnectionStatHandles::new(&registry)
    }

    #[test]
    fn test_push_raw_sacks_as_range() {
        let center = 0x8000_0000u32;
        let center64 = center as TcpSeq64;
        let state = UnidirectionalTcpState::new(
            center,
            ConnectionSide::Local,
            mk_mock_connection_key(),
            mk_stat_handles(),
        );
        let mut sacks = Vec::new();

        // outside the window ==> don't push
        state.push_raw_sack_as_range(&mut sacks, (0, 1));
        assert_eq!(sacks, &[]);

        // left  > right ==> don't push
        state.push_raw_sack_as_range(&mut sacks, (center + 10, center));
        assert_eq!(sacks, &[]);

        state.push_raw_sack_as_range(&mut sacks, (center, center + 10));
        assert_eq!(
            sacks,
            &[SeqRange::try_from_seq64((center64, center64 + 10)).unwrap()]
        );
        state.push_raw_sack_as_range(&mut sacks, (center + 20, center + 30));
        assert_eq!(
            sacks,
            &[
                SeqRange::try_from_seq64((center64, center64 + 10)).unwrap(),
                SeqRange::try_from_seq64((center64 + 20, center64 + 30)).unwrap()
            ]
        );
    }

    #[test]
    fn test_extract_sacks() {
        fn mkrange(left: TcpSeq64, right: TcpSeq64) -> SeqRange {
            SeqRange::try_from_seq64((left, right)).unwrap()
        }
        let initial_ack = 2_000_000_000;
        let initial_ack64 = initial_ack as TcpSeq64;
        let state = UnidirectionalTcpState::new(
            initial_ack,
            ConnectionSide::Local,
            mk_mock_connection_key(),
            mk_stat_handles(),
        );
        let mut tcph = TcpHeader::new(34333, 80, 123, 65535);
        tcph.ack = true;
        tcph.acknowledgment_number = initial_ack;

        assert_eq!(state.extract_sacks(&tcph), Vec::new());

        // single sack block
        tcph.set_options(&[TcpOptionElement::SelectiveAcknowledgement(
            (initial_ack + 10, initial_ack + 20),
            [None, None, None],
        )])
        .unwrap();
        assert_eq!(
            state.extract_sacks(&tcph),
            vec![mkrange(initial_ack64 + 10, initial_ack64 + 20)]
        );

        // multiple sack blocks
        tcph.set_options(&[TcpOptionElement::SelectiveAcknowledgement(
            (initial_ack + 10, initial_ack + 20),
            [Some((initial_ack + 30, initial_ack + 40)), None, None],
        )])
        .unwrap();
        assert_eq!(
            state.extract_sacks(&tcph),
            vec![
                mkrange(initial_ack64 + 10, initial_ack64 + 20),
                mkrange(initial_ack64 + 30, initial_ack64 + 40)
            ]
        );

        // multiple sack blocks, first sack block has invalid range
        tcph.set_options(&[TcpOptionElement::SelectiveAcknowledgement(
            (initial_ack + 20, initial_ack + 10),
            [Some((initial_ack + 30, initial_ack + 40)), None, None],
        )])
        .unwrap();
        assert_eq!(
            state.extract_sacks(&tcph),
            vec![mkrange(initial_ack64 + 30, initial_ack64 + 40)]
        );

        // multiple sack blocks, second block with invalid range
        tcph.set_options(&[TcpOptionElement::SelectiveAcknowledgement(
            (initial_ack + 10, initial_ack + 20),
            [
                Some((initial_ack + 40, initial_ack + 30)),
                Some((initial_ack + 50, initial_ack + 60)),
                None,
            ],
        )])
        .unwrap();
        assert_eq!(
            state.extract_sacks(&tcph),
            vec![
                mkrange(initial_ack64 + 10, initial_ack64 + 20),
                mkrange(initial_ack64 + 50, initial_ack64 + 60)
            ]
        );
    }

    #[test]
    fn test_ack_processing_1() {
        fn mkrange(left: TcpSeq64, right: TcpSeq64) -> SeqRange {
            SeqRange::try_from_seq64((left, right)).unwrap()
        }
        let pkt_time = DateTime::<Utc>::UNIX_EPOCH; // any time will do
        let initial_ack = 2_000_000_000;
        let initial_ack64 = initial_ack as TcpSeq64;
        let mut state = UnidirectionalTcpState::new(
            initial_ack,
            ConnectionSide::Local,
            mk_mock_connection_key(),
            mk_stat_handles(),
        );
        let mut tcph = TcpHeader::new(34333, 80, initial_ack - 1, 65535);
        tcph.ack = true;
        tcph.acknowledgment_number = initial_ack;

        // check dup ack logic
        assert_eq!(
            state.process_rx_ack(pkt_time, false, &tcph),
            ProcessRxAckReturn {
                is_dup_ack: false,
                ..Default::default()
            }
        );
        assert_eq!(
            state.process_rx_ack(pkt_time, true, &tcph),
            ProcessRxAckReturn {
                is_dup_ack: true,
                ..Default::default()
            }
        );
        assert_eq!(
            state.process_rx_ack(pkt_time, false, &tcph),
            ProcessRxAckReturn {
                is_dup_ack: false,
                ..Default::default()
            }
        );
        tcph.fin = true;
        assert_eq!(
            state.process_rx_ack(pkt_time, true, &tcph),
            ProcessRxAckReturn {
                is_dup_ack: false,
                ..Default::default()
            }
        );
        tcph.fin = false;

        tcph.set_options(&[TcpOptionElement::SelectiveAcknowledgement(
            (initial_ack + 10, initial_ack + 20),
            [Some((initial_ack + 40, initial_ack + 50)), None, None],
        )])
        .unwrap();

        assert_eq!(
            state.process_rx_ack(pkt_time, true, &tcph),
            ProcessRxAckReturn {
                is_dup_ack: true,
                new_lost_bytes: 30,
                ..Default::default()
            }
        );
        assert_eq!(
            state.holes,
            vec![
                mkrange(initial_ack64, initial_ack64 + 10),
                mkrange(initial_ack64 + 20, initial_ack64 + 40)
            ]
        );
        assert_eq!(state.lost_bytes, 30);
        assert_eq!(state.loss_events, 1);

        tcph.set_options(&[]).unwrap();

        // ACK more data, partially fill hole
        tcph.acknowledgment_number = initial_ack + 5;
        assert_eq!(
            state.process_rx_ack(pkt_time, true, &tcph),
            ProcessRxAckReturn {
                is_dup_ack: false,
                new_lost_bytes: 0,
                ..Default::default()
            }
        );
        assert_eq!(
            state.holes,
            vec![
                mkrange(initial_ack64 + 5, initial_ack64 + 10),
                mkrange(initial_ack64 + 20, initial_ack64 + 40)
            ]
        );
        assert_eq!(state.lost_bytes, 30);
        assert_eq!(state.loss_events, 1);

        // Send the SACK again. Nothing should happen
        tcph.set_options(&[TcpOptionElement::SelectiveAcknowledgement(
            (initial_ack + 10, initial_ack + 20),
            [Some((initial_ack + 40, initial_ack + 50)), None, None],
        )])
        .unwrap();
        assert_eq!(
            state.process_rx_ack(pkt_time, true, &tcph),
            ProcessRxAckReturn {
                is_dup_ack: true,
                new_lost_bytes: 0,
                ..Default::default()
            }
        );
        assert_eq!(
            state.holes,
            vec![
                mkrange(initial_ack64 + 5, initial_ack64 + 10),
                mkrange(initial_ack64 + 20, initial_ack64 + 40)
            ]
        );
        assert_eq!(state.lost_bytes, 30);
        assert_eq!(state.loss_events, 1);
        tcph.set_options(&[]).unwrap();

        // ACK more data, completely fill first hole
        tcph.acknowledgment_number = initial_ack + 20;
        assert_eq!(
            state.process_rx_ack(pkt_time, true, &tcph),
            ProcessRxAckReturn {
                is_dup_ack: false,
                new_lost_bytes: 0,
                ..Default::default()
            }
        );
        assert_eq!(
            state.holes,
            vec![mkrange(initial_ack64 + 20, initial_ack64 + 40)]
        );
        assert_eq!(state.lost_bytes, 30);
        assert_eq!(state.loss_events, 1);

        // extend SACK block
        tcph.set_options(&[TcpOptionElement::SelectiveAcknowledgement(
            (initial_ack + 35, initial_ack + 50),
            [None, None, None],
        )])
        .unwrap();
        assert_eq!(
            state.process_rx_ack(pkt_time, true, &tcph),
            ProcessRxAckReturn {
                is_dup_ack: true,
                new_lost_bytes: 0,
                ..Default::default()
            }
        );
        assert_eq!(
            state.holes,
            // NOTE, the hole is unchanged, since we originally saw a hole that big,
            // even if it has not been partially filled in!
            vec![mkrange(initial_ack64 + 20, initial_ack64 + 40),]
        );
        assert_eq!(state.lost_bytes, 30);
        assert_eq!(state.loss_events, 1);
        tcph.set_options(&[]).unwrap();

        // ACK more data, fill everything
        tcph.acknowledgment_number = initial_ack + 50;
        assert_eq!(
            state.process_rx_ack(pkt_time, true, &tcph),
            ProcessRxAckReturn {
                is_dup_ack: false,
                new_lost_bytes: 0,
                ..Default::default()
            }
        );
        assert_eq!(state.holes, &[]);
        assert_eq!(state.lost_bytes, 30);
        assert_eq!(state.loss_events, 1);
    }

    #[test]
    fn test_ack_processing_2() {
        fn mkrange(left: TcpSeq64, right: TcpSeq64) -> SeqRange {
            SeqRange::try_from_seq64((left, right)).unwrap()
        }
        let pkt_time = DateTime::<Utc>::UNIX_EPOCH; // any time will do
        let initial_ack = 2_000_000_000;
        let initial_ack64 = initial_ack as TcpSeq64;
        let mut state = UnidirectionalTcpState::new(
            initial_ack,
            ConnectionSide::Local,
            mk_mock_connection_key(),
            mk_stat_handles(),
        );
        let mut tcph = TcpHeader::new(34333, 80, initial_ack - 1, 65535);
        tcph.ack = true;
        tcph.acknowledgment_number = initial_ack;

        assert_eq!(
            state.process_rx_ack(pkt_time, true, &tcph),
            ProcessRxAckReturn::default()
        );

        tcph.set_options(&[TcpOptionElement::SelectiveAcknowledgement(
            (initial_ack + 10, initial_ack + 20),
            [Some((initial_ack + 40, initial_ack + 50)), None, None],
        )])
        .unwrap();

        assert_eq!(
            state.process_rx_ack(pkt_time, true, &tcph),
            ProcessRxAckReturn {
                is_dup_ack: true,
                new_lost_bytes: 30,
                ..Default::default()
            }
        );
        assert_eq!(
            state.holes,
            vec![
                mkrange(initial_ack64, initial_ack64 + 10),
                mkrange(initial_ack64 + 20, initial_ack64 + 40)
            ]
        );
        assert_eq!(state.lost_bytes, 30);
        assert_eq!(state.loss_events, 1);

        // Partiall fill some holes, create a new hole
        tcph.set_options(&[TcpOptionElement::SelectiveAcknowledgement(
            (initial_ack + 7, initial_ack + 8),
            [
                Some((initial_ack + 10, initial_ack + 20)),
                Some((initial_ack + 40, initial_ack + 50)),
                Some((initial_ack + 60, initial_ack + 70)),
            ],
        )])
        .unwrap();
        tcph.acknowledgment_number = initial_ack + 5;
        assert_eq!(
            state.process_rx_ack(pkt_time, true, &tcph),
            ProcessRxAckReturn {
                is_dup_ack: false,
                // Only the hole 50--60 is newly lost.
                new_lost_bytes: 10,
                ..Default::default()
            }
        );
        assert_eq!(
            state.holes,
            vec![
                // Even though, we've received a SACK(7,8) we don't change this hole size
                // since we originally got a hole that big.node
                mkrange(initial_ack64 + 5, initial_ack64 + 10),
                mkrange(initial_ack64 + 20, initial_ack64 + 40),
                mkrange(initial_ack64 + 50, initial_ack64 + 60),
            ]
        );
        assert_eq!(state.lost_bytes, 40);
        assert_eq!(state.loss_events, 2);
        tcph.set_options(&[]).unwrap();

        // ACK more data, fill everything and create a new hole
        tcph.acknowledgment_number = initial_ack + 60;
        tcph.set_options(&[TcpOptionElement::SelectiveAcknowledgement(
            (initial_ack + 75, initial_ack + 85),
            [None, None, None],
        )])
        .unwrap();
        assert_eq!(
            state.process_rx_ack(pkt_time, true, &tcph),
            ProcessRxAckReturn {
                is_dup_ack: false,
                new_lost_bytes: 15,
                ..Default::default()
            }
        );
        assert_eq!(
            state.holes,
            &[mkrange(initial_ack64 + 60, initial_ack64 + 75)]
        );
        assert_eq!(state.lost_bytes, 55);
        assert_eq!(state.loss_events, 3);
    }

    #[test]
    fn test_fin_retransmit() {
        let stat_registry = ExportedStatRegistry::new("testing", std::time::Instant::now());
        let stat_handles = ConnectionStatHandles::new(&stat_registry);
        let mut capture =
        // NOTE: this capture has no FINs so contracker will not remove it
        pcap::Capture::from_file(test_dir("libconntack", "tests/fin-retransmit.pcap"))
            .unwrap();
        // take all of the packets in the capture and pipe them into the connection tracker
        let key = ConnectionKey {
            local_ip: IpAddr::from_str("192.168.1.238").unwrap(),
            remote_ip: IpAddr::from_str("147.28.154.173").unwrap(),
            local_l4_port: 55190,
            remote_l4_port: 443,
            ip_proto: IpProtocol::TCP,
        };
        let mut state =
            UnidirectionalTcpState::new(3_283_100_000, ConnectionSide::Local, key, stat_handles);
        assert_eq!(state.tcp_window().seq64(3_283_100_000), Some(3_283_100_000));
        while let Ok(pkt) = capture.next_packet() {
            let owned_pkt = OwnedParsedPacket::try_from_pcap(pkt).unwrap();
            let tcph = owned_pkt.transport.clone().unwrap().tcp().unwrap();
            state.process_pkt(&owned_pkt, &tcph);
        }
        assert_eq!(*state.fin_seq(), Some(3_283_150_784));
        let counters = stat_registry.get_counter_map();
        assert_eq!(
            *counters
                .get("testing.multiple_fins_different_seqno.COUNT")
                .unwrap(),
            0
        );
    }

    #[test]
    fn test_tcp_timestamp_struct() {
        assert!(TcpTimestamp(0xffff_ffff).lt(TcpTimestamp(1)));
        assert!(!TcpTimestamp(0).lt(TcpTimestamp(0)));
        assert!(!TcpTimestamp(1).lt(TcpTimestamp(1)));
        assert!(!TcpTimestamp(0xffff_ffff).lt(TcpTimestamp(0xffff_ffff)));
        assert!(TcpTimestamp(1).lt(TcpTimestamp(2)));

        // values exactly 1<<32 apart are not comparable
        assert!(!TcpTimestamp(0).lt(TcpTimestamp(0x8000_0000)));
        assert!(!TcpTimestamp(0x8000_0000).lt(TcpTimestamp(0)));

        assert!(TcpTimestamp(1).lt(TcpTimestamp(0x8000_0000)));
        assert!(TcpTimestamp(2).lt(TcpTimestamp(0x8000_0000)));
    }

    pub fn mk_packet_with_ts(
        outgoing: bool,
        pkt_time: DateTime<Utc>,
        ack_seq: u32,
        tcp_ts: u32,
    ) -> (Box<OwnedParsedPacket>, TcpHeader) {
        let mut pkt_bytes: Vec<u8> = Vec::new();
        let local_mac = [11, 22, 33, 44, 55, 66];
        let remote_mac = [77, 88, 99, 10, 11, 12];
        let local_ip: [u8; 4] = [1, 2, 3, 4];
        let remote_ip: [u8; 4] = [5, 6, 7, 8];
        let local_port = 42;
        let remote_port = 80;
        let payload: Vec<u8> = vec![0u8; if outgoing { 1 } else { 0 }];

        if outgoing {
            // Outgoing packet with a tsval we are interested in
            etherparse::PacketBuilder::ethernet2(local_mac, remote_mac)
                .ipv4(local_ip, remote_ip, 64)
                .tcp(local_port, remote_port, 100_000 + ack_seq, 65535)
                .ack(4242) // doesn't matter
                .options(&[TcpOptionElement::Timestamp(tcp_ts, 42)]) // tsecr is irrelevent
                .unwrap()
                .write(&mut pkt_bytes, &payload)
                .unwrap();
        } else {
            // incoming packet with a tsecr we care about.
            etherparse::PacketBuilder::ethernet2(remote_mac, local_mac)
                .ipv4(remote_ip, local_ip, 64)
                .tcp(remote_port, local_port, 4242, 65535) // seqno doen't matter
                .ack(100_000 + ack_seq)
                .options(&[TcpOptionElement::Timestamp(42, tcp_ts)]) // tsval is irrelevant
                .unwrap()
                .write(&mut pkt_bytes, &payload)
                .unwrap();
        }
        let pkt_headers = etherparse::PacketHeaders::from_ethernet_slice(&pkt_bytes).unwrap();
        let tcph = pkt_headers.transport.clone().unwrap().tcp().unwrap();
        let pkt = Box::new(OwnedParsedPacket::from_headers_and_ts(
            pkt_headers,
            pkt_time,
            pkt_bytes.len() as u32,
        ));
        let conn_key = pkt
            .to_connection_key(&HashSet::from([IpAddr::from_str("1.2.3.4").unwrap()]))
            .unwrap()
            .0;
        assert_eq!(mk_mock_connection_key(), conn_key); // sanity check
        (pkt, tcph)
    }

    #[test]
    fn test_extract_tcp_timestamp() {
        let (_pkt, tcp) = mk_packet_with_ts(true, Utc::now(), 1, 12345);
        assert_eq!(
            extract_tcp_timestamp(&tcp),
            Some((TcpTimestamp(12345), TcpTimestamp(42)))
        );
        let (_pkt, tcp) = mk_packet_with_ts(false, Utc::now(), 1, 12345);
        assert_eq!(
            extract_tcp_timestamp(&tcp),
            Some((TcpTimestamp(42), TcpTimestamp(12345)))
        );
        // Also make sure a packet w/o timestamp works
        let mut tcp = tcp.clone();
        tcp.set_options(&[]).unwrap();
        assert_eq!(tcp.options_len(), 0);
        assert_eq!(extract_tcp_timestamp(&tcp), None);
    }

    #[test]
    pub fn test_tcp_timestamp_handling() {
        let mk_ts_obs = |pkt_time: DateTime<Utc>, tsval: u32| TimestampObservation {
            pkt_time,
            tsval: TcpTimestamp(tsval),
        };
        let mk_dur_ms = chrono::Duration::milliseconds;
        // picked a fixed time. This helps find cases where we use Utc::now()
        // instead of the packet time. This timestamp is from 2024-01-11
        let t0 = DateTime::<Utc>::from_timestamp(1705015239, 0).unwrap();
        let mut state = UnidirectionalTcpState::new(
            100_000,
            ConnectionSide::Local,
            mk_mock_connection_key(),
            mk_stat_handles(),
        );
        let (pkt, tcp) = mk_packet_with_ts(true, t0, 0, 42_000);
        state.process_pkt(&pkt, &tcp);
        assert_eq!(state.timestamp_history, &[mk_ts_obs(t0, 42_000)]);

        // same tsval again ==> don't store it.
        let (pkt, tcp) = mk_packet_with_ts(true, t0 + mk_dur_ms(10), 1, 42_000);
        state.process_pkt(&pkt, &tcp);
        assert_eq!(state.timestamp_history, &[mk_ts_obs(t0, 42_000)]);

        // new tsval ==> store it
        let (pkt, tcp) = mk_packet_with_ts(true, t0 + mk_dur_ms(15), 2, 42_010);
        state.process_pkt(&pkt, &tcp);
        assert_eq!(
            state.timestamp_history,
            &[mk_ts_obs(t0, 42_000), mk_ts_obs(t0 + mk_dur_ms(15), 42_010)]
        );

        // send an old tsval again ==> don't store it.
        let (pkt, tcp) = mk_packet_with_ts(true, t0 + mk_dur_ms(20), 1, 42_000);
        state.process_pkt(&pkt, &tcp);
        assert_eq!(
            state.timestamp_history,
            &[mk_ts_obs(t0, 42_000), mk_ts_obs(t0 + mk_dur_ms(15), 42_010)]
        );

        // Add another timestamp.
        let (pkt, tcp) = mk_packet_with_ts(true, t0 + mk_dur_ms(25), 3, 42_100);
        state.process_pkt(&pkt, &tcp);
        assert_eq!(
            state.timestamp_history,
            &[
                mk_ts_obs(t0, 42_000),
                mk_ts_obs(t0 + mk_dur_ms(15), 42_010),
                mk_ts_obs(t0 + mk_dur_ms(25), 42_100)
            ]
        );

        assert_eq!(state.rtt_estimate_ms, 0.0);

        // Add a response
        let (pkt, tcp) = mk_packet_with_ts(false, t0 + mk_dur_ms(30), 1, 42_000);
        let rv = state.process_rx_ack(pkt.timestamp, true, &tcp);
        assert_eq!(rv.rtt_sample, Some(mk_dur_ms(30)));
        assert_eq!(state.rtt_estimate_ms, 30.0);
        assert_eq!(state.timestamp_history.len(), 2);

        // Add a response that does NOT ACK new data ==> noop
        let (pkt, tcp) = mk_packet_with_ts(false, t0 + mk_dur_ms(55), 1, 42_100);
        let rv = state.process_rx_ack(pkt.timestamp, true, &tcp);
        assert_eq!(rv.rtt_sample, None);
        assert_eq!(state.rtt_estimate_ms, 30.0);
        assert_eq!(state.timestamp_history.len(), 2);

        // ACK new data ==> new RTT sample
        let (pkt, tcp) = mk_packet_with_ts(false, t0 + mk_dur_ms(67), 3, 42_100);
        let rv = state.process_rx_ack(pkt.timestamp, true, &tcp);
        assert_eq!(rv.rtt_sample, Some(mk_dur_ms(42)));
        assert_relative_eq!(state.rtt_estimate_ms, 30.0 * 0.9 + 42.0 * 0.1); // alpha = 0.1; 67.0 - 25 == 42

        // all tsval less than the tsecr we just sent should have been evicted.
        assert_eq!(state.timestamp_history.len(), 0);
    }

    #[test]
    fn test_tcp_timestamp_history_len() {
        let mk_dur_ms = chrono::Duration::milliseconds;
        // picked a fixed time. This helps find cases where we use Utc::now()
        // instead of the packet time. This timestamp is from 2024-01-11
        let t0 = DateTime::<Utc>::from_timestamp(1705015239, 0).unwrap();
        let mut state = UnidirectionalTcpState::new(
            100_000,
            ConnectionSide::Local,
            mk_mock_connection_key(),
            mk_stat_handles(),
        );

        for i in 0..MAX_TIMESTAMP_HISTORY_LEN as u32 {
            let (pkt, tcp) = mk_packet_with_ts(true, t0 + mk_dur_ms(i as i64), i, 1000 + i);
            state.process_pkt(&pkt, &tcp);
            assert_eq!(state.timestamp_history.len(), i as usize + 1);
        }
        // New timestamps will not be added. Old ones will be preserved
        let mut i = MAX_TIMESTAMP_HISTORY_LEN as u32;
        let (pkt, tcp) = mk_packet_with_ts(true, t0 + mk_dur_ms(i as i64), i, 1000 + i);
        state.process_pkt(&pkt, &tcp);
        assert_eq!(state.timestamp_history.len(), MAX_TIMESTAMP_HISTORY_LEN);
        i += 1;
        let (pkt, tcp) = mk_packet_with_ts(true, t0 + mk_dur_ms(i as i64), i, 1000 + i);
        state.process_pkt(&pkt, &tcp);
        assert_eq!(state.timestamp_history.len(), MAX_TIMESTAMP_HISTORY_LEN);
    }
}
