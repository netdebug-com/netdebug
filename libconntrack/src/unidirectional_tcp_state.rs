use std::fmt::Display;

use derive_getters::Getters;
use etherparse::{IpHeader, TcpHeader, TcpOptionElement};
use libconntrack_wasm::ConnectionKey;
use log::warn;

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
    /// The highest seq no seen from this INCLUDING the TCP payload
    sent_seq_no: Option<TcpSeq64>,
    /// The highest cummulative ACK this side has *received* from the other side.
    /// So, if `recv_ack_no == sent_seq_no + 1` then there is no unacked data
    recv_ack_no: Option<TcpSeq64>,
    /// Have we seen a RST from this side?
    rst_seen: bool,
    /// If this side has sent a FIN segment, the seq no of the FIN
    fin_seq: Option<TcpSeq64>,
    lost_bytes: u64,
    /// The list of current holes as compute from received SACKs. I.e., any hole between the highest
    /// ACK number received and any data indicated by SACK blocks. This Vec is sorted and the ranges
    /// are overlap free. Furthermore, when we advance `recv_ack_no` we remove any holes that have
    /// been 'closed' and record the lost bytes in `lost_bytes`.
    holes: Vec<SeqRange>,
    side: ConnectionSide,
}

impl UnidirectionalTcpState {
    pub fn new(
        raw_seq_or_ack: u32,
        side: ConnectionSide,
        connection_key: ConnectionKey,
        stat_handles: ConnectionStatHandles,
    ) -> Self {
        Self {
            connection_key,
            stat_handles,
            syn_pkt: None,
            tcp_window: TcpWindow::new(raw_seq_or_ack),
            sent_seq_no: None,
            recv_ack_no: None,
            rst_seen: false,
            fin_seq: None,
            lost_bytes: 0,
            holes: Vec::new(),
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
        // None < Some(x) for every x, so this nicely does the right thing :-)
        self.sent_seq_no = self
            .sent_seq_no
            .max(Some(cur_pkt_seq + tcp_payload_len(packet, tcp) as u64));
        if tcp.syn {
            if self.syn_pkt.is_some() {
                self.stat_handles.multiple_syns.bump();
                warn!(
                    "{}: {}: Weird - multiple SYNs on the same connection",
                    self.connection_key, self.side,
                );
            }
            self.syn_pkt = Some(packet.clone()); // memcpy() but doesn't happen that much or with much data
        }
        if tcp.fin {
            // FIN's "use" a sequence number as if they sent a byte of data
            if let Some(fin_seq) = self.fin_seq {
                if fin_seq != cur_pkt_seq {
                    self.stat_handles.multiple_fins.bump();
                    warn!(
                        "{}: {}: Weird: got multiple FIN seqnos: {} != {}",
                        self.connection_key, self.side, fin_seq, cur_pkt_seq
                    );
                }
                // else it's just a duplicate packet
            }
            self.fin_seq = Some(cur_pkt_seq);
        }
    }

    /// Process an ACK segment sent by the other side. I.e., process anything the other
    /// side has ACK'ed
    pub fn process_rx_ack(&mut self, pkt_payload_empty: bool, tcp: &TcpHeader) -> bool {
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
                return false;
            }
        };
        let is_dup_ack = match self.recv_ack_no {
            // Is this ACK a duplicate ACK?
            Some(old_ack) => {
                old_ack == cur_pkt_ack && pkt_payload_empty && !tcp.syn && !tcp.fin && !tcp.rst
            }
            None => false,
        };
        // None < Some(x) for every x, so this nicely does the right thing :-)
        self.recv_ack_no = self.recv_ack_no.max(Some(cur_pkt_ack));
        // TOOD: should we use the highest ACK number received so far or the ACK number from the current
        // packet. In theory both should be the same unless there is some weird re-ordering going on. But
        // I think the highest received ACK number makes the most sense....
        let holes = get_holes_from_sack(self.recv_ack_no.unwrap(), self.extract_sacks(tcp));
        self.holes.extend(holes);
        self.holes = sort_and_merge_ranges(std::mem::take(&mut self.holes));
        self.lost_bytes += remove_filled_holes(self.recv_ack_no.unwrap(), &mut self.holes);
        is_dup_ack
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

#[cfg(test)]
mod test {
    use std::{net::IpAddr, str::FromStr};

    use common_wasm::timeseries_stats::ExportedStatRegistry;
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
        let mut registry = ExportedStatRegistry::new("testing", std::time::Instant::now());
        ConnectionStatHandles::new(&mut registry)
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
    fn test_ack_processing() {
        fn mkrange(left: TcpSeq64, right: TcpSeq64) -> SeqRange {
            SeqRange::try_from_seq64((left, right)).unwrap()
        }
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
        assert!(!state.process_rx_ack(false, &tcph));
        assert!(state.process_rx_ack(true, &tcph));
        assert!(!state.process_rx_ack(false, &tcph));
        tcph.fin = true;
        assert!(!state.process_rx_ack(true, &tcph));
        tcph.fin = false;

        tcph.set_options(&[TcpOptionElement::SelectiveAcknowledgement(
            (initial_ack + 10, initial_ack + 20),
            [Some((initial_ack + 30, initial_ack + 40)), None, None],
        )])
        .unwrap();

        assert!(state.process_rx_ack(true, &tcph));
        assert_eq!(
            state.holes,
            vec![
                mkrange(initial_ack64, initial_ack64 + 10),
                mkrange(initial_ack64 + 20, initial_ack64 + 30)
            ]
        );
        assert_eq!(state.lost_bytes, 0);

        tcph.set_options(&[]).unwrap();

        // ACK more data, partially fill hole
        tcph.acknowledgment_number = initial_ack + 5;
        assert!(!state.process_rx_ack(true, &tcph));
        assert_eq!(
            state.holes,
            vec![
                mkrange(initial_ack64 + 5, initial_ack64 + 10),
                mkrange(initial_ack64 + 20, initial_ack64 + 30)
            ]
        );
        assert_eq!(state.lost_bytes, 5);

        // Send the SACK again. Nothing should happen
        tcph.set_options(&[TcpOptionElement::SelectiveAcknowledgement(
            (initial_ack + 10, initial_ack + 20),
            [Some((initial_ack + 30, initial_ack + 40)), None, None],
        )])
        .unwrap();
        assert!(state.process_rx_ack(true, &tcph));
        assert_eq!(
            state.holes,
            vec![
                mkrange(initial_ack64 + 5, initial_ack64 + 10),
                mkrange(initial_ack64 + 20, initial_ack64 + 30)
            ]
        );
        assert_eq!(state.lost_bytes, 5);
        tcph.set_options(&[]).unwrap();

        // ACK more data, completely fill first hole
        tcph.acknowledgment_number = initial_ack + 10;
        assert!(!state.process_rx_ack(true, &tcph));
        assert_eq!(
            state.holes,
            vec![mkrange(initial_ack64 + 20, initial_ack64 + 30)]
        );
        assert_eq!(state.lost_bytes, 10);

        // ACK more data, fill everything
        tcph.acknowledgment_number = initial_ack + 50;
        assert!(!state.process_rx_ack(true, &tcph));
        assert_eq!(state.holes, &[]);
        assert_eq!(state.lost_bytes, 20);
    }
}
