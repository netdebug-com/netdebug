#[derive(Debug, Clone, clap::ValueEnum)]
pub enum PacketField {
    /// Packet timestamp as floating point since epoch
    Time,
    /// Packet timestamp as ISO formatted string
    Isotime,
    /// Source IP
    Sip,
    /// Destination IP
    Dip,
    /// Source Port
    Sport,
    /// Destination Port
    Dport,
    /// The length of the packet as reported by libpcap
    Len,
    /// The length of the packet from the IP header
    Iplen,
    /// The IP protocol / next header. String for some well known ones,
    /// raw number otherwise
    Proto,
    /// The IP ID for IPv4, 0 for IPv6
    Ipid,
    /// TTL
    Ttl,
    /// Length of the payload (w/o IP and transport headers)
    PayloadLen,

    /// TCP sequence number
    TcpSeqNo,
    /// TCP ack number
    TcpAckNo,

    /// Syn Flag. 'S' if set, else '.'
    TcpSyn,
    /// Fin Flag. 'F' if set, else '.'
    TcpFin,
    /// Rst Flag. 'R' if set, else '.'
    TcpRst,
    /// Ack Flag. 'A' if set, else '.'
    TcpAck,
    /// Push Flag. 'P' if set, else '.'
    TcpPsh,
}

/// Print selected fields for each packet in the trace. One line per
/// packet. Like ipsumdump.
#[derive(clap::Parser, Debug)]
pub struct SumdumpCmdArgs {
    /// Comma separated list of packet header fields to display
    #[arg(long, value_delimiter = ',')]
    fields: Vec<PacketField>,
    pcap_file: String,
}
