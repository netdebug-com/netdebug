use analysis_messages::AnalysisInsights;
use itertools::Itertools;
use std::{collections::HashMap, fmt::Display, net::IpAddr}; // for .sorted()

/**
 * Attention: everything in this library (including transitively) must
 * complile for both native rust as well as for WASM, so:
 * 1) No Threads
 * 2) No System dependencies (e.g., clocks)
 * 3) Probably more things
 *
 * Might want to consider moving this to Google Protobufs so we can
 * get forwards and backwards compatibility, but for now we can do a version
 * check at the start and reload the client if need be.
 */
use serde::{Deserialize, Serialize};

pub const PROBE_MAX_TTL: u8 = 32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    VersionCheck {
        git_hash: String,
    },
    // Initial message from server
    Ping1FromServer {
        server_timestamp_ms: f64,
        probe_round: u32,
        max_rounds: u32,
    },
    // Client replies, copying server_timestamp_ns back and attaching its own ts
    Ping2FromClient {
        server_timestamp_ms: f64,
        client_timestamp_ms: f64,
        probe_round: u32,
        max_rounds: u32,
    },
    // Final reply from server, echoing client's ts back to it
    // and server_rtt = server recv - server_timestamp_us
    Ping3FromServer {
        server_rtt: f64,
        client_timestamp_ms: f64,
        probe_round: u32,
        max_rounds: u32,
    },
    ProbeReport {
        report: ProbeRoundReport,
        probe_round: u32,
    },
    SetUserAnnotation {
        annotation: String,
    },
    Insights {
        insights: Vec<AnalysisInsights>,
    },
}

impl Message {
    pub fn make_version_check() -> Message {
        Message::VersionCheck {
            git_hash: env!("GIT_HASH").to_string(),
        }
    }

    pub fn check_version(git_hash: &String) -> bool {
        // Note that the webserver, the webclient, and this library
        // should all use the same GIT_HASH and this is created
        // at compile time by build.rs
        git_hash == env!("GIT_HASH")
    }
}

pub fn get_git_hash_version() -> String {
    env!("GIT_HASH").to_string()
}

fn convert_f64_ms_to_pb_duration(duration_ms: Option<f64>) -> Option<prost_types::Duration> {
    match duration_ms {
        Some(dt) => {
            let dt = dt / 1000.;
            Some(prost_types::Duration {
                seconds: if dt < 0.0 { dt.ceil() } else { dt.floor() } as i64,
                nanos: (dt.fract() * 1e9) as i32,
            })
        }
        None => None,
    }
}

fn convert_f64_ms_to_pb_timestamp(timestamp_ms: Option<f64>) -> Option<prost_types::Timestamp> {
    // protobuf Duration and Timestap happen to have the same fields and types, so a bit of hackery:
    convert_f64_ms_to_pb_duration(timestamp_ms).map(|dur| prost_types::Timestamp {
        seconds: dur.seconds,
        nanos: dur.nanos,
    })
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProbeRoundReport {
    pub probes: HashMap<ProbeId, ProbeReportEntry>,
    pub probe_round: u32,
    pub application_rtt: Option<f64>,
}

impl Eq for ProbeRoundReport {}

impl Display for ProbeRoundReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(app_rtt) = self.application_rtt {
            writeln!(f, "Probe report: application delay {}", app_rtt,)?;
        }
        for probe_id in self.probes.keys().sorted() {
            let e = self.probes.get(probe_id).unwrap();
            writeln!(f, "Probe {:3} - {:?}", probe_id, e)?;
        }
        Ok(())
    }
}

impl ProbeRoundReport {
    pub fn to_protobuf(&self) -> pb_conntrack_types::ProbeRoundReport {
        pb_conntrack_types::ProbeRoundReport {
            probe_round: self.probe_round,
            application_rtt: convert_f64_ms_to_pb_duration(self.application_rtt),
            probes: self.probes.iter().map(|p| p.1.to_protobuf()).collect(),
        }
    }
}

pub type ProbeId = u8;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ProbeReportEntry {
    // the notion of 'comment' might get abused - consider strongly typing everything(?)
    RouterReplyFound {
        // an ICMP message
        ttl: u8,
        out_timestamp_ms: f64,
        rtt_ms: f64,
        src_ip: IpAddr,
        comment: String,
    },
    NatReplyFound {
        // an ICMP message, but src_ip of the ICMP is the dst_ip of our original packet, implies NAT!
        ttl: u8,
        out_timestamp_ms: f64,
        rtt_ms: f64,
        src_ip: IpAddr,
        comment: String,
    },
    NoReply {
        ttl: u8,
        out_timestamp_ms: f64,
        comment: String,
    },
    NoOutgoing {
        ttl: u8,
        comment: String,
    },
    RouterReplyNoProbe {
        ttl: u8,
        in_timestamp_ms: f64,
        src_ip: IpAddr,
        comment: String,
    },
    NatReplyNoProbe {
        ttl: u8,
        in_timestamp_ms: f64,
        src_ip: IpAddr,
        comment: String,
    },
    EndHostReplyFound {
        ttl: u8,
        out_timestamp_ms: f64,
        rtt_ms: f64,
        comment: String,
    },
    EndHostNoProbe {
        ttl: u8,
        in_timestamp_ms: f64,
        comment: String,
    },
    // TODO: add GoodRR etc. for w/ Record Route
}

impl ProbeReportEntry {
    fn to_protobuf(&self) -> pb_conntrack_types::Probe {
        use pb_conntrack_types::ProbeType;
        let sender_ip = self.get_ip().map(|ip| ip.to_string());
        let comment = if !self.get_comment().is_empty() {
            Some(self.get_comment())
        } else {
            None
        };

        let probe_type = match self {
            ProbeReportEntry::RouterReplyFound { .. } => ProbeType::RouterReplyFound,
            ProbeReportEntry::NatReplyFound { .. } => ProbeType::NatReplyFound,
            ProbeReportEntry::NoReply { .. } => ProbeType::NoReply,
            ProbeReportEntry::NoOutgoing { .. } => ProbeType::NoOutgoing,
            ProbeReportEntry::RouterReplyNoProbe { .. } => ProbeType::RouterReplyNoProbe,
            ProbeReportEntry::NatReplyNoProbe { .. } => ProbeType::NatReplyNoProbe,
            ProbeReportEntry::EndHostReplyFound { .. } => ProbeType::EndHostReplyFound,
            ProbeReportEntry::EndHostNoProbe { .. } => ProbeType::EndHostReplyNoProbe,
        } as i32;

        let outgoing_ttl = self.get_ttl() as u32;
        pb_conntrack_types::Probe {
            probe_type,
            outgoing_ttl,
            out_timestamp: convert_f64_ms_to_pb_timestamp(self.get_out_timestamp_ms()),
            in_timestamp: convert_f64_ms_to_pb_timestamp(self.get_in_timestamp_ms()),
            sender_ip,
            received_ttl_remaining: None,
            comment: comment,
        }
    }

    fn get_comment(&self) -> String {
        use ProbeReportEntry::*;
        match self {
            RouterReplyFound {
                ttl: _,
                out_timestamp_ms: _,
                rtt_ms: _,
                src_ip: _,
                comment,
            }
            | NatReplyFound {
                ttl: _,
                out_timestamp_ms: _,
                rtt_ms: _,
                src_ip: _,
                comment,
            }
            | NoReply {
                ttl: _,
                out_timestamp_ms: _,
                comment,
            }
            | NoOutgoing { ttl: _, comment }
            | RouterReplyNoProbe {
                ttl: _,
                in_timestamp_ms: _,
                src_ip: _,
                comment,
            }
            | NatReplyNoProbe {
                ttl: _,
                in_timestamp_ms: _,
                src_ip: _,
                comment,
            }
            | EndHostReplyFound {
                ttl: _,
                out_timestamp_ms: _,
                rtt_ms: _,
                comment,
            }
            | EndHostNoProbe {
                ttl: _,
                in_timestamp_ms: _,
                comment,
            } => comment.clone(),
        }
    }

    fn get_ip(&self) -> Option<IpAddr> {
        use ProbeReportEntry::*;
        match self {
            RouterReplyFound {
                ttl: _,
                out_timestamp_ms: _,
                rtt_ms: _,
                src_ip,
                comment: _,
            }
            | NatReplyFound {
                ttl: _,
                out_timestamp_ms: _,
                rtt_ms: _,
                src_ip,
                comment: _,
            }
            | NatReplyNoProbe {
                ttl: _,
                in_timestamp_ms: _,
                src_ip,
                comment: _,
            } => Some(*src_ip),
            RouterReplyNoProbe {
                ttl: _,
                in_timestamp_ms: _,
                src_ip: _,
                comment: _,
            }
            | NoReply {
                ttl: _,
                out_timestamp_ms: _,
                comment: _,
            }
            | NoOutgoing { ttl: _, comment: _ }
            | EndHostReplyFound {
                ttl: _,
                out_timestamp_ms: _,
                rtt_ms: _,
                comment: _,
            }
            | EndHostNoProbe {
                ttl: _,
                in_timestamp_ms: _,
                comment: _,
            } => None,
        }
    }

    fn get_rtt(&self) -> Option<f64> {
        use ProbeReportEntry::*;
        match self {
            RouterReplyFound { rtt_ms, .. }
            | NatReplyFound { rtt_ms, .. }
            | EndHostReplyFound { rtt_ms, .. } => Some(*rtt_ms),
            NoReply { .. }
            | NoOutgoing { .. }
            | RouterReplyNoProbe { .. }
            | NatReplyNoProbe { .. }
            | EndHostNoProbe { .. } => None,
        }
    }

    fn get_out_timestamp_ms(&self) -> Option<f64> {
        use ProbeReportEntry::*;
        match self {
            RouterReplyFound {
                out_timestamp_ms, ..
            }
            | NatReplyFound {
                out_timestamp_ms, ..
            }
            | EndHostReplyFound {
                out_timestamp_ms, ..
            }
            | NoReply {
                out_timestamp_ms, ..
            } => Some(*out_timestamp_ms),
            NoOutgoing { .. }
            | RouterReplyNoProbe { .. }
            | NatReplyNoProbe { .. }
            | EndHostNoProbe { .. } => None,
        }
    }

    fn get_in_timestamp_ms(&self) -> Option<f64> {
        use ProbeReportEntry::*;
        match self {
            RouterReplyFound {
                out_timestamp_ms,
                rtt_ms,
                ..
            }
            | NatReplyFound {
                out_timestamp_ms,
                rtt_ms,
                ..
            }
            | EndHostReplyFound {
                out_timestamp_ms,
                rtt_ms,
                ..
            } => Some(*out_timestamp_ms + *rtt_ms),
            NoReply { .. } | NoOutgoing { .. } => None,
            RouterReplyNoProbe {
                in_timestamp_ms, ..
            }
            | NatReplyNoProbe {
                in_timestamp_ms, ..
            }
            | EndHostNoProbe {
                in_timestamp_ms, ..
            } => Some(*in_timestamp_ms),
        }
    }

    fn get_ttl(&self) -> u8 {
        use ProbeReportEntry::*;
        match self {
            RouterReplyFound { ttl, .. }
            | NatReplyFound { ttl, .. }
            | NoReply { ttl, .. }
            | NoOutgoing { ttl, .. }
            | RouterReplyNoProbe { ttl, .. }
            | NatReplyNoProbe { ttl, .. }
            | EndHostReplyFound { ttl, .. }
            | EndHostNoProbe { ttl, .. } => *ttl,
        }
    }
}

impl Eq for ProbeReportEntry {}

impl ProbeRoundReport {
    pub fn new(
        report: HashMap<ProbeId, ProbeReportEntry>,
        probe_round: u32,
        application_rtt: Option<f64>,
    ) -> ProbeRoundReport {
        ProbeRoundReport {
            probes: report,
            probe_round,
            application_rtt,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProbeReportSummaryNode {
    pub probe_type: ProbeReportEntry,
    pub ttl: u8,
    pub ip: Option<IpAddr>,
    pub rtts: Vec<f64>,
    pub comments: Vec<String>,
}
impl Eq for ProbeReportSummaryNode {}

impl ProbeReportSummaryNode {
    pub fn stats(&self) -> Option<(f64, f64, f64)> {
        let mut min = f64::MAX;
        let mut max = f64::MIN;
        let mut sum = 0.0;
        for rtt in &self.rtts {
            min = if min > *rtt { *rtt } else { min };
            max = if max > *rtt { max } else { *rtt };
            sum += rtt;
        }
        if self.rtts.len() > 0 {
            let avg = sum / self.rtts.len() as f64;
            Some((min, avg, max))
        } else {
            None
        }
    }

    pub fn name(&self) -> String {
        use ProbeReportEntry::*;
        match self.probe_type {
            RouterReplyFound { .. } => "Router",
            NatReplyFound { .. } => "NAT",
            NoReply { .. } => "*",
            NoOutgoing { .. } => "???", // missing outgoing, how do we represent this to the user?
            RouterReplyNoProbe { .. } => "Router?",
            NatReplyNoProbe { .. } => "NAT?",
            EndHostReplyFound { .. } => "Host",
            EndHostNoProbe { .. } => "Host?",
        }
        .to_string()
    }
}

impl Display for ProbeReportSummaryNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO: aggregate the comments
        if let Some((min, avg, max)) = self.stats() {
            write!(
                f,
                "{:?} {:?} RTT(ms) min={} avg={} max={} ",
                self.probe_type, self.ip, min, avg, max
            )
        } else {
            write!(f, "{:?} {:?} ", self.probe_type, self.ip,)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeReportSummary {
    pub raw_reports: Vec<ProbeRoundReport>,
    pub summary: HashMap<u8, Vec<ProbeReportSummaryNode>>,
}

impl ProbeReportSummary {
    pub fn new() -> ProbeReportSummary {
        ProbeReportSummary {
            raw_reports: Vec::new(),
            summary: HashMap::new(),
        }
    }

    /**
     * For each ttl, we can have multiple events (e.g., sometimes a packet is dropped, sometime not)
     *
     * Take this new probe report, and aggregate the information into the ProbeReportSummary
     *
     */
    pub fn update(&mut self, report: ProbeRoundReport) {
        for (ttl, probe) in &report.probes {
            let nodes = self.summary.entry(*ttl).or_insert(Vec::new());
            let mut inserted = false;
            for node in nodes {
                // are these two ProbeReportEntry's the same variant?
                // https://stackoverflow.com/questions/32554285/compare-enums-only-by-variant-not-value
                if std::mem::discriminant(probe) == std::mem::discriminant(&node.probe_type) {
                    use ProbeReportEntry::*;
                    match probe {
                        RouterReplyFound {
                            ttl: _,
                            out_timestamp_ms: _,
                            rtt_ms,
                            src_ip,
                            comment,
                        }
                        | NatReplyFound {
                            ttl: _,
                            out_timestamp_ms: _,
                            rtt_ms,
                            src_ip,
                            comment,
                        } => {
                            if src_ip == &node.ip.unwrap() {
                                // these variants should always have an IP
                                node.rtts.push(*rtt_ms);
                                if !comment.is_empty() {
                                    node.comments.push(comment.clone());
                                }
                                inserted = true;
                                break;
                            }
                            // else keep looking
                        }
                        EndHostReplyFound {
                            ttl: _,
                            out_timestamp_ms: _,
                            rtt_ms,
                            comment,
                        } => {
                            node.rtts.push(*rtt_ms);
                            if !comment.is_empty() {
                                node.comments.push(comment.clone());
                            }
                            inserted = true;
                            break;
                        }
                        NoReply {
                            ttl: _,
                            out_timestamp_ms: _,
                            comment,
                        }
                        | NoOutgoing { ttl: _, comment }
                        | EndHostNoProbe {
                            ttl: _,
                            in_timestamp_ms: _,
                            comment,
                        } => {
                            if !comment.is_empty() {
                                node.comments.push(comment.clone());
                            }
                            inserted = true;
                            break;
                        }
                        RouterReplyNoProbe {
                            ttl: _,
                            in_timestamp_ms: _,
                            src_ip,
                            comment,
                        }
                        | NatReplyNoProbe {
                            ttl: _,
                            in_timestamp_ms: _,
                            src_ip,
                            comment,
                        } => {
                            if src_ip == &node.ip.unwrap() {
                                // these variants should always have an IP
                                if !comment.is_empty() {
                                    node.comments.push(comment.clone());
                                }
                                inserted = true;
                                break;
                            }
                            // else keep looking
                        }
                    }
                }
            }
            if !inserted {
                // need a new node
                let node = ProbeReportSummaryNode {
                    probe_type: probe.clone(),
                    ttl: *ttl,
                    ip: probe.get_ip(),
                    rtts: if let Some(rtt_ms) = probe.get_rtt() {
                        vec![rtt_ms]
                    } else {
                        Vec::new()
                    },
                    comments: if !probe.get_comment().is_empty() {
                        vec![probe.get_comment()]
                    } else {
                        Vec::new()
                    },
                };
                // get nodes again from the summary is it went into the above for loop's into_iter()
                let nodes = self.summary.entry(*ttl).or_insert(Vec::new());
                nodes.push(node);
            }
        }
        self.raw_reports.push(report);
    }
}

impl Display for ProbeReportSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for ttl in self.summary.keys().sorted() {
            let nodes = self.summary.get(ttl).unwrap();
            if nodes.len() == 1 {
                // simple and hopefully common case
                writeln!(f, "TTL {:3} - {}", ttl, nodes.first().unwrap())?;
            } else {
                // multiple different replies for the same TTL
                // this can happen with packet loss or route flapping
                // it shouldn't happen often as all packets in a probe report should hit
                // the same ECMP bucket
                writeln!(f, "TTL {:3} -------", ttl)?;
                let n_nodes = self.raw_reports.len(); // each report should have 1 result per ttl
                for node in nodes {
                    let n_replies = node.comments.len(); // one comment per replu
                    let percent = 100.0 * n_replies as f64 / n_nodes as f64;
                    // TODO: sort by frequency?
                    writeln!(f, "     {:4}% - {} :: {}", percent, n_replies, node)?;
                }
            }
        }
        Ok(())
    }
}

pub mod analysis_messages;
pub mod evicting_hash_map;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_convert_f64_ms_to_pb_duration() {
        assert_eq!(convert_f64_ms_to_pb_duration(None), None);

        let dur = convert_f64_ms_to_pb_duration(Some(69517123.456789));
        assert!(dur.is_some());
        let dur_unwrapped = dur.unwrap();
        assert_eq!(dur_unwrapped.seconds, 69517);
        // Since we are dealing with f64, the nano seconds can't be represented
        // with full precision, so check that we are "close enough"
        assert!((dur_unwrapped.nanos - 123456789).abs() < 100);

        let dur = convert_f64_ms_to_pb_duration(Some(-4242123.456));
        assert!(dur.is_some());
        let dur_unwrapped = dur.unwrap();
        assert_eq!(dur_unwrapped.seconds, -4242);
        assert!((-dur_unwrapped.nanos - 123456000).abs() < 100);
    }
}
