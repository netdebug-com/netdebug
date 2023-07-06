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
        report: ProbeReport,
        probe_round: u32,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeReport {
    pub probes: HashMap<ProbeId, ProbeReportEntry>,
}

impl Display for ProbeReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for probe_id in self.probes.keys().sorted() {
            let e = self.probes.get(probe_id).unwrap();
            writeln!(f, "Probe {:3} - {:?}", probe_id, e)?;
        }
        Ok(())
    }
}

pub type ProbeId = u8;

#[derive(Clone, Debug, Serialize, Deserialize)]
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
}

impl ProbeReport {
    pub fn new(report: HashMap<ProbeId, ProbeReportEntry>) -> ProbeReport {
        ProbeReport { probes: report }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeReportSummaryNode {
    pub probe_type: ProbeReportEntry,
    pub ttl: u8,
    pub ip: Option<IpAddr>,
    pub rtts: Vec<f64>,
    pub comments: Vec<String>,
}

impl Display for ProbeReportSummaryNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut min = f64::MAX;
        let mut max = f64::MIN;
        let mut sum = 0.0;
        for rtt in &self.rtts {
            min = if min > *rtt { *rtt } else { min };
            max = if max > *rtt { max } else { *rtt };
            sum += rtt;
        }
        let avg = sum / self.rtts.len() as f64;
        // TODO: aggregate the comments
        if self.rtts.len() > 0 {
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeReportSummary {
    pub raw_reports: Vec<ProbeReport>,
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
     */
    pub fn update(&mut self, report: ProbeReport) {
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
                                node.comments.push(comment.clone());
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
                            node.comments.push(comment.clone());
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
                            node.comments.push(comment.clone());
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
                                node.comments.push(comment.clone());
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
                    rtts: Vec::new(),
                    comments: Vec::from([probe.get_comment()]),
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
