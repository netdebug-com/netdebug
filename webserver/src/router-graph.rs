use std::{
    collections::{HashMap, HashSet},
    io::Write,
    net::IpAddr,
    process::ExitCode,
    rc::Rc,
    time::Duration,
};

use chrono::Utc;
use clap::{Parser, Subcommand};
use common_wasm::ProbeReportEntry;
use itertools::Itertools;
use libconntrack::pcap::lookup_egress_device;
use libconntrack_wasm::{ConnectionKey, ConnectionMeasurements, IpProtocol};
#[cfg(not(test))]
use log::{error, warn};
use rusqlite::{Connection, OpenFlags};
#[cfg(test)]
use std::{println as error, println as warn}; // Workaround to use prinltn! for logs.

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Args {
    #[command(subcommand)]
    command: CliCommands,
    // TODO: couldn't figure out how to mix arg() options with subcommand
    // so I've moved the files into each subcommand
}

#[derive(Debug, Subcommand)]
enum CliCommands {
    List(ListCmd),
    Stats(StatsCmd),
    Dot(DotCmd),
    ExtractRouterIps(IpCmd),
    Endhost(EndhostCmd),
    Search(SearchCmd),
    IntfTest(IntfTestCmd),
}

#[derive(Debug, Parser)]
struct IntfTestCmd {
    /// Just print interfaces once and exit
    #[arg(long, default_value_t = false)]
    pub one_shot: bool,
}
#[derive(Debug, Parser)]
struct ListCmd {
    #[arg()]
    pub sqlite_filenames: Vec<String>,
}
#[derive(Debug, Parser)]
struct StatsCmd {
    /// print weird flows as we find them
    #[arg(long, default_value_t = false)]
    pub verbose: bool,

    /// DB File
    #[arg()]
    pub sqlite_filenames: Vec<String>,
}

#[derive(Debug, Parser)]
struct DotCmd {
    /// DB File
    #[arg()]
    pub sqlite_filenames: Vec<String>,
}

#[derive(Debug, Parser)]
struct IpCmd {
    /// DB File
    #[arg()]
    pub sqlite_filenames: Vec<String>,
}

#[derive(Debug, Parser)]
struct EndhostCmd {
    /// Show Intra-probe-round Variance
    #[arg(long, default_value_t = false)]
    pub intra: bool,

    /// Show Inter-probe-round Variance
    #[arg(long, default_value_t = false)]
    pub inter: bool,

    /// DB File
    #[arg()]
    pub sqlite_filenames: Vec<String>,
}

#[derive(Debug, Parser)]
struct SearchCmd {
    /// Dump Json of matched measurements to screen
    #[arg(long, default_value_t = false)]
    pub dump_json: bool,

    /// Match on this src_ip
    #[arg(long, default_value = None)]
    pub local_ip: Option<IpAddr>,

    /// Match on this dst_ip
    #[arg(long, default_value = None)]
    pub remote_ip: Option<IpAddr>,

    /// Match on this src_port (as a string)
    #[arg(long, default_value = None)]
    pub local_port: Option<u16>,

    /// Match on this dst_ip (as a string)
    #[arg(long, default_value = None)]
    pub remote_port: Option<u16>,

    /// Match on this ip_protocol (as a number, e.g., 6 for TCP)
    #[arg(long, default_value = None)]
    pub ip_proto: Option<IpProtocol>,

    /// Show Inter-probe-round Variance
    #[arg(long, default_value_t = false)]
    pub inter: bool,

    /// DB File
    #[arg()]
    pub sqlite_filenames: Vec<String>,
}

type BoxError = Box<dyn std::error::Error>;

#[derive(Clone, PartialEq, Eq, Debug)]
struct MyRecord {
    remote_ip: String,
    remote_hostname: String,
    paths: HashSet<String>,
}

#[derive(Default, Clone, Eq, PartialEq, Debug)]
pub struct PathEntry {
    // TTL / distance from source
    pub dist: u8,
    // If we collapse multi unresponsive hops into a single Node (PathEntry) we
    // use count to track how many we collapsed
    pub count: u8,
    // The ip of this node. Or none if we inferred that this hop/TTL didn't
    // send a ersponse.
    pub ip: Option<String>,
    // Ip of predeccsor in the path
    pub pred_ip: Option<String>,
    // Ip of successor in the path
    pub successor_ip: Option<String>,
    pub is_endhost: bool,
    // The key to identify this router/host. If `ip` is set,
    // the IP will be the used. Otherwise we combine pred_ip and
    // successor_ip.
    pub key: NodeKey,
    pub num_out_path: usize,
}

impl PathEntry {
    pub fn mkkey(&mut self) {
        self.key = Rc::new(match &self.ip {
            Some(ip) => ip.to_string(),
            None => format!(
                "{}xx{}",
                self.pred_ip.clone().unwrap_or_default(),
                self.successor_ip.clone().unwrap_or_default()
            ),
        });
    }
}

fn visit_all_connections<F: FnMut(&String, &ConnectionMeasurements)>(
    db_files: &Vec<String>,
    mut visit: F,
) -> Result<(), Box<dyn std::error::Error>> {
    for db_file in db_files {
        let db = Connection::open_with_flags(db_file, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let mut stmt = db
            .prepare("SELECT saved_at, measurements FROM connections")
            .expect("Could not prepare statement");
        let entries =
            stmt.query_and_then::<(String, ConnectionMeasurements), BoxError, _, _>([], |row| {
                let json = row.get::<usize, String>(1)?;
                let ts = row.get::<usize, String>(0)?;
                Ok((ts, serde_json::from_str::<ConnectionMeasurements>(&json)?))
            })?;
        for entry in entries {
            let (ts, entry) = entry?;
            visit(&ts, &entry);
        }
    }
    Ok(())
}

fn visit_selected_connections<F: FnMut(&String, &ConnectionMeasurements)>(
    db_files: &Vec<String>,
    filter: ConnectionKeySearch,
    mut visit: F,
) -> Result<(), Box<dyn std::error::Error>> {
    visit_all_connections(db_files, |ts, measurements| {
        if filter.matches(&measurements.key) {
            visit(ts, measurements)
        }
    })
}

/**
 * Only call the underlying visit function for ConnectionStorageEntry without weird runs (e.g., with comments) or
 * and if it contains at least one router and does not have a 'busted' endhost
 *
 * Call 'reject' on any that don't pass this criteria
 */

fn filter_weird_and_routerless_connections<F: FnMut(&String, &ConnectionMeasurements)>(
    ts: &String,
    connection: &ConnectionMeasurements,
    mut visit: F,
) {
    let mut found_routers = false;
    let mut found_weird = false;
    let mut busted_endhost_check1 = false;
    let mut busted_endhost_check2 = false;
    for probe_round in &connection.probe_report_summary.raw_reports {
        for ttl in probe_round.probes.keys().sorted() {
            let probe = probe_round.probes.get(ttl).unwrap();
            // did we get a reply from a router or NAT?
            use ProbeReportEntry::*;
            match probe {
                RouterReplyFound { .. }
                | NatReplyFound { .. }
                | NatReplyNoProbe { .. }
                | RouterReplyNoProbe { .. } => found_routers = true,
                NoReply { .. }
                | NoOutgoing { .. }
                | EndHostReplyFound { .. }
                | EndHostNoProbe { .. } => (), // NO-OP
            }
            if !probe.get_comment().is_empty() {
                found_weird = true;
            }
            if busted_endhost_check1 && matches!(probe, ProbeReportEntry::NoReply { .. }) {
                busted_endhost_check2 = false; // doesn't match the pattern
            }
            if *ttl == 1 && matches!(probe, ProbeReportEntry::EndHostReplyFound { .. }) {
                // busted endhost has a signature in two parts;
                // first hop is an endhost (!?)
                busted_endhost_check1 = true;
                busted_endhost_check2 = true;
            }
        }
    }
    let busted = busted_endhost_check1 && busted_endhost_check2;
    if found_weird || (busted_endhost_check1 && busted_endhost_check2) || !found_routers {
        warn!(
            "Rejecting conneciton with bad data: {} :: weird={} busted={}, routers={}",
            connection.get_five_tuple_string(),
            found_weird,
            busted,
            found_routers
        );
    } else {
        visit(ts, connection);
    }
}

fn run_dot(
    db_files: &Vec<String>,
    no_filter: bool,
    print_graph: bool,
    print_stats: bool,
) -> Result<TheGraph, Box<dyn std::error::Error>> {
    common::init::netdebug_init();
    let mut graph: TheGraph = TheGraph::new();
    if no_filter {
        visit_all_connections(db_files, |_ts, connection| {
            process_connection(&mut graph, connection);
        })?;
    } else {
        visit_all_connections(db_files, |ts, connection| {
            filter_weird_and_routerless_connections(
                ts,
                connection,
                |_ts: &String, connection: &ConnectionMeasurements| {
                    process_connection(&mut graph, connection);
                },
            );
        })?;
    }
    if print_graph {
        graph.print_dot(&mut std::io::stdout())?;
    }
    if print_stats {
        graph.print_stats();
    }
    Ok(graph)
}

fn process_connection(graph: &mut TheGraph, entry: &ConnectionMeasurements) {
    // FIXME: this ingores some legit IPs as well for now. But we'll survive
    if entry.key.remote_ip.to_string().starts_with("192.168.")
        || entry.key.remote_ip.to_string().starts_with("fe80::")
    {
        return;
    }
    if entry.key.remote_ip.to_string().contains(':') {
        // lets skip IPv6 for now
        return;
    }
    //println!("{:#?}", entry);
    for probe_round in &entry.probe_report_summary.raw_reports {
        // probes in DB are not sorrted by TTL. Sort them
        let mut path_vec = Vec::new();
        for ttl in probe_round.probes.keys().sorted() {
            let probe = probe_round.probes.get(ttl).unwrap();
            let mut path_entry = PathEntry {
                dist: *ttl,
                ip: probe.get_ip().map(|ip| ip.to_string()),
                ..Default::default()
            };
            use ProbeReportEntry::*;
            match probe {
                EndHostReplyFound { .. } | EndHostNoProbe { .. } => {
                    path_entry.is_endhost = true;
                    // For endhosts, probe.sender_ip is None. So we need to use
                    // remote_ip
                    path_entry.ip = Some(entry.key.remote_ip.to_string().clone());
                }
                _ => (),
            }
            if path_vec.is_empty() {
                path_vec.push(path_entry);
            } else if path_vec.last().unwrap().is_endhost {
                // previous entry was an endhost. So this entry and all following ones
                // will also be dupACKs from the endhost. So, break the loop.
                break;
            } else {
                path_vec.push(path_entry);
            }
        }
        // Find the last element in that path that has a sender IP. This is for cases where we
        // don't see any more responses.
        let mut last_idx_with_ip = 0;
        for (idx, elem) in itertools::enumerate(&path_vec) {
            if elem.ip.is_some() {
                last_idx_with_ip = idx;
            }
        }

        // truncate the path.
        // Then collapse conseutive unresponsive hops/routers.
        let mut new_vec = path_vec[0..=last_idx_with_ip]
            .iter()
            // Dedup/collapse consecutive entries with matching IPs. At this stage this
            // we would expect that to be only for cases where a.ip == b.ip == None. I.e.,
            // unresponsive hosts. But maybe we sohuldn't assume and sanity check if the ip is not
            // None
            .dedup_by_with_count(|a, b| a.ip == b.ip)
            .map(|(cnt, elem)| {
                let mut elem = elem.clone();
                elem.count = cnt as u8;
                elem
            })
            .collect_vec();
        // For each element in the path, find the predecessor and successor IPs.
        let mut prev_ip = None;
        for elem in &mut new_vec {
            elem.pred_ip = prev_ip;
            prev_ip = elem.ip.clone();
        }
        let mut succ_ip = None;
        for elem in new_vec.iter_mut().rev() {
            elem.successor_ip = succ_ip;
            succ_ip = elem.ip.clone();
        }
        // hackery warning. lets compute the key we use for the node/PathEntry
        for elem in &mut new_vec {
            elem.mkkey();
        }
        graph.add_path(&new_vec);

        /*
        println!("ORIG {}", foobar(&path_vec));
        println!("MODI {}", foobar(&new_vec));
        println!("----");
        */
    }
}

pub struct NodeInfo<'a> {
    _node: &'a mut PathEntry,
    pred: &'a HashSet<NodeKey>,
    succ: &'a HashSet<NodeKey>,
}

type NodeKey = Rc<String>;

pub struct TheGraph {
    nodes: HashMap<NodeKey, PathEntry>,
    edges: HashSet<(NodeKey, NodeKey)>,
    // For each node: the set of outgoign edges
    out_edges: HashMap<NodeKey, HashSet<NodeKey>>,
    // For each node: the set of incoming edges
    in_edges: HashMap<NodeKey, HashSet<NodeKey>>,
    // The root node. I.e., the probign machine itself
    root: NodeKey,
    // Hackery: somewhere in the code we need to return a ref to an empty set that
    // needs to live long enough. So just dump one here.
    empty_set: HashSet<NodeKey>,
}

impl Default for TheGraph {
    fn default() -> Self {
        let mut nodes = HashMap::new();
        let root = Rc::new("LOCAL".to_string());
        nodes.insert(
            root.clone(),
            PathEntry {
                dist: 0,
                count: 0,
                ip: Some((*root).clone()),
                pred_ip: None,
                successor_ip: None,
                is_endhost: false,
                key: root.clone(),
                num_out_path: 0,
            },
        );
        TheGraph {
            nodes,
            edges: HashSet::new(),
            root,
            out_edges: HashMap::new(),
            in_edges: HashMap::new(),
            empty_set: HashSet::new(),
        }
    }
}

impl TheGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_path(&mut self, path: &Vec<PathEntry>) {
        let mut prev_node = self.root.clone();
        for elem in path {
            if let Some(entry) = self.nodes.get(&elem.key) {
                if entry != elem && entry.ip.is_none() {
                    // This happens if we have a number of unresponsive hops on a path from
                    // router A to router B. But the number of unresponsive hops differs from a previous
                    // route.
                    warn!(
                        "Same key but entries differ: from map: {:#?} VS. {:#?}",
                        entry, elem
                    );
                }
            } else {
                self.nodes.insert(elem.key.clone(), elem.clone());
            }
            self.out_edges
                .entry(prev_node.clone())
                .or_default()
                .insert(elem.key.clone());
            self.in_edges
                .entry(elem.key.clone())
                .or_default()
                .insert(prev_node.clone());
            self.edges.insert((prev_node, elem.key.clone()));
            prev_node = elem.key.clone();
        }
    }

    pub fn print_stats(&self) {
        eprintln!("nodes: {}", self.nodes.len());
        eprintln!("edges: {}", self.edges.len());
        let num_endhosts = self.nodes.iter().filter(|(_, v)| v.is_endhost).count();
        let num_unknown = self.nodes.iter().filter(|(k, _)| k.contains("xx")).count();
        eprintln!(
            "endhosts: {}, unknown routers: {}",
            num_endhosts, num_unknown
        );
    }

    pub fn get_node(&mut self, key: &NodeKey) -> NodeInfo {
        NodeInfo {
            _node: self.nodes.get_mut(key).unwrap(),
            pred: self.in_edges.get(key).unwrap_or(&self.empty_set),
            succ: self.out_edges.get(key).unwrap_or(&self.empty_set),
        }
    }

    pub fn print_dot<W: Write>(&mut self, mut writer: W) -> Result<(), std::io::Error> {
        // In order to keep the graph a bit more manageble for now, we find nodes we want to skip
        // We start at a node with no successor and follow it back towards to origin. Any node
        // with exactly one incoming and one outgoing edge is added to the list of skipped nodes.
        // Once we reach a node with more incoming or outgoing edges we stop. We do note the number of
        // such "stub" paths in the stop node.
        // WARNING. THIS CODE IS PROBABLY PRETTY SUSPECT AND MIGHT DO THE WRONG THING.
        let mut to_skip = Vec::new();
        let node_keys = self.nodes.keys().cloned().collect_vec();
        for key in node_keys {
            let info = self.get_node(&key);
            if info.succ.is_empty() && info.pred.len() == 1 {
                to_skip.push(key.clone());
            }
        }
        let mut idx = 0;
        while idx < to_skip.len() {
            let pred_key = {
                let info = self.get_node(&to_skip[idx]);
                assert_eq!(info.pred.len(), 1);
                info.pred.iter().next().unwrap().clone()
            };

            let info = self.get_node(&pred_key);
            if info.succ.len() == 1 && info.pred.len() == 1 {
                to_skip.push(pred_key.clone());
            } else {
                (self.nodes.get_mut(&pred_key).unwrap()).num_out_path += 1;
            }
            idx += 1;
        }
        let to_skip_set: HashSet<NodeKey> = HashSet::from_iter(to_skip.iter().cloned());
        write!(writer, "digraph foobar {{")?;
        write!(writer, r#"rankdir="LR""#)?;
        for (key, entry) in &self.nodes {
            if to_skip_set.contains(key) {
                continue;
            }
            let attr_str = if entry.is_endhost {
                r#"[color="red" fontcolor="red" shape="pentagon"]"#
            } else if entry.num_out_path > 0 {
                // we removed paths/chains from this node.
                // TODO: we should node how many we removed
                r#"[color="blue" fontcolor="blue"]"#
            } else if entry.key.contains("xx") {
                // a "virtual router". I.e. a set of unresponsive hops
                r#"[color="green" fontcolor="green" shape="rect"]"#
            } else {
                ""
            };
            write!(writer, r#"    "{}" {}"#, key, attr_str)?;
        }
        for edge in &self.edges {
            if to_skip_set.contains(&edge.0) || to_skip_set.contains(&edge.1) {
                continue;
            }
            let attr_str = if edge.0.contains("xx") || edge.1.contains("xx") {
                r#"[color="green"]"#
            } else {
                ""
            };
            // NOTE: this code currently inverts the direction of the edge. I.e., edges point from
            // the endhosts/probe targets towards the probing machine. I felt that this makes the dot layout somewhat better
            println!(r#"    "{}" -> "{}" {}"#, edge.1, edge.0, attr_str);
        }
        write!(writer, "}}")?;
        Ok(())
    }
}

/// Just like a ConnectionKey, but all of the fields are Optional
/// so we can use to select on a group of ConnectionKeys.
/// Any field marked as None will be treated like a wild card
#[derive(Debug, Clone)]
struct ConnectionKeySearch {
    local_ip: Option<IpAddr>,
    remote_ip: Option<IpAddr>,
    local_l4_port: Option<u16>,
    remote_l4_port: Option<u16>,
    ip_proto: Option<IpProtocol>,
}

impl ConnectionKeySearch {
    /**
     * This the passed key match this search key?
     *
     * Any field in the search key that's None is ignored/wildcarded
     */
    pub fn matches(&self, key: &ConnectionKey) -> bool {
        (self.local_ip.is_none() || self.local_ip.unwrap() == key.local_ip)
            && (self.remote_ip.is_none() || self.remote_ip.unwrap() == key.remote_ip)
            && (self.local_l4_port.is_none() || self.local_l4_port.unwrap() == key.local_l4_port)
            && (self.remote_l4_port.is_none() || self.remote_l4_port.unwrap() == key.remote_l4_port)
            && (self.ip_proto.is_none() || self.ip_proto.unwrap() == key.ip_proto)
    }
}
fn main() -> ExitCode {
    let args = Args::parse();
    use CliCommands::*;
    match args.command {
        List(sub_args) => {
            list_db_contents(&sub_args.sqlite_filenames);
            ExitCode::SUCCESS
        }
        Stats(sub_args) => {
            compute_stats(&sub_args.sqlite_filenames, sub_args.verbose);
            ExitCode::SUCCESS
        }
        Dot(sub_args) => match run_dot(&sub_args.sqlite_filenames, false, true, true) {
            Ok(_graph) => ExitCode::SUCCESS,
            Err(e) => {
                error!("{:?}", e);
                ExitCode::FAILURE
            }
        },
        ExtractRouterIps(sub_args) => match extract_ips(&sub_args.sqlite_filenames) {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => {
                warn!("Error: {}", e);
                ExitCode::FAILURE
            }
        },
        Endhost(sub_args) => match analyze_endhost_latencies_from_dbfiles(&sub_args) {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => {
                warn!("Error: {}", e);
                ExitCode::FAILURE
            }
        },
        Search(sub_args) => {
            if sub_args.sqlite_filenames.is_empty() {
                warn!("No DB files specified!?");
            }
            match visit_selected_connections(
                &sub_args.sqlite_filenames,
                ConnectionKeySearch {
                    local_ip: sub_args.local_ip,
                    remote_ip: sub_args.remote_ip,
                    local_l4_port: sub_args.local_port,
                    remote_l4_port: sub_args.remote_port,
                    ip_proto: sub_args.ip_proto,
                },
                |_ts, m| {
                    if sub_args.dump_json {
                        println!("{}", serde_json::to_string_pretty(&m).unwrap());
                    } else {
                        println!("Key found: {:?}", m.key);
                    }
                },
            ) {
                Ok(_) => ExitCode::SUCCESS,
                Err(e) => {
                    warn!("Search error: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        IntfTest(args) => run_intf_test(args),
    }
}

fn run_intf_test(args: IntfTestCmd) -> ExitCode {
    let mut devices = Vec::new();
    let mut old_egress_device = lookup_egress_device().unwrap();
    loop {
        let new_devices = pcap::Device::list().unwrap();
        let new_egress_device = lookup_egress_device().unwrap();
        if compare_devices(&devices, &new_devices) {
            println!("Network changed!");
            // NOTE: {:#?} is a pretty printer for debug!
            println!("    Old devices: {:#?}", devices);
            println!("    New devices: {:#?}", new_devices);
            println!("    Old Egress device: {:#?}", old_egress_device);
            println!("    New Egress device: {:#?}", new_egress_device);
        } else {
            println!("- No change - {:?}", Utc::now());
        }
        devices = new_devices;
        old_egress_device = new_egress_device;
        if args.one_shot {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    ExitCode::SUCCESS
}

/// Compare a list of ```pcap::Device```s and return 'true' if they are different
fn compare_devices(old_devices: &Vec<pcap::Device>, new_devices: &Vec<pcap::Device>) -> bool {
    if old_devices.len() != new_devices.len() {
        return true;
    }
    // assume they come in the same order - is that true?
    for (idx, old_dev) in old_devices.iter().enumerate() {
        let new_dev = new_devices.get(idx).unwrap();
        if !compare_device(old_dev, new_dev) {
            println!(" ---- Dev #{} {} not {}", idx, old_dev.name, new_dev.name);
            return true;
        }
    }
    false
}

fn compare_device(l: &pcap::Device, r: &pcap::Device) -> bool {
    l.name == r.name
        && l.desc == r.desc
        && l.flags.if_flags == r.flags.if_flags
        && l.flags.connection_status == r.flags.connection_status
        && l.addresses.len() == r.addresses.len()
    // skip comparing the actual interfaces; good enough for this test
}

// TODO: split each of the cli actions into its own file with libraries; next diff
#[allow(dead_code)]
struct EndHostLatencies {
    pub key: ConnectionKey,
    pub latencies_ms: Vec<f64>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct EndHostLatenciesStats {
    pub key: ConnectionKey,
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub max_less_mean: f64,
}

/// Extract the latency info from all of the probes and index by end-host IPs
/// TODO: assumes IPs are globally unique which is not true wrt Ip Anycast or RFC1918 addrs
/// TODO: assumes that all source addresses are the same host, which also isn't true..
/// ... handle them later
fn analyze_endhost_latencies(
    all_latencies: &mut HashMap<IpAddr, Vec<EndHostLatencies>>,
    measurements: &ConnectionMeasurements,
) {
    let endhost_ip = measurements.key.remote_ip;
    // Each new probe_round is from a different point in time, so call that a unique Latency measuremnt
    for probe_round in &measurements.probe_report_summary.raw_reports {
        // but each probe within a probe round happened back-to-back, so pull those together
        let data_entry = all_latencies.entry(endhost_ip).or_default();
        use ProbeReportEntry::*;
        let latencies_ms = probe_round
            .probes
            .iter()
            // only look at probes from the EndHost and extract out their RTT's
            .filter_map(|(_ttl, p)| match p {
                EndHostReplyFound {
                    rtt_ms, comment, ..
                } => {
                    if comment.is_empty() {
                        Some(rtt_ms)
                    } else {
                        None // skip 'weird' measurements with comments
                    }
                }
                _ => None,
            })
            .cloned()
            .collect::<Vec<f64>>();
        // only track/count probe_rounds with non-zero endhost probes
        if !latencies_ms.is_empty() {
            data_entry.push(EndHostLatencies {
                key: measurements.key.clone(),
                latencies_ms,
            })
        }
    }
}

fn analyze_endhost_intra_variance(endhost_latencies: &EndHostLatencies) -> EndHostLatenciesStats {
    assert!(!endhost_latencies.latencies_ms.is_empty());
    let mut min = f64::MAX;
    let mut max = f64::MIN;
    let mut sum = 0.0;
    for lat in &endhost_latencies.latencies_ms {
        min = lat.min(min);
        max = lat.max(max);
        sum += lat;
    }
    let mean = sum / endhost_latencies.latencies_ms.len() as f64;
    let max_less_mean = max - mean;
    EndHostLatenciesStats {
        key: endhost_latencies.key.clone(),
        min,
        max,
        mean,
        max_less_mean,
    }
}

fn analyze_endhost_latencies_from_dbfiles(
    sub_args: &EndhostCmd,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut all_latencies: HashMap<IpAddr, Vec<EndHostLatencies>> = HashMap::new();
    visit_all_connections(&sub_args.sqlite_filenames, |_ts, measurements| {
        analyze_endhost_latencies(&mut all_latencies, measurements);
    })?;
    println!("Done analysys: {:?}", sub_args);
    // print the intra-probe_round variance
    if sub_args.intra {
        for (ip, data) in all_latencies {
            print!("{} :: {} rounds :: congestion(ms): ", ip, data.len());
            let mut intra_variance = data
                .iter()
                .map(analyze_endhost_intra_variance)
                .collect::<Vec<EndHostLatenciesStats>>();
            // unwrap here is ok b/c we assert that this will never divide by zero/be NaN
            intra_variance.sort_by(|a, b| b.max_less_mean.partial_cmp(&a.max_less_mean).unwrap());
            for stat in intra_variance {
                if stat.max_less_mean > 10.0 {
                    print!(" {} ({:?})", stat.max_less_mean, stat);
                } else {
                    print!(" {}", stat.max_less_mean);
                }
            }
            println!();
        }
    }
    if sub_args.inter {
        todo!("Not implemented --inter!");
    }
    Ok(())
}

fn extract_ips(db_files: &Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let mut router_ips = HashSet::new();
    let mut remote_ips = HashSet::new();
    visit_all_connections(db_files, |_ts, entry| {
        remote_ips.insert(entry.key.remote_ip);
        for probe_round in &entry.probe_report_summary.raw_reports {
            for probe in probe_round.probes.values() {
                if let Some(sender_ip) = probe.get_ip() {
                    router_ips.insert(sender_ip);
                }
            }
        }
    })?;
    for ip in &router_ips {
        println!("router {}", ip);
    }
    for ip in &remote_ips {
        println!("remote {}", ip);
    }
    Ok(())
}

fn compute_stats(db_files: &Vec<String>, verbose: bool) {
    let mut num_flows = 0;
    let mut flows_with_routers = 0;
    let mut flows_with_weird = 0;
    let mut flows_with_busted_endhost = 0;
    visit_all_connections(db_files, |_ts, connection| {
        num_flows += 1;
        let mut found_routers = false;
        let mut found_weird = false;
        let mut busted_endhost_check1 = false;
        let mut busted_endhost_check2 = false;
        for probe_round in &connection.probe_report_summary.raw_reports {
            for ttl in probe_round.probes.keys().sorted() {
                // did we get a reply from a router or NAT?
                let probe = probe_round.probes.get(ttl).unwrap();
                use ProbeReportEntry::*;
                match probe {
                    RouterReplyFound { .. }
                    | RouterReplyNoProbe { .. }
                    | NatReplyFound { .. }
                    | NatReplyNoProbe { .. } => found_routers = true,
                    _ => (),
                }
                if !probe.get_comment().is_empty() {
                    found_weird = true;
                }
                if busted_endhost_check1 && matches!(probe, NoReply { .. }) {
                    busted_endhost_check2 = false; // doesn't match the pattern
                }
                if *ttl == 1 && matches!(probe, EndHostReplyFound { .. }) {
                    // busted endhost has a signature in two parts;
                    // first hop is an endhost (!?)
                    busted_endhost_check1 = true;
                    busted_endhost_check2 = true;
                }
            }
        }
        if found_routers {
            flows_with_routers += 1;
        }
        if found_weird {
            if verbose {
                println!("Found weird! {}", connection.get_five_tuple_string());
            }
            flows_with_weird += 1;
        }
        if busted_endhost_check1 && busted_endhost_check2 {
            flows_with_busted_endhost += 1;
        }
    })
    .unwrap();

    println!("Number of flows: {}", num_flows);
    println!(
        "... with routers: {} :: {}%",
        flows_with_routers,
        100 * flows_with_routers / num_flows
    );
    println!(
        "... with weird comments {} :: {}%",
        flows_with_weird,
        100 * flows_with_weird / num_flows
    );
    println!(
        "... with busted endhost {} :: {}%",
        flows_with_busted_endhost,
        100 * flows_with_busted_endhost / num_flows
    );
}

fn list_db_contents(db_files: &Vec<String>) {
    visit_all_connections(db_files, |_ts, connection| {
        let mut found_endhost = false;
        for probe_round in &connection.probe_report_summary.raw_reports {
            // TODO: maybe use ConnectionMeasurment::get_five_tuple_string instead?
            println!(
                "Connection: {} {:?} ({}:{}) --> {:?} ({}:{})",
                connection.key.ip_proto,
                connection.local_hostname,
                connection.key.local_ip,
                connection.key.local_l4_port,
                connection.remote_hostname,
                connection.key.remote_ip,
                connection.key.remote_l4_port
            );

            for ttl in probe_round.probes.keys().sorted() {
                let probe = probe_round.probes.get(ttl).unwrap();
                let rtt = match (&probe.get_in_timestamp_ms(), &probe.get_out_timestamp_ms()) {
                    (None, None) | (None, Some(_)) | (Some(_), None) => String::from(" "),
                    (Some(in_ts), Some(out_ts)) => {
                        format!("{:?}", Duration::from_millis((out_ts - in_ts) as u64))
                    }
                };
                let ip = if let Some(ip) = probe.get_ip() {
                    ip.to_string()
                } else if matches!(probe, ProbeReportEntry::EndHostReplyFound { .. }) {
                    connection.key.remote_ip.to_string()
                } else {
                    "-".to_string()
                };
                let probe_type = probe.get_type_name();
                if matches!(probe, ProbeReportEntry::EndHostReplyFound { .. }) {
                    // continue many end-host probes on the same line
                    if found_endhost {
                        print!(" {}", rtt);
                    } else {
                        found_endhost = true;
                        print!("      TTL {:2}: {} {} {}", ttl, probe_type, ip, rtt,);
                    }
                } else {
                    println!("      TTL {:2}: {} {} {}", ttl, probe_type, ip, rtt,);
                }
            }
            println!(); // end with an empty line
            println!("----------------------------------------------");
        }
    })
    .unwrap();
}

#[cfg(test)]
mod test {
    use common::test_utils::test_dir;

    use crate::run_dot;

    const TEST_DATA_SIMPLE: &str = "tests/test_input_connections.sqlite3";
    #[test]
    fn test_simple_graph() {
        let test_files = vec![test_dir("storge_server", TEST_DATA_SIMPLE)];
        let graph = run_dot(&test_files, false, false, false).unwrap();
        assert_eq!(graph.edges.len(), 33);
        assert_eq!(graph.nodes.len(), 33);
    }
}
