use std::{
    collections::{HashMap, HashSet},
    process::ExitCode,
    rc::Rc,
};

use clap::Parser;
use itertools::Itertools;
use log::{error, info, warn};
use pb_conntrack_types::ConnectionStorageEntry;
use prost::Message;
use rusqlite::{Connection, OpenFlags};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
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

fn run() -> Result<(), Box<dyn std::error::Error>> {
    common::init::netdebug_init();
    let args = Args::parse();
    let mut graph: TheGraph = TheGraph::new();
    for fname in &args.sqlite_filenames {
        info!("Reading sqlite file: {}", fname);
        let db = Connection::open_with_flags(fname, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let mut stmt = db
            .prepare("SELECT saved_at, pb_storage_entry FROM connections")
            .expect("Could not prepare statement");
        let entries =
            stmt.query_and_then::<(String, ConnectionStorageEntry), BoxError, _, _>([], |row| {
                let buf = row.get::<usize, Vec<u8>>(1)?;
                let ts = row.get::<usize, String>(0)?;
                Ok((ts, ConnectionStorageEntry::decode(buf.as_slice())?))
            })?;
        for entry in entries {
            let entry = entry?;
            let (_ts, entry) = entry;
            // FIXME: this ingores some legit IPs as well for now. But we'll survive
            if entry.remote_ip.starts_with("192.168.") || entry.remote_ip.starts_with("fe80::") {
                continue;
            }
            if entry.remote_ip.contains(":") {
                // lets skip IPv6 for now
                continue;
            }
            //println!("{:#?}", entry);
            for probe_round in &entry.probe_rounds {
                // probes in DB are not sorrted by TTL. Sort them
                let mut probes_sorted = probe_round.probes.clone();
                probes_sorted.sort_by_key(|x| x.outgoing_ttl);
                let mut path_vec = Vec::new();
                for probe in probes_sorted {
                    use pb_conntrack_types::ProbeType::*;
                    let mut path_entry = PathEntry::default();
                    path_entry.dist = probe.outgoing_ttl as u8;
                    path_entry.ip = probe.sender_ip.clone();
                    match probe.probe_type() {
                        EndHostReplyFound | EndHostReplyNoProbe | UnspecifiedProbeType => {
                            path_entry.is_endhost = true;
                            // For endhosts, probe.sender_ip is None. So we need to use
                            // remote_ip
                            path_entry.ip = Some(entry.remote_ip.clone());
                        }
                        _ => (),
                    }
                    if path_vec.is_empty() {
                        path_vec.push(path_entry);
                    } else {
                        if path_vec.last().unwrap().is_endhost {
                            // previous entry was an endhost. So this entry and all following ones
                            // will also be dupACKs from the endhost. So, break the loop.
                            break;
                        } else {
                            path_vec.push(path_entry);
                        }
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
    }
    graph.print_dot();
    graph.print_stats();
    Ok(())
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

impl TheGraph {
    pub fn new() -> Self {
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

    pub fn print_dot(&mut self) {
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
        println!("digraph foobar {{");
        println!(r#"rankdir="LR""#);
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
            println!(r#"    "{}" {}"#, key, attr_str);
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
        println!("}}");
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{:?}", e);
            ExitCode::FAILURE
        }
    }
}
