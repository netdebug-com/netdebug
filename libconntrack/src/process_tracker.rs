use std::net::IpAddr;
use std::{collections::HashMap, time::Instant};

use chrono::Duration;
use common_wasm::timeseries_stats::{ExportedStatRegistry, StatHandle, StatType, Units};
#[cfg(not(test))]
use log::{debug, warn};
use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::{println as debug, println as warn};
use tokio::sync::mpsc::channel;
use tokio::{sync::mpsc::UnboundedSender, task::JoinHandle};

use crate::connection::{ConnectionKey, ConnectionTrackerMsg, ConnectionTrackerSender};
use crate::utils::{make_perf_check_stats, PerfCheckStats, PerfMsgCheck};
use crate::{perf_check, try_send_async, try_send_sync};

#[derive(Clone, Debug)]
pub enum ProcessTrackerMessage {
    LookupOne {
        key: ConnectionKey,
        tx: ConnectionTrackerSender,
    },
    UpdateCache,
    UpdatePidMapping {
        // enumerating processes is usually slow, so do this
        // in a different task and send the results here periodically
        pid2process: HashMap<u32, String>,
    },
    DumpCache {
        // return the tcp_cache and the udp_cache
        tx: UnboundedSender<(
            HashMap<ConnectionKey, ProcessTrackerEntry>,
            HashMap<(IpAddr, u16), ProcessTrackerEntry>,
        )>,
    },
}

pub type ProcessTrackerSender = tokio::sync::mpsc::Sender<PerfMsgCheck<ProcessTrackerMessage>>;
pub type ProcessTrackerReceiver = tokio::sync::mpsc::Receiver<PerfMsgCheck<ProcessTrackerMessage>>;
pub struct ProcessTracker {
    tx: ProcessTrackerSender,
    rx: ProcessTrackerReceiver,
    tcp_cache: HashMap<ConnectionKey, ProcessTrackerEntry>,
    udp_cache: HashMap<(IpAddr, u16), ProcessTrackerEntry>,
    pid2app_name_cache: HashMap<u32, String>,
    msgs_received: StatHandle,
    msgs_tx_errors: StatHandle,
    dump_cache_perf_stat: PerfCheckStats,
    update_cache_perf_stat: PerfCheckStats,
    lookup_queue: Vec<(ConnectionKey, ConnectionTrackerSender)>, // where we store queued lookup requests
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTrackerEntry {
    pub associated_apps: HashMap<u32, Option<String>>, // map from PID to the application name, if we know it
}

impl ProcessTracker {
    pub fn new(max_queue: usize, mut stats: ExportedStatRegistry) -> ProcessTracker {
        let (tx, rx) = channel::<PerfMsgCheck<ProcessTrackerMessage>>(max_queue);
        let msgs_received = stats.add_stat("messages_recieved", Units::None, [StatType::COUNT]);
        let msgs_tx_errors = stats.add_stat("messages_tx_errors", Units::None, [StatType::COUNT]);
        ProcessTracker {
            tx,
            rx,
            tcp_cache: HashMap::new(),
            udp_cache: HashMap::new(),
            pid2app_name_cache: HashMap::new(),
            msgs_received,
            msgs_tx_errors,
            dump_cache_perf_stat: make_perf_check_stats("dump_cache", &mut stats),
            update_cache_perf_stat: make_perf_check_stats("update_cache", &mut stats),
            lookup_queue: Vec::new(),
        }
    }

    /**
     * Start the rx handler in the background
     *
     * and on supported OS's, also start a pid2process caching class
     */

    pub async fn spawn(
        mut self,
        update_frequency: Duration,
    ) -> (ProcessTrackerSender, JoinHandle<()>) {
        #[cfg(windows)]
        {
            let tx = self.tx.clone();
            let _join_pid2process_loop =
                tokio::spawn(async move { run_pid2process_loop(update_frequency, tx).await });
        }
        let tx = self.tx.clone();
        let join = tokio::spawn(async move { self.do_async_loop(update_frequency).await });
        (tx, join)
    }

    pub async fn do_async_loop(&mut self, update_frequency: Duration) {
        // setup a background task to periodically send a UpdateCache message
        let tx = self.tx.clone();
        let mut stat = self.msgs_tx_errors.clone();
        tokio::spawn(async move {
            loop {
                // TODO: break on too many errors? Then do what?
                tokio::time::sleep(update_frequency.to_std().unwrap()).await;
                try_send_async!(
                    &tx,
                    "process_tracker",
                    ProcessTrackerMessage::UpdateCache,
                    &mut stat
                )
                .await;
            }
        });
        while let Some(msg) = self.rx.recv().await {
            use ProcessTrackerMessage::*;
            self.msgs_received.add_value(1);
            let start = Instant::now();
            let msg = msg.perf_check_get("ProcessTracker::do_async_loop queue");
            // quick debug message, unless it's the really big
            if let UpdatePidMapping { pid2process } = &msg {
                debug!("Got UpdatePidMapping msg : {} pids", pid2process.len());
            } else {
                debug!("Got msg: {:?}", msg); // all the rest are short enough to log via Debug
            }
            match &msg {
                LookupOne { key, tx } => self.lookup_or_queue(key.clone(), tx.clone()),
                UpdateCache => self.update_cache(),
                DumpCache { tx } => {
                    let start = Instant::now();
                    if let Err(e) = tx.send((self.tcp_cache.clone(), self.udp_cache.clone())) {
                        warn!("ProcessTracker :: dump cache sender failed: {}", e);
                    }
                    perf_check!(
                        format!(
                            "ProcessTracker::DumpCache (tcp={}, udp={})",
                            self.tcp_cache.len(),
                            self.udp_cache.len()
                        ),
                        start,
                        std::time::Duration::from_millis(25),
                        self.dump_cache_perf_stat
                    );
                }
                UpdatePidMapping { pid2process } => {
                    self.pid2app_name_cache = pid2process.clone();
                }
            }
            perf_check!(
                format!(
                    "ProcessTracker: message handle {:?} :: {} tcp {} udp",
                    msg,
                    self.tcp_cache.len(),
                    self.udp_cache.len()
                ),
                start,
                std::time::Duration::from_millis(100)
            );
        }
    }

    fn lookup_from_cache(&self, key: &ConnectionKey) -> Option<ProcessTrackerEntry> {
        if key.ip_proto == etherparse::IpNumber::Tcp as u8 {
            if let Some(entry) = self.tcp_cache.get(&key) {
                Some(entry.clone())
            } else {
                None
            }
        } else {
            // Udp is stored only by local IP + local Port - try looking that up
            // only a single process can bind a specific port, so try that
            if let Some(entry) = self.udp_cache.get(&(key.local_ip, key.local_l4_port)) {
                Some(entry.clone())
            } else {
                None
            }
        }
    }

    /**
     * If we get a request to lookup one application, if we have the data now, send it immediately.
     * If not, queue it until the next update
     */

    fn lookup_or_queue(&mut self, key: ConnectionKey, tx: ConnectionTrackerSender) {
        let reply = self.lookup_from_cache(&key);
        if reply.is_some() {
            try_send_sync!(
                tx,
                "ConnectionTracker",
                ConnectionTrackerMsg::SetConnectionApplication {
                    key,
                    application: reply,
                },
                &mut self.msgs_tx_errors
            );
        } else {
            // try again on next refresh to avoid a race condition
            self.lookup_queue.push((key.clone(), tx.clone()));
        }
    }

    /**
     * Update the cache of connections from the OS (with mapping from connection to pid)
     * and the mapping of pid to process name.  
     *
     * Note that Windows claims that a given connection can be owned by multiple PIDs, e.g.,
     * when a DLL starts a DNS cache, but this makes no sense to me.  Just rolling with it but
     * this is why all of the resulting data structures are one to many (e.g., Vec()/HashMap() rather than one to one.
     */
    fn update_cache(&mut self) {
        let start = Instant::now();
        let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
        // pull the sockets to process mapping from the OS via this cool (buggy?) netstat2 crate
        let sockets_info = match netstat2::get_sockets_info(af_flags, proto_flags) {
            Ok(info) => info,
            Err(e) => {
                warn!(
                    "Failed to get socket info netstat2::get_sockets_info() :: {}",
                    e
                );
                return;
            }
        };
        let mut new_tcp_cache: HashMap<ConnectionKey, ProcessTrackerEntry> = HashMap::new();
        let mut new_udp_cache: HashMap<(IpAddr, u16), ProcessTrackerEntry> = HashMap::new();

        // parse out all of the new data
        for si in sockets_info {
            let associated_apps = HashMap::from_iter(si.associated_pids.into_iter().map(|p| {
                // clone the app name if it exists
                let app = if let Some(app) = self.pid2app_name_cache.get(&p) {
                    Some(app.clone())
                } else {
                    None
                };
                (p, app)
            }));
            match &si.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp_si) => {
                    if tcp_si.remote_port != 0 {
                        // don't record sockets that are just listenning
                        let key =
                            ConnectionKey::from_protocol_socket_info(&si.protocol_socket_info);
                        if new_tcp_cache.contains_key(&key) && associated_apps.is_empty() {
                            debug!(
                                "process_tracker:: Skipping stray duplicate update!?: {} -- {:?}",
                                key, associated_apps
                            );
                            continue;
                        }
                        new_tcp_cache.insert(key, ProcessTrackerEntry { associated_apps });
                    }
                }
                ProtocolSocketInfo::Udp(udp_si) => {
                    let key = (udp_si.local_addr, udp_si.local_port);
                    new_udp_cache.insert(key, ProcessTrackerEntry { associated_apps });
                }
            }
        }

        // last, move new cache into place
        self.tcp_cache = new_tcp_cache;
        self.udp_cache = new_udp_cache;
        self.process_queued_lookups();
        perf_check!(
            "ProcessTracker::update_cache",
            start,
            std::time::Duration::from_millis(25),
            self.update_cache_perf_stat
        );
    }

    /**
     * This is called after an update, so process any queued lookups that were hoping
     * that their application was listed in the most recent update.
     *
     * If it's not, just return None so they can track the stats appropriately
     */

    fn process_queued_lookups(&mut self) {
        while let Some((key, tx)) = self.lookup_queue.pop() {
            let application = self.lookup_from_cache(&key);
            try_send_sync!(
                tx,
                "ConnectionTracker",
                ConnectionTrackerMsg::SetConnectionApplication {
                    key,
                    application: application,
                },
                &mut self.msgs_tx_errors
            );
        }
    }
}

/**
 * This is only defined for windows, for now
 *
 * This can take a long time to run .. seconds even, so run in a diff
 * task/thread and async post the data back to the main ProcessTracker
 */
#[cfg(windows)]
async fn run_pid2process_loop(update_frequency: Duration, tx: ProcessTrackerSender) {
    use chrono::Utc;

    loop {
        let start = Utc::now();
        let pid2process = match make_pid2process() {
            Ok(map) => map,
            Err(e) => {
                warn!("ProcessTracker make_pid2process returned : {}", e);
                continue; // try again!?
            }
        };

        use ProcessTrackerMessage::*;
        try_send_async!(tx, "process_tracker", UpdatePidMapping { pid2process }).await;

        let next_update = start + update_frequency;
        let now = Utc::now();
        if next_update > now {
            let delta = next_update - now;
            debug!("run_pid2process_loop sleeping for {}", delta);
            tokio::time::sleep(delta.to_std().unwrap()).await;
        }
    }
}

#[cfg(windows)]
fn make_pid2process() -> Result<HashMap<u32, String>, Box<dyn std::error::Error>> {
    use std::io::BufRead;
    use std::io::BufReader;
    let mut pid2process = HashMap::new();
    let cmd_output = std::process::Command::new("tasklist")
        .arg("/fo")
        .arg("CSV") // output in CSV format
        .arg("/nh") // skip the CSV header
        .output()?; // can this ever fail?
    if !cmd_output.stderr.is_empty() {
        return Err(format!(
            "Error from pid2process(): {}",
            String::from_utf8(cmd_output.stderr)?
        )
        .into());
    }
    let output = BufReader::new(cmd_output.stdout.as_slice());
    for line in output.lines() {
        if let Err(e) = line {
            warn!("Unparsed string in run_pid2process!? {}", e);
            continue;
        }
        let line = line.unwrap(); // ok, b/c we checked above

        // TODO: find a real CSV parser library
        let tokens = line.split(",").collect::<Vec<&str>>();
        if tokens.len() < 3 {
            warn!(
                "Too short CSV string in run_pid2process!? {}",
                tokens.join(",")
            );
            continue;
        }
        let process_name = tokens[0].replace("\"", "");
        let pid: u32 = tokens[1].replace("\"", "").parse()?;
        pid2process.insert(pid, process_name);
    }
    Ok(pid2process)
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use libconntrack_wasm::IpProtocol;

    use super::*;
    #[tokio::test]
    async fn process_update() {
        // bind a socket real quick for some ground truth
        let tcp_server = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let server_addr = tcp_server.local_addr().unwrap();
        // println!("Test socket bound: {}", server_addr);
        let tcp_client = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let client_port = tcp_client.local_addr().unwrap().port();
        let local_l4_port = std::cmp::min(server_addr.port(), client_port);
        let remote_l4_port = std::cmp::max(server_addr.port(), client_port);
        let my_pid = std::process::id();
        let test_key = ConnectionKey {
            local_ip: server_addr.ip(),
            remote_ip: server_addr.ip(),
            local_l4_port,
            remote_l4_port,
            ip_proto: etherparse::IpNumber::Tcp as u8,
        };
        //

        let mut process_tracker = ProcessTracker::new(
            128,
            ExportedStatRegistry::new("process_tracker", Instant::now()),
        );
        process_tracker.update_cache();

        let mut found_it = false;
        for (key, entry) in &process_tracker.tcp_cache {
            if *key == test_key {
                found_it = true;
                // did we correctly find this connection and map it back to this pid?
                assert!(!entry.associated_apps.is_empty());
                assert!(entry.associated_apps.contains_key(&my_pid));
                // TODO : we don't track App names for all OSes yet - when we do, add this test
                // let name = apps.get(&my_pid);
                // assert_eq(name, std::process::name(), std::env::args().next().unwrap());
            }
        }
        assert!(found_it);
    }

    #[tokio::test]
    async fn test_queued_lookups() {
        let mut process_tracker = ProcessTracker::new(
            128,
            ExportedStatRegistry::new("process_tracker", Instant::now()),
        );
        let local_ip = IpAddr::from_str("1.1.1.1").unwrap();
        let remote_ip = IpAddr::from_str("2.2.2.2").unwrap();
        let (conntrack_tx, mut conntrack_rx) = tokio::sync::mpsc::channel(128);
        let test_key = ConnectionKey {
            local_ip,
            remote_ip,
            local_l4_port: 3333,
            remote_l4_port: 4444,
            ip_proto: IpProtocol::TCP.to_wire(),
        };
        assert_eq!(process_tracker.lookup_queue.len(), 0);
        // cache is empty, so lookup should queue
        process_tracker.lookup_or_queue(test_key.clone(), conntrack_tx);
        assert_eq!(process_tracker.lookup_queue.len(), 1);
        let my_pid = 12345;
        let my_app = "MyApp".to_string();
        // fake insert some data into the queue
        process_tracker.tcp_cache.insert(
            test_key.clone(),
            ProcessTrackerEntry {
                associated_apps: HashMap::from([(my_pid, Some(my_app.clone()))]),
            },
        );
        process_tracker.process_queued_lookups();
        use ConnectionTrackerMsg::*;
        match conntrack_rx.try_recv().unwrap().skip_perf_check() {
            SetConnectionApplication { key, application } => {
                assert_eq!(key, test_key);
                let application = application.unwrap();
                assert_eq!(application.associated_apps.len(), 1);
                let (test_pid, test_app) = application.associated_apps.iter().next().unwrap();
                assert_eq!(*test_pid, my_pid);
                assert_eq!(*test_app, Some(my_app));
            }
            _other => panic!("Expected SetConnectionApplication: got {:?}", _other),
        }
    }

    /**
     * Any system will have some threads; just make sure we get non-garbage data
     * and make sure we find this process in it
     */
    #[cfg(windows)]
    #[test]
    fn test_make_pid2process() {
        let my_pid = std::process::id();
        let pid2process_cache = make_pid2process().unwrap();
        assert_ne!(pid2process_cache.len(), 0);
        assert!(pid2process_cache.contains_key(&my_pid));
    }
}
