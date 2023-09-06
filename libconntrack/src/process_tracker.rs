use std::collections::HashMap;
use std::net::IpAddr;

use chrono::Duration;
use log::warn;
use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};

use crate::connection::{ConnectionKey, ConnectionTrackerMsg};

pub enum ProcessTrackerMessage {
    LookupOne {
        key: ConnectionKey,
        tx: UnboundedSender<Option<ProcessTrackerEntry>>,
    },
    UpdateCache,
}

pub struct ProcessTracker {
    conntracker: UnboundedSender<ConnectionTrackerMsg>,
    tx: UnboundedSender<ProcessTrackerMessage>,
    rx: UnboundedReceiver<ProcessTrackerMessage>,
    tcp_cache: HashMap<ConnectionKey, ProcessTrackerEntry>,
    udp_cache: HashMap<(IpAddr, u16), ProcessTrackerEntry>,
    pid2app_name_cache: HashMap<u32, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTrackerEntry {
    associated_pids: Vec<u32>,
}

impl ProcessTracker {
    pub fn new(conntracker: UnboundedSender<ConnectionTrackerMsg>) -> ProcessTracker {
        let (tx, rx) = unbounded_channel::<ProcessTrackerMessage>();
        ProcessTracker {
            conntracker,
            tx,
            rx,
            tcp_cache: HashMap::new(),
            udp_cache: HashMap::new(),
            pid2app_name_cache: HashMap::new(),
        }
    }

    pub async fn spawn(
        mut self,
        update_frequency: Duration,
    ) -> (UnboundedSender<ProcessTrackerMessage>, JoinHandle<()>) {
        let tx = self.tx.clone();
        let join = tokio::spawn(async move { self.do_async_loop(update_frequency).await });
        (tx, join)
    }

    pub async fn do_async_loop(&mut self, update_frequency: Duration) {
        // setup a background task to periodically send a UpdateCache message
        let tx = self.tx.clone();
        tokio::spawn(async move {
            loop {
                // TODO: break on too many errors? Then do what?
                tokio::time::sleep(update_frequency.to_std().unwrap()).await;
                if let Err(e) = tx.send(ProcessTrackerMessage::UpdateCache) {
                    warn!("ProcessTracker :: update cache sender failed: {}", e);
                }
            }
        });
        while let Some(msg) = self.rx.recv().await {
            use ProcessTrackerMessage::*;
            match msg {
                LookupOne { key, tx } => self.handle_lookup(key, tx),
                UpdateCache => self.update_cache(),
            }
        }
    }

    fn handle_lookup(&self, key: ConnectionKey, tx: UnboundedSender<Option<ProcessTrackerEntry>>) {
        let reply = if key.ip_proto == etherparse::IpNumber::Tcp as u8 {
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
        };
        if let Err(e) = tx.send(reply) {
            warn!(
                "Failed to send reply from ProcessTracker::handle_lookup!?: {}",
                e
            );
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
            match &si.protocol_socket_info {
                ProtocolSocketInfo::Tcp(_tcp_si) => {
                    let key = ConnectionKey::from_protocol_socket_info(&si.protocol_socket_info);
                    new_tcp_cache.insert(
                        key,
                        ProcessTrackerEntry {
                            associated_pids: si.associated_pids,
                        },
                    );
                }
                ProtocolSocketInfo::Udp(udp_si) => {
                    let key = (udp_si.local_addr, udp_si.local_port);
                    new_udp_cache.insert(
                        key,
                        ProcessTrackerEntry {
                            associated_pids: si.associated_pids,
                        },
                    );
                }
            }
        }

        // walk through the old data and compare
        for (k, v) in &new_tcp_cache {
            if !self.tcp_cache.contains_key(&k) {
                if let Err(e) = self
                    .conntracker
                    .send(ConnectionTrackerMsg::SetConnectionPids {
                        key: k.clone(),
                        associated_apps: v
                            .associated_pids
                            .iter()
                            .map(|p| {
                                let name = match self.pid2app_name_cache.get(&p) {
                                    Some(name) => Some(name.clone()),
                                    None => None,
                                };
                                (p.clone(), name)
                            })
                            .collect(),
                    })
                {
                    warn!("Failed to send SetConnectionPids to ConnTracker: {}", e);
                }
            }
        }
        // don't bother sending the proactive UDP updates for now - too much work for too little reward
        // TODO: add Udp support once netstat2 is fixed up sanely per issue #11

        // last, move new cache into place
        self.tcp_cache = new_tcp_cache;
        self.udp_cache = new_udp_cache;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[tokio::test]
    async fn dns_update() {
        // bind a socket real quick for some ground truth
        let tcp_server = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
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
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        let mut process_tracker = ProcessTracker::new(tx);
        process_tracker.update_cache();

        // in theory, the only tx to the channel is in process_tracker and it will
        // go out of scope HERE b/c it's not refereced anymore, so the rx should
        // empty the channel and then return an error when getting messages
        // rather than just query indefinitely

        let mut found_it = false;
        while let Ok(msg) = rx.try_recv() {
            use ConnectionTrackerMsg::*;
            let (key, apps) = match &msg {
                SetConnectionPids {
                    key,
                    associated_apps,
                } => Some((key, associated_apps)),
                _ => panic!("Got unexplained ConnectionTrackerMsg {:?}", msg),
            }
            .unwrap();
            if *key == test_key {
                found_it = true;
                // did we correctly find this connection and map it back to this pid?
                assert!(!apps.is_empty());
                assert!(apps.contains_key(&my_pid));
                // TODO : we don't track App names for all OSes yet - when we do, add this test
                // let name = apps.get(&my_pid);
                // assert_eq(name, std::process::name(), std::env::args().next().unwrap());
            }
        }
        assert!(found_it);
    }
}
