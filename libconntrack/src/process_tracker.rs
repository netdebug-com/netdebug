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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTrackerEntry {
    associated_pids: Vec<u32>,
}

impl ProcessTracker {
    pub fn new(
        conntracker: UnboundedSender<ConnectionTrackerMsg>,
    ) -> ProcessTracker {
        let (tx, rx) = unbounded_channel::<ProcessTrackerMessage>();
        ProcessTracker {
            conntracker,
            tx,
            rx,
            tcp_cache: HashMap::new(),
            udp_cache: HashMap::new(),
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
                        associated_pids: v.associated_pids.clone(),
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
