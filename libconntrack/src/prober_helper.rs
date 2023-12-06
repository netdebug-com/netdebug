use std::{collections::HashMap, net::IpAddr};

use common::rate_limit::SimpleRateLimiter;
use tokio::sync::mpsc::Sender;

use crate::{in_band_probe::ProbeMessage, utils::PerfMsgCheck};

const PROBE_DEST_EVERY_MILLIS: u64 = 15_000;
const PROBE_FIRST_HOPS_EVERY_MILLIS: u64 = 2_000;
const MIN_TTL_WHEN_RATE_LIMITED: u8 = 4;

/// Helper struct to limit the amount of probes we send to a particular destination
/// host and to the first couple of hops.
#[derive(Clone, Debug)]
pub struct ProberHelper {
    per_dst_rate_limit: HashMap<IpAddr, SimpleRateLimiter>,
    probe_first_hops_limit: SimpleRateLimiter,
    tx: Sender<PerfMsgCheck<ProbeMessage>>,
    unlimited: bool, // disable rate limiting if this is true
}

impl ProberHelper {
    pub fn new(prober_tx: Sender<PerfMsgCheck<ProbeMessage>>, unlimited: bool) -> Self {
        ProberHelper {
            per_dst_rate_limit: HashMap::new(),
            probe_first_hops_limit: SimpleRateLimiter::new(tokio::time::Duration::from_millis(
                PROBE_FIRST_HOPS_EVERY_MILLIS,
            )),
            tx: prober_tx,
            unlimited,
        }
    }

    /// Check and update the rate limiter for sending probes to a particular dst host.
    /// If this method returns `true` we can send a probe, if it returns `false`, we
    /// should not probe the destination.
    pub fn check_update_dst_ip(&mut self, dst_ip: IpAddr) -> bool {
        if self.unlimited {
            return true;
        }
        let dst_limiter = self
            .per_dst_rate_limit
            .entry(dst_ip)
            .or_insert(SimpleRateLimiter::new(tokio::time::Duration::from_millis(
                PROBE_DEST_EVERY_MILLIS,
            )));
        dst_limiter.check_update()
    }

    /// When sending probes: what should be the min TTL for outgoing probes. This
    /// limits how frequently we probe the first couple of hops.
    pub fn get_min_ttl(&mut self) -> u8 {
        if self.unlimited {
            return 1;
        }
        if self.probe_first_hops_limit.check_update() {
            1
        } else {
            MIN_TTL_WHEN_RATE_LIMITED
        }
    }

    pub fn tx(&self) -> Sender<PerfMsgCheck<ProbeMessage>> {
        self.tx.clone()
    }
}
