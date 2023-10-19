/***
 * Given a (ideally closed)/finished/fully probed [struct Connect], tell the user as much about
 * it as we can.
 *
 * NOTE: All of this business logic is intentionally kept out of the client code so that it can't
 * be dissassembled/reverse engineered from the client code.
 */

use std::{collections::HashMap, error::Error};

use itertools::Itertools;

use common_wasm::{
    analysis_messages::{AnalysisInsights, Blame, Goodness, ProbeReportLatencies},
    ProbeReportEntry, ProbeReportSummaryNode,
};
use log::debug;

use crate::connection::Connection;

pub fn analyze(connection: &Connection) -> Vec<AnalysisInsights> {
    let mut insights = Vec::new();

    if connection.probe_report_summary.raw_reports.is_empty() {
        // No probes recorded!?  That will hamper our ability to learn anything
        insights.push(AnalysisInsights::NoProbes);
    }

    // TODO
    // connection option insights
    // remote OS insights
    // window scaling insights
    // dropped egress probes

    let nats = look_for_nat(connection);
    let mut best_nat = Vec::<u32>::new();
    for (ttl, probe_reports) in &nats {
        insights.push(AnalysisInsights::HasNat { ttl: *ttl });
        if best_nat.len() < probe_reports.len() {
            best_nat = probe_reports.clone();
        }
    }
    // just focus on the TTL with the most nat replies

    insights.append(&mut naive_latency_analysis(connection));
    insights.append(&mut explain_latency(connection, best_nat));

    insights
}

/**
 * Look through all of the probe replies and return the TTL of the NAT devices
 * we found.  NAT device locations should be fairly stable to just the first should be
 * fine but track all just in case.  Note that NAT replies can be fairly rate limited (~1 reply/second) so we won't
 * find one all of the time.
 *
 * Return value is a Map of <TTL> --> Vec of probe reports that had a NAT
 */

fn look_for_nat(connection: &Connection) -> HashMap<u8, Vec<u32>> {
    let mut nats = HashMap::new();

    for (probe_round, probe_report) in connection
        .probe_report_summary
        .raw_reports
        .iter()
        .enumerate()
    {
        for (_ttl, probe) in &probe_report.probes {
            use ProbeReportEntry::*;
            match &probe {
                NatReplyFound { ttl, .. } => {
                    if nats.contains_key(ttl) {
                        // why can't the compiler figure out this type!?
                        let probes: &mut Vec<u32> = nats.get_mut(ttl).unwrap();
                        probes.push(probe_round as u32);
                    } else {
                        nats.insert(*ttl, vec![probe_round as u32]);
                    }
                }
                RouterReplyFound { .. }
                | NoReply { .. }
                | NoOutgoing { .. }
                | RouterReplyNoProbe { .. }
                | NatReplyNoProbe { .. }
                | EndHostReplyFound { .. }
                | EndHostNoProbe { .. } => (),
            }
        }
    }
    nats
}

#[allow(dead_code)] // we'll probably use these extra fields later
struct ApplicationLatencyAnalysis {
    pub min: f64,
    pub max: f64,
    pub avg: f64,
    pub max_probe_round: u32,
    pub avg_probe_round: u32,
    pub avg_probe_round_approximation_error: f64,
}

/**
 * If nats is set, only look at the application latency for the
 * probe rounds where there is a NAT reply
 */

fn compute_application_latency(
    connection: &Connection,
    nats: Option<Vec<u32>>,
) -> ApplicationLatencyAnalysis {
    let mut min = f64::MAX;
    let mut max = f64::MIN;
    let mut sum = 0.0;
    let mut max_probe_round = 0;

    let report_rounds = if let Some(nats) = nats {
        nats
    } else {
        (0..connection.probe_report_summary.raw_reports.len() as u32).collect()
    };
    for probe_round in &report_rounds {
        let report = connection
            .probe_report_summary
            .raw_reports
            .get(*probe_round as usize)
            .unwrap();
        if let Some(app_rtt) = report.application_rtt {
            sum += app_rtt;
            if min > app_rtt {
                min = app_rtt;
            }
            if max < app_rtt {
                max = app_rtt;
                max_probe_round = *probe_round as u32;
            }
        }
    }

    let avg = if report_rounds.len() > 0 {
        sum / report_rounds.len() as f64
    } else {
        0.0 // no data, can't take average
    };
    // now go back through the application latency results and find the round closest
    // to the average so we can compare against a 'typical' one
    let mut avg_probe_round_approximation_error = f64::MAX;
    let mut avg_probe_round = 0 as u32;
    for probe_round in report_rounds {
        let report = connection
            .probe_report_summary
            .raw_reports
            .get(probe_round as usize)
            .unwrap();
        if let Some(app_rtt) = report.application_rtt {
            let diff = f64::abs(avg - app_rtt);
            if diff < avg_probe_round_approximation_error {
                // this clause should trigger at least once if there's any data
                avg_probe_round_approximation_error = diff;
                avg_probe_round = probe_round as u32;
            }
        }
    }
    ApplicationLatencyAnalysis {
        min,
        max,
        avg,
        max_probe_round,
        avg_probe_round,
        avg_probe_round_approximation_error,
    }
}

/**
 * Try to explain why there is a latency difference between the average application latency and the max.
 *
 * If the connection had enough replies with the NAT responding, then focus only on the probe rounds that
 * had NATS in them. NOTE that NATs can be heavily rate limited (~1 reply/second) so this might throw away
 * a lot (too much?) of our data
 *
 * This algorithm is a little complicated because for each probe round, in theory we have three measurements
 * we want to compare: a reply from a NAT device indidicating the start of the home network, probably many replies
 * from the endhost - indicating a reply from the kernel, and an application level reply.  But we might not have a
 * reply from the NAT, so do we ignore non-NAT replies?  Also, how do we compare the many endhost replies to the
 * at most one application reply?  Make some best guesses here and come back if it looks too weird.
 *
 * When we have a lot of endhost replies for a specific probe round, which one do we use?  The avg?  min? max?
 * Since we're really using the endhost pings to test the latency of the last-hop (presumably the hop after the NAT)
 * then the min would be best as it minimizes the kernel stack processing variance, but also adds potential
 * measurement error.
 *
 * Also a "NAT" may show up at many hops if there's an interior network on the other side of the NAT.  What
 * we really want is to partition regions of concern, e.g, ISP's part of the network vs. the endhost's network
 * vs. the endhost's processing delay.
 */

fn explain_latency(connection: &Connection, nats: Vec<u32>) -> Vec<AnalysisInsights> {
    let mut insights = Vec::new();

    const MIN_NATS_FOR_ANALYSIS: usize = 50; // made up number, e.g. at least 50% of 100 probe rounds
    let application_latency = if nats.len() < MIN_NATS_FOR_ANALYSIS {
        debug!("Found NATs, but not enough to narrowly analyze just the nats");
        compute_application_latency(connection, None)
    } else {
        compute_application_latency(connection, Some(nats))
    };

    // extract the average(typical) and worst cases and releative percents
    let typical = extract_latencies(
        connection,
        application_latency.avg_probe_round,
        application_latency.avg,
    );
    let worst = extract_latencies(
        connection,
        application_latency.max_probe_round,
        application_latency.max,
    );
    // ok - given the fractional changes in the latencies between the typical and worst
    // cases, then we decide to 'blame' the source that had the biggest/positive increase
    let net_delta = worst.percent_endhost - typical.percent_net;
    let endhost_delta = worst.percent_endhost - typical.percent_endhost;
    let processing_delta = worst.percent_processing - typical.percent_processing;

    let blame = if net_delta > endhost_delta {
        if net_delta > processing_delta {
            if worst.net_is_nat {
                Blame::IspNetwork
            } else {
                Blame::LastMile
            }
        } else {
            Blame::HostStack
        }
    } else {
        if endhost_delta > processing_delta {
            Blame::HomeNetwork
        } else {
            Blame::HostStack
        }
    };
    use Goodness::*;
    let goodness = match application_latency.max - application_latency.avg {
        x if x < 0.10 => VeryGood,
        x if x < 0.25 => Good,
        x if x < 0.75 => Meh,
        x if x < 1.5 => Bad,
        _ => VeryBad,
    };
    insights.push(AnalysisInsights::LatencySpikeExplaination {
        typical,
        worst,
        net_delta,
        endhost_delta,
        processing_delta,
        goodness,
        blame,
    });
    insights
}

/**
 * Go throgh the specied probe report and extract the relevant latencies
 */
fn extract_latencies(
    connection: &Connection,
    probe_round: u32,
    app_rtt: f64,
) -> ProbeReportLatencies {
    let mut nat_rtt = None;
    let mut last_hop_rtt = None;
    let mut endhost_rtts = Vec::new();
    let report = connection
        .probe_report_summary
        .raw_reports
        .get(probe_round as usize)
        .unwrap();
    for ttl in report.probes.keys().sorted() {
        let probe = report.probes.get(ttl).unwrap();
        use ProbeReportEntry::*;
        match probe {
            RouterReplyFound { rtt_ms, .. } => last_hop_rtt = Some(rtt_ms),
            NatReplyFound { rtt_ms, .. } => nat_rtt = Some(rtt_ms),
            EndHostReplyFound { rtt_ms, .. } => endhost_rtts.push(rtt_ms),
            NoReply { .. }
            | NoOutgoing { .. }
            | RouterReplyNoProbe { .. }
            | NatReplyNoProbe { .. }
            | EndHostNoProbe { .. } => (),
        }
    }
    let mut endhost_sum = 0.0;
    let mut endhost_max = f64::MIN;
    for endhost_rtt in &endhost_rtts {
        endhost_sum += **endhost_rtt;
        if endhost_max < **endhost_rtt {
            endhost_max = **endhost_rtt;
        }
    }
    let endhost_avg = if endhost_rtts.len() > 0 {
        endhost_sum / endhost_rtts.len() as f64
    } else {
        // complete packet loss!?  what should we do?  Return a large constant for now
        1000.0 // 1 second!
    };

    let (net_is_nat, net_rtt) = if let Some(nat_rtt) = nat_rtt {
        (true, *nat_rtt)
    } else if let Some(last_hop) = last_hop_rtt {
        (false, *last_hop)
    } else {
        (false, 0.0)
    };
    let percent_net = net_rtt / app_rtt;
    let percent_endhost = endhost_avg / app_rtt;
    // this calc could be negative if, e.g., the kernel delayed replying to the endhost ping
    let processing_delay = app_rtt - endhost_avg;
    let percent_processing = (processing_delay / app_rtt).max(0.0);
    ProbeReportLatencies {
        net_rtt,
        net_is_nat,
        endhost_avg,
        endhost_max,
        app_rtt,
        percent_net,
        percent_endhost,
        percent_processing,
        processing_delay,
        probe_round,
    }
}

/**
 * The Naive latency analysis doesn't try to correlate the application latency with the endhost/network latencies
 * and so it doesn't really "explain what happened", but rather provides a stasticial summary.
 */

fn naive_latency_analysis(connection: &Connection) -> Vec<AnalysisInsights> {
    let mut latency_insights = Vec::new();
    let mut out_drop_count = 0;
    let mut last_router: Option<ProbeReportSummaryNode> = None;
    let mut nat: Option<ProbeReportSummaryNode> = None;
    // TODO: track which ttl the endhost replies first come at
    let mut endhosts = Vec::new();

    for ttl in connection.probe_report_summary.summary.keys().sorted() {
        let nodes = connection.probe_report_summary.summary.get(ttl).unwrap();
        use ProbeReportEntry::*;
        for node in nodes {
            match node.probe_type {
                // MAGIC!  match on ".." instead of all of the struct members!
                RouterReplyFound { .. } => last_router = Some(node.clone()),
                NatReplyFound { .. } => nat = Some(node.clone()),
                NoReply { .. } => (), // TODO: account for these some useful way
                // Count any kind of missing NoProbe as an egress drop - silly pcap
                EndHostNoProbe { .. }
                | NoOutgoing { .. }
                | RouterReplyNoProbe { .. }
                | NatReplyNoProbe { .. } => out_drop_count += node.rtts.len(),
                EndHostReplyFound { .. } => endhosts.push(node.clone()),
            }
        }
    }

    if out_drop_count > 0 {
        // we send ProbeMaxTTL * MaxRounds (currently 32 * 100) probes
        let goodness = if out_drop_count < 10 {
            Goodness::Meh
        } else if out_drop_count < 100 {
            Goodness::Bad
        } else {
            Goodness::VeryBad
        };
        latency_insights.push(AnalysisInsights::MissingOutgoingProbes {
            out_drop_count,
            goodness,
        });
    }

    if endhosts.len() > 0 {
        // calc some quick stats across all of the endhost probes (likely across many TTLs)
        let mut endhost_min = f64::MAX;
        let mut endhost_max = f64::MIN;
        let mut sum = 0.0;
        let mut count = 0.0;
        for endhost in endhosts {
            count += endhost.rtts.len() as f64;
            for rtt in endhost.rtts {
                if rtt < endhost_min {
                    endhost_min = rtt;
                }
                if rtt > endhost_max {
                    endhost_max = rtt;
                }
                sum += rtt;
            }
        }
        let endhost_avg = sum / count;
        latency_insights.append(&mut analyze_application_latency(
            connection,
            endhost_avg,
            endhost_max,
        ));
        if let Some(nat) = nat {
            // Good news - we found a NAT device so we can be reasonably certain that's near the EndHost
            // How true is this assumption?
            let (_nat_min, nat_avg, nat_max) = nat.stats().unwrap(); // unwrap ok for Nat's
            if nat_avg > endhost_avg || nat_max > endhost_max {
                // weird data - this shouldn't ever be the case and likely indicates some sort of
                // systematic measurement error, e.g., bad clocks
                latency_insights.push(AnalysisInsights::LatencyNatWeirdData {
                    nat_avg,
                    endhost_avg,
                    nat_max,
                    endhost_max,
                });
            } else {
                // a lot of work to get to some clean data!
                let last_hop_avg = endhost_avg - nat_avg;
                let last_hop_max = endhost_max - nat_max;
                let last_hop_avg_fraction = last_hop_avg / nat_avg;
                let last_hop_max_fraction = last_hop_max / nat_max;
                // boundaries are somewhat arbitrary ... but IMHO defensible
                let goodness = match last_hop_max_fraction {
                    x if x < 0.1 => Goodness::VeryGood,
                    x if x < 0.4 => Goodness::Good,
                    x if x < 0.8 => Goodness::Meh,
                    x if x < 1.5 => Goodness::Bad,
                    _ => Goodness::VeryBad, // last hop max is 150+% more than rest of network
                };
                latency_insights.push(AnalysisInsights::LastHopNatLatencyVariance {
                    goodness,
                    last_hop_avg,
                    last_hop_max,
                    last_hop_avg_fraction,
                    last_hop_max_fraction,
                    endhost_avg,
                    endhost_max,
                });
            }
        } else {
            if let Some(router) = last_router {
                // if we can't find a NAT, use the last router we got as a reference; it's not
                // as accurate but hopefully one day we can validate this with geolocation
                // e.g., if the latitude and longitudes of the endhost and routers are not too far apart
                let (_router_min, router_avg, router_max) = router.stats().unwrap(); // unwrap ok for Router's
                if router_avg > endhost_avg || router_max > endhost_max {
                    // weird data - this shouldn't ever be the case and likely indicates some sort of
                    // systematic measurement error, e.g., bad clocks
                    latency_insights.push(AnalysisInsights::LatencyRouterWeirdData {
                        router_avg,
                        endhost_avg,
                        router_max,
                        endhost_max,
                    });
                } else {
                    // a lot of work to get to some clean data!
                    //
                    let last_hop_avg = endhost_avg - router_avg;
                    let last_hop_max = endhost_max - router_max;
                    let last_hop_avg_fraction = last_hop_avg / router_avg;
                    let last_hop_max_fraction = last_hop_max / router_max;
                    // boundaries are somewhat arbitrary ... but IMHO defensible
                    // relative to a NAT, should probably increase them but.. how much?
                    // leave the same for now...
                    let goodness = match last_hop_max_fraction {
                        x if x < 0.1 => Goodness::VeryGood,
                        x if x < 0.4 => Goodness::Good,
                        x if x < 0.8 => Goodness::Meh,
                        x if x < 1.5 => Goodness::Bad,
                        _ => Goodness::VeryBad, // last hop max is 150+% more than rest of network
                    };
                    latency_insights.push(AnalysisInsights::LastHopRouterLatencyVariance {
                        goodness,
                        last_hop_avg,
                        last_hop_max,
                        last_hop_avg_fraction,
                        last_hop_max_fraction,
                        endhost_avg,
                        endhost_max,
                    });
                }
            } else {
                latency_insights.push(AnalysisInsights::NoRouterReplies);
            }
        }
    } else {
        // no endhost probes - like at all?!
        latency_insights.push(AnalysisInsights::NoEndhostReplies);
    }

    latency_insights
}

fn analyze_application_latency(
    connection: &Connection,
    endhost_avg: f64,
    endhost_max: f64,
) -> Vec<AnalysisInsights> {
    let mut insights = Vec::new();
    let application_latency = compute_application_latency(connection, None);
    let application_avg = application_latency.avg;
    let application_max = application_latency.max;
    let delta_avg = application_avg - endhost_avg;
    let delta_max = application_max - endhost_max;
    if endhost_avg > application_latency.avg || endhost_max > application_latency.max {
        insights.push(AnalysisInsights::ApplicationLatencyWeirdVariance {
            endhost_avg,
            endhost_max,
            application_avg,
            application_max,
            delta_avg,
            delta_max,
        });
    } else {
        let fraction_avg = delta_avg / application_avg;
        let fraction_max = delta_max / application_max;
        // what fraction of end2end latency should be due to in-host processing?
        use Goodness::*;
        let goodness = match fraction_max {
            x if x < 0.05 => VeryGood,
            x if x < 0.10 => Good,
            x if x < 0.40 => Meh,
            x if x < 0.7 => Bad,
            _ => VeryBad, // worse than 70% of end2end latency makes this VeryBad
        };
        insights.push(AnalysisInsights::ApplicationLatencyVariance {
            endhost_avg,
            endhost_max,
            application_avg,
            application_max,
            delta_avg,
            delta_max,
            fraction_avg,
            fraction_max,
            goodness,
        });
    }
    insights
}

pub fn connection_from_log(_file: &str) -> Result<Connection, Box<dyn Error>> {
    //let log = std::fs::read_to_string(file)?;

    //let connection: Connection = serde_json::from_str(&log)?;
    //Ok(connection)
    unimplemented!();
}

#[cfg(test)]
mod test {

    use super::*;
    // FIXME: the log files on disk use a previous version of OwnedParsedPacket (in
    // particular, they still contain a pcap_header field), instead of a broken out
    // timestamp and len field.
    use crate::connection::test::test_dir;
    #[test]
    #[ignore]
    fn validate_latency() {
        let test_log = r"tests/logs/annotated_connection1_localhost.log";
        let connection = connection_from_log(test_dir(test_log).as_str()).unwrap();

        let insights = analyze(&connection);
        assert!(insights
            .iter()
            .find(|i| matches!(i, AnalysisInsights::NoRouterReplies { .. }),)
            .is_some());
    }

    #[test]
    #[ignore]
    fn validate_latency_turkey() {
        let test_log = r"tests/logs/annotated_rob_linux_wifi_turkey.log";
        let connection = connection_from_log(test_dir(test_log).as_str()).unwrap();

        let insights = analyze(&connection);
        let last_hop = insights
            .iter()
            .find(|i| matches!(i, AnalysisInsights::LastHopNatLatencyVariance { .. }));
        assert!(last_hop.is_some());
        use AnalysisInsights::*;
        if let Some(LastHopNatLatencyVariance { goodness, .. }) = last_hop {
            assert_eq!(*goodness, Goodness::Meh);
        }
    }

    #[test]
    #[ignore]
    fn validate_macos() {
        let test_log = r"tests/logs/annotated_macos_gregor.log";
        let connection = connection_from_log(test_dir(test_log).as_str()).unwrap();

        assert!(connection.user_agent.is_some());

        let user_agent = connection.user_agent.as_deref().unwrap();

        assert!(user_agent.contains("Mac OS X"));

        let insights = analyze(&connection);
        let last_hop = insights
            .iter()
            .find(|i| matches!(i, AnalysisInsights::LastHopNatLatencyVariance { .. }));
        assert!(last_hop.is_some());
        use AnalysisInsights::*;
        if let Some(LastHopNatLatencyVariance { goodness, .. }) = last_hop {
            assert_eq!(*goodness, Goodness::Good);
        }
    }

    #[test]
    #[ignore]
    fn validate_latency_spike() {
        // super useful for manually exploring the data:
        // jq '.probe_report_summary.raw_reports[].application_rtt'  webserver/tests/logs/annotated_macos1.log  | sort -n | less

        /*
         * Also:
         *
         * for i in `seq 100`; do
         *  ./target/debug/netdebug_cli \
         *          --print-probe-report $i \
         *          --analyze-log ./webserver/tests/logs/annotated_macos_ed.log | grep appl ; done | sort -n -k 9
         */
        let test_log = r"tests/logs/annotated_macos_gregor.log";
        let connection = connection_from_log(test_dir(test_log).as_str()).unwrap();

        let insights = analyze(&connection);
        let spike = insights
            .iter()
            .find(|i| matches!(i, AnalysisInsights::LatencySpikeExplaination { .. }));
        assert!(spike.is_some());
        use AnalysisInsights::*;
        if let Some(LatencySpikeExplaination {
            goodness, blame, ..
        }) = spike
        {
            assert_eq!(*goodness, Goodness::VeryBad);
            assert_eq!(*blame, Blame::LastMile);
        } else {
            panic!("Failed to destructure LatencySpike")
        }
    }
}
