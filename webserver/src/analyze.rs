/***
 * Given a (ideally closed)/finished/fully probed [struct Connect], tell the user as much about
 * it as we can.
 *
 * NOTE: All of this business logic is intentionally kept out of the client code so that it can't
 * be dissassembled/reverse engineered from the client code.
 */

use std::error::Error;

use itertools::Itertools;

use common::{
    analysis_messages::{AnalysisInsights, Goodness},
    ProbeReportEntry, ProbeReportSummaryNode,
};

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

    insights.append(&mut latency_analysis(connection));

    insights
}

#[allow(dead_code)] // we'll probably use these extra fields later
struct ApplicationLatencyAnalysis {
    pub min: f64,
    pub max: f64,
    pub avg: f64,
    pub max_probe_round: u32,
}

fn compute_application_latency(
    connection: &Connection,
) -> Result<ApplicationLatencyAnalysis, Box<dyn Error>> {
    let mut min = f64::MAX;
    let mut max = f64::MIN;
    let mut sum = 0.0;
    let mut max_probe_round = 0;

    for (probe_round, report) in connection
        .probe_report_summary
        .raw_reports
        .iter()
        .enumerate()
    {
        sum += report.application_rtt;
        if min > report.application_rtt {
            min = report.application_rtt;
        }
        if max < report.application_rtt {
            max = report.application_rtt;
            max_probe_round = probe_round as u32;
        }
    }
    let avg = if connection.probe_report_summary.raw_reports.len() > 0 {
        sum / connection.probe_report_summary.raw_reports.len() as f64
    } else {
        0.0 // no data, can't take average
    };
    Ok(ApplicationLatencyAnalysis {
        min,
        max,
        avg,
        max_probe_round,
    })
}

fn latency_analysis(connection: &Connection) -> Vec<AnalysisInsights> {
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
    let application_latency = compute_application_latency(connection).unwrap();
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

pub fn connection_from_log(file: &str) -> Result<Connection, Box<dyn Error>> {
    let log = std::fs::read_to_string(file)?;

    let connection: Connection = serde_json::from_str(&log)?;
    Ok(connection)
}

#[cfg(test)]
mod test {

    use super::*;

    use crate::connection::test::test_dir;
    #[test]
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
    fn validate_macos() {
        let test_log = r"tests/logs/annotated_macos1.log";
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
}
