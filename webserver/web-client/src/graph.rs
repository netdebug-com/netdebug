use std::{collections::HashMap, vec};

use common::{ProbeReportEntry, ProbeReportSummary, ProbeRoundReport};
use itertools::Itertools;
use sorted_vec::SortedVec;
use wasm_bindgen::JsValue;

use crate::consts::*;
use crate::tabs::calc_height;
use crate::{
    console_log, log, lookup_by_id, plot_json_chart, plot_json_chart_update, plot_latency_chart,
};

#[derive(Debug, PartialEq, PartialOrd)]
pub struct PingData {
    pub rtt: f64,
    pub time_stamp: f64,
}

// b/c we're based on f64 and float semantics are crazy,
// we have to implement our own Eq and Ord implementations
// these are technically Wrong (e.g., NaN is technically != NaN)
// but good enough for our purposes
impl Eq for PingData {}

impl Ord for PingData {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rtt.total_cmp(&other.rtt)
    }
}

pub struct Graph {
    data_server: SortedVec<PingData>,
    data_client: SortedVec<PingData>,
    data_probes: HashMap<String, SortedVec<PingData>>,
    data_points_per_draw: usize,
    canvas: String,
    autoscale_max: f64,
    probe_report_summary: ProbeReportSummary,
    max_rounds: Option<u32>,
    chart: Option<JsValue>,
}

impl Graph {
    pub fn new(data_points_per_draw: usize, canvas: String) -> Graph {
        Graph {
            data_server: SortedVec::new(),
            data_client: SortedVec::new(),
            data_probes: HashMap::new(),
            data_points_per_draw,
            canvas,
            probe_report_summary: ProbeReportSummary::new(),
            autoscale_max: f64::MIN,
            max_rounds: None,
            chart: None,
        }
    }

    pub fn add_data(&mut self, server_rtt: f64, client_rtt: f64, time_stamp: f64) {
        if self.autoscale_max < server_rtt {
            self.autoscale_max = server_rtt;
        }
        if self.autoscale_max < client_rtt {
            self.autoscale_max = client_rtt;
        }
        self.data_server.push(PingData {
            rtt: server_rtt,
            time_stamp,
        });
        self.data_client.push(PingData {
            rtt: client_rtt,
            time_stamp,
        });

        // did we get enough data to be worth redrawing the graph?
        if self.data_server.len() % self.data_points_per_draw == 0 {
            self.draw();
        }
    }

    /**
     * Copy in the data from the probe reports
     *
     * NOTE: because we're decoupling the probe report data from the application
     * data and sorting them independently, it's not the case that the data lines
     * up in time, e.g., the p75 of the application data and the p75 of the probe report
     * data may not occur at the same time
     */

    pub fn add_data_probe_report(&mut self, probe_report: ProbeRoundReport, probe_round: u32) {
        for (_ttl, probe) in &probe_report.probes {
            // extract a name for the hop (e.g. "TTL=x" or "NAT") plus rtt, etc. info
            if let Some((key, rtt, ts)) = match probe {
                ProbeReportEntry::RouterReplyFound {
                    ttl,
                    out_timestamp_ms,
                    rtt_ms,
                    src_ip: _,
                    comment: _,
                } => Some((format!("ttl={}", ttl), rtt_ms, out_timestamp_ms)),
                ProbeReportEntry::NatReplyFound {
                    ttl: _,
                    out_timestamp_ms,
                    rtt_ms,
                    src_ip: _,
                    comment: _,
                } => Some(("NAT".to_string(), rtt_ms, out_timestamp_ms)),
                ProbeReportEntry::EndHostReplyFound {
                    ttl: _,
                    out_timestamp_ms,
                    rtt_ms,
                    comment: _,
                } => Some(("EndHost".to_string(), rtt_ms, out_timestamp_ms)),
                ProbeReportEntry::NoReply {
                    ttl: _,
                    out_timestamp_ms: _,
                    comment: _,
                }
                | ProbeReportEntry::NoOutgoing { ttl: _, comment: _ }
                | ProbeReportEntry::RouterReplyNoProbe {
                    ttl: _,
                    in_timestamp_ms: _,
                    src_ip: _,
                    comment: _,
                }
                | ProbeReportEntry::NatReplyNoProbe {
                    ttl: _,
                    in_timestamp_ms: _,
                    src_ip: _,
                    comment: _,
                }
                | ProbeReportEntry::EndHostNoProbe {
                    ttl: _,
                    in_timestamp_ms: _,
                    comment: _,
                } => None,
            } {
                let d = PingData {
                    rtt: *rtt,
                    time_stamp: *ts,
                };
                if let Some(probes) = self.data_probes.get_mut(&key) {
                    probes.push(d);
                } else {
                    self.data_probes.insert(key, SortedVec::from(vec![d]));
                }
            }
        }
        self.probe_report_summary.update(probe_report);
        if let Some(max_rounds) = self.max_rounds {
            if max_rounds <= probe_round {
                // got all of the probe reports!
                self.update_probe_report_summaries();
            }
        } else {
            console_log!("Weird: called Graph::add_data_probe_report with a max_rounds");
        }
    }

    fn draw(&mut self) {
        let mut datasets = Vec::new();
        let plot_server: Vec<serde_json::Value> = self
            .data_server
            .iter()
            .enumerate()
            .map(|(idx, ping)| {
                serde_json::json!(
                    {
                        "y": ping.rtt,
                        "x": 100.0 * (idx as f64 + 1.0) / (self.data_client.len() as f64),
                    }
                )
            })
            .collect();
        datasets.push(serde_json::json!({
            "label": "App Latency (from server)",
            "data": plot_server,
        }));
        let plot_client: Vec<serde_json::Value> = self
            .data_client
            .iter()
            .enumerate()
            .map(|(idx, ping)| {
                serde_json::json!(
                    {
                        "y": ping.rtt,
                        "x": 100.0 * (idx as f64 + 1.0) / (self.data_client.len() as f64),
                    }
                )
            })
            .collect();
        datasets.push(serde_json::json!({
            "label": "App Latency (from client)",
            "data": plot_client,
        }));

        for plot_label in self.data_probes.keys().sorted() {
            let probes = self.data_probes.get(plot_label).unwrap();
            let data: Vec<serde_json::Value> = probes
                .iter()
                .enumerate()
                .map(|(idx, ping)| {
                    serde_json::json!({
                        "y": ping.rtt,
                        "x": 100.0 * (idx as f64 + 1.0) / (probes.len() as f64),
                    })
                })
                .collect();

            let ttl_data = serde_json::json!({
                "label": plot_label,
                "data": data,
            });
            datasets.push(ttl_data);
        }

        let json = serde_json::json!({
            "type": "scatter",
            "data": {
                "datasets": datasets,
            },
            "options": {
                "showLine": true,
                "scales": {
                    "x": {
                        "title": {
                            "display": true,
                            "text" : "% < Y (CDF)",
                        }
                    },
                    "y": {
                        "title": {
                            "display": true,
                            "text": "RTT (milliseconds)"
                        }
                    }
                }
            }
        });

        if let Some(chart) = &self.chart {
            // update existing
            let data_json = &json["data"]["datasets"];
            let data_json = serde_json::to_string(&data_json).unwrap();
            plot_json_chart_update(chart.clone(), data_json.as_str(), false);
        } else {
            // create fresh chart the first time
            let json = serde_json::to_string(&json).unwrap();
            self.chart = Some(plot_json_chart(self.canvas.as_str(), json.as_str(), true));
        }
    }

    pub fn set_max_rounds(&mut self, max_rounds: u32) {
        if self.max_rounds.is_none() {
            self.max_rounds = Some(max_rounds);
            let progress = lookup_by_id(PROGRESS_METER).expect("No progress meter!?");
            progress
                .set_attribute("max", format!("{}", max_rounds).as_str())
                .unwrap();
        }
    }

    fn update_probe_report_summaries(&self) {
        console_log!("Got all probes - updating summaries!");
        let probes_div = lookup_by_id(PROBE_TAB).expect("Probes tab not setup!?");
        let window = web_sys::window().expect("no global 'window' exists!?");
        let document = window.document().expect("should have a document on window");
        let pre_formated = document
            .create_element("pre")
            .expect("Failed to create a 'pre'");
        // for now, just use the existing Display format
        pre_formated.set_inner_html(format!("{}", self.probe_report_summary).as_str());
        probes_div.set_inner_html(
            format!("Collected 100% of {} probes", self.max_rounds.unwrap()).as_str(),
        );
        probes_div
            .append_child(&pre_formated)
            .expect("Failed to append pre to div!?");
        // could just continue, but logically different to do a new function
        self.draw_main_latencies_chart();
    }

    /**
     * Try to find the p1, p50, and p99 (e.g., best, typical, and worst)
     * latencies for the NAT, EndHost, and client (e.g., isp, home, and app)
     * data.
     *
     * NOTE: this calculation can compare probes from different periods,e.g.,
     * the 'worst' time for NAT may not be the same wallclock time for Endhost
     */

    fn draw_main_latencies_chart(&self) {
        let best_client_index = 1;
        let typical_client_index = self.data_client.len() / 2;
        let worst_client_index = self.data_client.len() - 1;

        // let best_client_time = self.data_client[best_client_index].time_stamp;
        // let typical_client_time = self.data_client[typical_client_index].time_stamp;
        // let worst_client_time = self.data_client[worst_client_index].time_stamp;
        let best_client_rtt = self.data_client[best_client_index].rtt;
        let typical_client_rtt = self.data_client[typical_client_index].rtt;
        let worst_client_rtt = self.data_client[worst_client_index].rtt;

        // pull data from probe summaries
        let mut nat: Option<(f64, f64, f64)> = None;
        let mut endhost: Option<(f64, f64, f64)> = None;
        for (_ttl, probes) in &self.probe_report_summary.summary {
            // use if let rather than match as there are a lot of different types of ProbeSummaries
            for probe in probes {
                if let ProbeReportEntry::NatReplyFound {
                    ttl: _,
                    out_timestamp_ms: _,
                    rtt_ms: _,
                    src_ip: _,
                    comment: _,
                } = probe.probe_type
                {
                    nat = probe.stats();
                } else if let ProbeReportEntry::EndHostReplyFound {
                    ttl: _,
                    out_timestamp_ms: _,
                    rtt_ms: _,
                    comment: _,
                } = probe.probe_type
                {
                    endhost = probe.stats();
                    break; // just grab the first one for now - lowest in TTL
                }
            }
        }
        let nat = match nat {
            None => {
                console_log!("No NAT Probes found!?");
                (0.0, 0.0, 0.0)
            }
            Some((min, avg, max)) => (min, avg, max),
        };
        let endhost = match endhost {
            None => {
                console_log!("No EndHost Probes found!?");
                (0.0, 0.0, 0.0)
            }
            Some((min, avg, max)) => (min, avg, max),
        };

        // should be no reason to console_log these - just pulling them from ProbeReportSummary which
        // is already logged

        let main_div = lookup_by_id(MAIN_TAB).unwrap();
        let document = web_sys::window().unwrap().document().unwrap();
        let body = document.body().unwrap();
        let canvas = document.create_element("canvas").unwrap();
        canvas.set_id("main_canvas"); // come back if we need manual double buffering
        let (width, height) = calc_height(&document, &body);
        let width = 9 * width / 10;
        let height = 4 * height / 5;
        canvas
            .set_attribute("width", format!("{}", width).as_str())
            .unwrap();
        canvas
            .set_attribute("height", format!("{}", height).as_str())
            .unwrap();

        main_div.set_inner_html("");
        main_div.append_child(&canvas).unwrap();

        // now adjust everything to be relative time and catch when time seems to go backwards due to processing delays
        let best_isp = nat.0;
        let best_home = sane_subtract(endhost.0, nat.0, "best nat processing delay - adjust!");
        let best_app = sane_subtract(
            best_client_rtt,
            endhost.0,
            "best endhost processing delay - adjust!",
        );
        let typical_isp = nat.1;
        let typical_home =
            sane_subtract(endhost.1, nat.1, "typical nat processing delay - adjust!");
        let typical_app = sane_subtract(
            typical_client_rtt,
            endhost.1,
            "typical endhost processing delay - adjust!",
        );
        let worst_isp = nat.2;
        let worst_home = sane_subtract(endhost.2, nat.2, "worst nat processing delay - adjust!");
        let worst_app = sane_subtract(
            worst_client_rtt,
            endhost.2,
            "worst endhost processing delay - adjust!",
        );

        plot_latency_chart(
            "main_canvas",
            best_isp,
            best_home,
            best_app,
            typical_isp,
            typical_home,
            typical_app,
            worst_isp,
            worst_home,
            worst_app,
            false,
        );
    }
}

fn sane_subtract(bigger: f64, smaller: f64, text: &str) -> f64 {
    if bigger > smaller {
        bigger - smaller
    } else {
        console_log!("{}", text);
        0.0
    }
}
