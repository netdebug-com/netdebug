use desktop_common::GuiToServerMessages;
use libconntrack_wasm::aggregate_counters::AggregateCounterConnectionTracker;
use std::collections::HashMap;
use std::time::Duration;
use wasm_bindgen::prelude::Closure;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{window, MessageEvent, WebSocket};

use crate::tabs::{Tab, Tabs};
use crate::{console_log, html, log, plot_json_chart, plot_json_chart_update};

pub const BANDWIDTH_GRAPH_TAB: &str = "bandwidth_graph";
pub const CANVAS_MILLIS: &str = "CANVAS_millis";
pub const CANVAS_SECONDS: &str = "CANVAS_seconds";
pub const CANVAS_MINUTES: &str = "CANVAS_minutes";

pub struct BandwidthGraph {
    min_request_interval: Duration,
    last_request_sent: f64,
    rendered_charts: HashMap<String, JsValue>, // map the Chart Label to the Chart Object, if rendered
}

impl BandwidthGraph {
    pub(crate) fn new() -> Tab {
        Tab {
            name: BANDWIDTH_GRAPH_TAB.to_string(),
            text: "Bandwidth".to_string(),
            on_activate: Some(|tab, _tabs, ws| {
                BandwidthGraph::on_activate(tab, ws);
            }),
            on_deactivate: Some(|tab, _tabs, ws| {
                BandwidthGraph::on_deactivate(tab, ws);
            }),
            data: Some(Box::new(BandwidthGraph {
                min_request_interval: Duration::from_millis(50),
                last_request_sent: 0.0,
                rendered_charts: HashMap::new(),
            })),
        }
    }

    pub fn on_activate(tab: &mut Tab, ws: WebSocket) {
        let window = web_sys::window().expect("window");
        let d = window.document().expect("document");
        let content = d
            .get_element_by_id(crate::tabs::TAB_CONTENT)
            .expect("tab content div");
        content.set_inner_html("");
        // Create three canvas's, one for each of the milliseconds, seconds, minutes view
        for canvas_id in [CANVAS_MILLIS, CANVAS_SECONDS, CANVAS_MINUTES] {
            let canvas = html!("canvas", {"id" => canvas_id, "height" => "30%"}).unwrap();
            content.append_child(&canvas).unwrap();
        }

        let bandwidth_graph = tab
            .get_tab_data::<BandwidthGraph>()
            .expect("No BandwidthGraph data!?");

        bandwidth_graph.last_request_sent = window.performance().expect("performance").now();
        bandwidth_graph.rendered_charts = HashMap::new();

        send_aggregate_request_now(ws);
    }

    pub fn on_deactivate(_tab: &mut Tab, _ws: WebSocket) {
        // NOOP, for now
    }
}

fn send_aggregate_request_now(ws: WebSocket) {
    let msg = GuiToServerMessages::DumpAggregateCounters {};
    if let Err(e) = ws.send_with_str(&serde_json::to_string(&msg).unwrap()) {
        console_log!("Error talking to server: {:?}", e);
    }
}

/**
 * Either send a request immediately if more than min_interval time has passed,
 * or queue up a delayed send until the right amount of time has passed to avoid
 * sending a high rate of requests.
 */

fn send_aggregate_request(ws: WebSocket, last_sent_ms: f64, min_interval: Duration, tabs: Tabs) {
    let now = window()
        .expect("window")
        .performance()
        .expect("performance")
        .now();
    if (now - last_sent_ms) > min_interval.as_millis() as f64 {
        // send right away if it's been long enough
        send_aggregate_request_now(ws);
    } else {
        // delayed sent
        let delay_ms = (min_interval.as_millis() - (now - last_sent_ms) as u128) as i32;
        assert!(delay_ms > 0);
        let ws_clone = ws.clone();
        let delayed_send = Closure::<dyn FnMut(_)>::new(move |_e: MessageEvent| {
            let mut tabs_lock = tabs.lock().unwrap();
            // only do this if the bandwidth tab is still active
            if tabs_lock.get_active_tab_name() == BANDWIDTH_GRAPH_TAB {
                let now = window()
                    .expect("window")
                    .performance()
                    .expect("performance")
                    .now();
                let bandwidth_graph = tabs_lock.get_active_tab_data::<BandwidthGraph>().unwrap();
                bandwidth_graph.last_request_sent = now;
                send_aggregate_request_now(ws_clone.clone())
            }
        });
        let window = window().expect("window");
        match window.set_timeout_with_callback_and_timeout_and_arguments_0(
            delayed_send.as_ref().unchecked_ref(),
            delay_ms,
        ) {
            Ok(_timeout_id) => (), // don't track it to cancel
            Err(e) => console_log!("Weird: got {:?} trying to set window.set_timeout()", e),
        }
        delayed_send.forget(); // critical magic to make RUST not free() this
    }
}

pub(crate) fn handle_aggregate_counters(
    counters: AggregateCounterConnectionTracker,
    ws: WebSocket,
    tabs: Tabs,
) -> Result<(), wasm_bindgen::JsValue> {
    let (last_request_sent, min_interval, rendered_chart) = {
        // don't hold to the lock longer than we need
        let mut lock = tabs.lock().unwrap();
        if lock.get_active_tab_name() != BANDWIDTH_GRAPH_TAB {
            return Ok(()); // ignore this message when this tab isn't active
        }
        let bandwidth_graph = lock.get_active_tab_data::<BandwidthGraph>().unwrap();
        (
            bandwidth_graph.last_request_sent,
            bandwidth_graph.min_request_interval,
            bandwidth_graph.rendered_charts.clone(),
        )
    };
    console_log!("Got a AggregateCounters reply, sending another");
    // Only send a new request after we've received a reply from the old one (i.e., this function)
    send_aggregate_request(ws, last_request_sent, min_interval, tabs.clone());
    // assume the send and recv counters track the same Durations + num_buckets
    for ts_label in counters.send.counts.keys() {
        let duration = counters
            .send
            .counts
            .get(ts_label)
            .unwrap()
            .bucket_time_window;
        /*
         * This math seems annoying to get right so I'm writing the derivation here:
         *
         * Convert bytes/bucket (which are variable length in time) to mega-bits/second
         * e.g., with a sum of 'x' and a bucket size of 'd' seconds, the following conversion applies:
         *  (x bytes/bucket) * (bucket/d seconds) --> (x/d bytes/second)
         *  (x/d bytes/second) * (8 bits/byte) --> (8x/d bits/second)
         *  (8x/d bits/second) * (Megabit/1e6 bits) --> (8x/1e6d megabits/second)
         *
         *  Factoring out a 'y_scale' means normalized = x/y_scale and
         *  y_scale = 1e6*d/8 for d in seconds and
         *  y_scale = 1e3*d/8 for d in milliseconds
         *
         */
        let (units, units_per_bucket, y_scale, canvas_id) = match &duration {
            // Sigh - one day we'll do micro-second level precision --- just not today :-)
            // x  if *x < Duration::from_millis(1) => ("Micro-seconds", duration.as_micros()),
            x if *x < Duration::from_secs(1) => (
                "Millis",
                duration.as_millis(),
                1e3 * duration.as_millis() as f64 / 8.0,
                CANVAS_MILLIS,
            ),
            x if *x < Duration::from_secs(60) => (
                "Seconds",
                duration.as_secs() as u128,
                1e6 * duration.as_secs() as f64 / 8.0,
                CANVAS_SECONDS,
            ),
            x if *x >= Duration::from_secs(60) => (
                "Minutes",
                duration.as_secs() as u128,
                1e6 * duration.as_secs() as f64 / 8.0,
                CANVAS_MINUTES,
            ),
            _ => todo!("Unknown Duration !!",),
        };
        // format the data for chart.js
        let rx_data: Vec<serde_json::Value> = counters
            .recv
            .counts
            .get(ts_label)
            .expect("RX and TX to have same durations")
            .buckets
            .iter()
            .enumerate()
            .map(|(bucket_index, b)| {
                serde_json::json!({
                    "y": b.sum as f64/ y_scale,
                    "x": bucket_index * units_per_bucket as usize
                })
            })
            .collect();
        let tx_data: Vec<serde_json::Value> = counters
            .send
            .counts
            .get(ts_label)
            .expect("RX and TX to have same durations")
            .buckets
            .iter()
            .enumerate()
            .map(|(bucket_index, b)| {
                serde_json::json!({
                    "y": b.sum as f64 / y_scale,
                    "x": bucket_index * units_per_bucket as usize
                })
            })
            .collect();
        let datasets = vec![
            serde_json::json!({
                "label": "Download Bandwidth",
                "data": rx_data,
            }),
            serde_json::json!({
                "label": "Upload Bandwidth",
                "data": tx_data,
            }),
        ];

        if let Some(chart) = rendered_chart.get(ts_label) {
            // just update the existing chart with the new data
            plot_json_chart_update(
                chart.clone(),
                serde_json::to_string(&datasets).unwrap().as_str(),
                false,
            )
        } else {
            // create a new chart from scratch
            let chart_json = serde_json::to_string(&serde_json::json!({
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
                                "text" : format!("{} ({})", ts_label, units).as_str(),
                            }
                        },
                        "y": {
                            "title": {
                                "display": true,
                                "text": "Mbits/s",
                            }
                        }
                    }
                }
            }))
            .unwrap();
            let new_chart = plot_json_chart(canvas_id, chart_json.as_str(), false);
            // store a pointer to the new chart back in the shared state
            tabs.lock()
                .unwrap()
                .get_tab_data::<BandwidthGraph>(BANDWIDTH_GRAPH_TAB.to_string())
                .unwrap()
                .rendered_charts
                .insert(ts_label.clone(), new_chart);
        }
    }

    Ok(())
}
