use chrono::Duration;
use desktop_common::GuiToServerMessages;
use libconntrack_wasm::aggregate_counters::{AggregateCounter, AggregateCounterKind};
use web_sys::WebSocket;

use crate::tabs::{Tab, Tabs};
use crate::{console_log, log};

pub const BANDWIDTH_GRAPH_TAB: &str = "bandwidth_graph";

#[allow(unused)]
pub struct BandwidthGraph {
    min_request_interval: Duration,
    last_request_sent: f64,
    last_aggregate_counters: Vec<AggregateCounter>,
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
                min_request_interval: Duration::milliseconds(50),
                last_request_sent: 0.0,
                last_aggregate_counters: Vec::new(),
            })),
        }
    }

    pub fn on_activate(tab: &mut Tab, ws: WebSocket) {
        let window = web_sys::window().expect("window");
        let d = window.document().expect("document");
        let content = d
            .get_element_by_id(crate::tabs::TAB_CONTENT)
            .expect("tab content div");
        content.set_inner_html("TODO"); // TODO!

        let bandwidth_graph = tab
            .get_tab_data::<BandwidthGraph>()
            .expect("No BandwidthGraph data!?");

        bandwidth_graph.last_request_sent = window.performance().expect("performance").now();

        send_aggregate_request(
            ws,
            AggregateCounterKind::ConnectionTracker,
            "ConnectionTracker".to_string(),
        );
    }

    pub fn on_deactivate(_tab: &mut Tab, _ws: WebSocket) {
        // NOOP, for now
    }
}

fn send_aggregate_request(ws: WebSocket, kind: AggregateCounterKind, name: String) {
    // send one message immediately to get us started
    let msg = GuiToServerMessages::DumpAggregateCounters { kind, name };
    if let Err(e) = ws.send_with_str(&serde_json::to_string(&msg).unwrap()) {
        console_log!("Error talking to server: {:?}", e);
    }
}

#[allow(unused)] // TODO: will fix in next patch
pub(crate) fn handle_aggregate_counters(
    counters: Vec<AggregateCounter>,
    ws: WebSocket,
    tabs: Tabs,
) -> Result<(), wasm_bindgen::JsValue> {
    if tabs.lock().unwrap().get_active_tab_name() != BANDWIDTH_GRAPH_TAB {
        return Ok(()); // ignore this message when this tab isn't active
    }
    console_log!("Got a AggregateCounters reply, sending another");
    // TODO - rate limit how fast these are sent
    send_aggregate_request(
        ws,
        AggregateCounterKind::ConnectionTracker,
        "ConnectionTracker".to_string(),
    );
    Ok(())
}
