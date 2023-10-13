use chrono::Duration;
use desktop_common::GuiToServerMessages;
use libconntrack_wasm::aggregate_counters::{AggregateCounter, AggregateCounterKind};
use wasm_bindgen::prelude::Closure;
use wasm_bindgen::JsCast;
use web_sys::{window, MessageEvent, WebSocket};

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

        send_aggregate_request_now(
            ws,
            AggregateCounterKind::ConnectionTracker,
            "ConnectionTracker".to_string(),
        );
    }

    pub fn on_deactivate(_tab: &mut Tab, _ws: WebSocket) {
        // NOOP, for now
    }
}

fn send_aggregate_request_now(ws: WebSocket, kind: AggregateCounterKind, name: String) {
    let msg = GuiToServerMessages::DumpAggregateCounters { kind, name };
    if let Err(e) = ws.send_with_str(&serde_json::to_string(&msg).unwrap()) {
        console_log!("Error talking to server: {:?}", e);
    }
}

/**
 * Either send a request immediately if more than min_interval time has passed,
 * or queue up a delayed send until the right amount of time has passed to avoid
 * sending a high rate of requests.
 */

fn send_aggregate_request(
    ws: WebSocket,
    kind: AggregateCounterKind,
    name: String,
    last_sent_ms: f64,
    min_interval: Duration,
    tabs: Tabs,
) {
    let now = window()
        .expect("window")
        .performance()
        .expect("performance")
        .now();
    if (now - last_sent_ms) > min_interval.num_milliseconds() as f64 {
        // send right away if it's been long enough
        send_aggregate_request_now(ws, kind, name);
    } else {
        // delayed sent
        let delay_ms = (min_interval.num_milliseconds() - (now - last_sent_ms) as i64) as i32;
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
                send_aggregate_request_now(ws_clone.clone(), kind, name.clone())
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

#[allow(unused)] // TODO: will fix in next patch
pub(crate) fn handle_aggregate_counters(
    counters: Vec<AggregateCounter>,
    ws: WebSocket,
    tabs: Tabs,
) -> Result<(), wasm_bindgen::JsValue> {
    let (last_request_sent, min_interval) = {
        // don't hold to the lock longer than we need
        let mut lock = tabs.lock().unwrap();
        if lock.get_active_tab_name() != BANDWIDTH_GRAPH_TAB {
            return Ok(()); // ignore this message when this tab isn't active
        }
        let bandwidth_graph = lock.get_active_tab_data::<BandwidthGraph>().unwrap();
        (
            bandwidth_graph.last_request_sent,
            bandwidth_graph.min_request_interval,
        )
    };
    console_log!("Got a AggregateCounters reply, sending another");
    // Only send a new request after we've received a reply from the old one (i.e., this function)
    send_aggregate_request(
        ws,
        AggregateCounterKind::ConnectionTracker,
        "ConnectionTracker".to_string(),
        last_request_sent,
        min_interval,
        tabs.clone(),
    );
    Ok(())
}
