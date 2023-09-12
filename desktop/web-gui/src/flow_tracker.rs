use chrono::Utc;
use desktop_common::GuiToServerMessages;
use libconntrack_wasm::ConnectionMeasurements;
use wasm_bindgen::prelude::Closure;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{MessageEvent, WebSocket};

use crate::tabs::{Tab, Tabs};
use crate::{console_log, html, log};

#[derive(Debug, Clone)]
pub struct FlowTracker {
    timeout_id: Option<i32>,
}

pub const FLOW_TRACKER_TAB: &str = "flow_tracker";
pub const FLOW_TRACKER_TABLE: &str = "__TABLE_flow_tracker";

impl FlowTracker {
    pub(crate) fn new() -> Tab {
        Tab {
            name: FLOW_TRACKER_TAB.to_string(),
            text: "Flow Tracker".to_string(),
            on_activate: Some(|tab, ws| {
                FlowTracker::on_activate(tab, ws);
            }),
            on_deactivate: Some(|tab, ws| {
                FlowTracker::on_deactivate(tab, ws);
            }),
            data: Some(Box::new(FlowTracker { timeout_id: None })),
        }
    }

    /**
     * Setup a periodic timer to send out DumpFlow messages
     */

    pub fn on_activate(tab: &mut Tab, ws: WebSocket) {
        let d = web_sys::window()
            .expect("window")
            .document()
            .expect("document");
        let content = d.get_element_by_id("tab_content").expect("tab content div");
        content.set_inner_html("");

        let h1 = html!("th").unwrap();
        h1.set_inner_html("Flow #");
        let h2 = html!("th").unwrap();
        h2.set_inner_html("Flow Key");
        let h3 = html!("th").unwrap();
        h3.set_inner_html("Application(s)");
        let h4 = html!("th").unwrap();
        h4.set_inner_html("Lifetime");
        let thead = html!("thead", {}, html!("tr", {}, h1, h2, h3, h4).unwrap()).unwrap();
        let table = html!(
            "table",
            {"class" => "content-table"},
            &thead,
            html!("tbody", { "id" => FLOW_TRACKER_TABLE}).unwrap()
        )
        .expect("table");
        content.append_child(&table).expect("context.append");
        // send one message immediately to get us started
        let msg = GuiToServerMessages::DumpFlows();
        if let Err(e) = ws.send_with_str(&serde_json::to_string(&msg).unwrap()) {
            console_log!("Error talking to server: {:?}", e);
        }
        // and start a timer closure to do every 500ms for periodic updates
        let periodic = Closure::<dyn FnMut(_)>::new(move |_e: MessageEvent| {
            let msg = GuiToServerMessages::DumpFlows();
            if let Err(e) = ws.send_with_str(&serde_json::to_string(&msg).unwrap()) {
                console_log!("Error talking to server: {:?}", e);
            }
        });
        let flow_tracker = tab
            .data
            .as_mut()
            .expect("No flowtracker data!?")
            .downcast_mut::<FlowTracker>()
            .expect("no flowtracker data!?");
        let window = web_sys::window().expect("window");
        match window.set_interval_with_callback_and_timeout_and_arguments_0(
            periodic.as_ref().unchecked_ref(),
            500,
        ) {
            // save the timeout id so we can cancel it later
            Ok(timeout) => flow_tracker.timeout_id = Some(timeout),
            Err(e) => console_log!("Failed to set_timeout() for Flow Tracker!?: {:?}", e),
        }
        periodic.forget();
    }

    /**
     * Cancel the DumpFlows timer when this tab is deactivated
     */
    pub fn on_deactivate(tab: &mut Tab, _ws: WebSocket) {
        let flow_tracker = tab
            .data
            .as_mut()
            .expect("No flowtracker data!?")
            .downcast_mut::<FlowTracker>()
            .expect("no flowtracker data!?");
        let window = web_sys::window().expect("window");
        if let Some(timeout_id) = flow_tracker.timeout_id {
            // DOM implements no return value for this, so I guess pray() it works!?
            window.clear_interval_with_handle(timeout_id);
            flow_tracker.timeout_id = None;
        }
    }
}

pub fn handle_dumpflows_reply(
    mut flows: Vec<ConnectionMeasurements>,
    _ws: WebSocket,
    tabs: Tabs,
) -> Result<(), JsValue> {
    // this message is just for the flow tracker tab; ignore if it's not active
    // note that even when we cancel the timer event for the flow tracker and change the
    // active tab to something else, we could still get this event if we lose the race
    if tabs.lock().unwrap().get_active_tab() != FLOW_TRACKER_TAB {
        return Ok(());
    }
    let d = web_sys::window()
        .expect("window")
        .document()
        .expect("document");
    let tbody = d
        .get_element_by_id(FLOW_TRACKER_TABLE)
        .expect(FLOW_TRACKER_TABLE);
    tbody.set_inner_html(""); // clear the table (??)
    let now = Utc::now();
    flows.sort_by(|a,b| a.start_tracking_time.cmp(&b.start_tracking_time));
    for (idx, measurments) in flows.into_iter().enumerate() {
        let idx_elm = html!("td").unwrap();
        idx_elm.set_inner_html(format!("{}", idx).as_str());
        let flow_elm = html!("td").unwrap();
        let local = if let Some(local) = measurments.local_hostname {
            local
        } else {
            format!("[{}]", measurments.local_ip)
        };
        let remote = if let Some(remote) = measurments.remote_hostname {
            remote
        } else {
            format!("[{}]", measurments.remote_ip)
        };
        flow_elm.set_inner_html(
            format!(
                "{} {}::{} --> {}::{}",
                measurments.ip_proto, local, measurments.local_l4_port, remote, measurments.remote_l4_port
            )
            .as_str(),
        );
        let apps = if !measurments.associated_apps.is_empty() {
            measurments
                .associated_apps
                .iter()
                .map(|(p, a)| {
                    if let Some(name) = a {
                        name.clone()
                    } else {
                        format!("({})", p)
                    }
                })
                .collect::<Vec<String>>()
                .join(", ")
        } else {
            "(unknown!)".to_string()
        };
        let app_elm = html!("td").unwrap();
        app_elm.set_inner_html(&apps);
        let life_elm = html!("td").unwrap();
        let lifetime = now - measurments.start_tracking_time;
        life_elm.set_inner_html(format!("{} seconds", lifetime.num_seconds()).as_str());
        tbody
            .append_child(&html!("tr", {}, idx_elm, flow_elm, app_elm, life_elm).unwrap())
            .unwrap();
    }
    Ok(())
}
