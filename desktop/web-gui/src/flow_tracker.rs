use desktop_common::GuiToServerMessages;
use wasm_bindgen::prelude::Closure;
use wasm_bindgen::JsCast;
use web_sys::{MessageEvent, WebSocket};

use crate::tabs::Tab;
use crate::{console_log, log};

#[derive(Debug, Clone)]
pub struct FlowTracker {
    timeout_id: Option<i32>,
}

pub const FLOW_TRACKER_TAB: &str = "flow_tracker";

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
        content.set_inner_html(format!("Content for the {} tab", tab.name).as_str());
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
            .downcast_mut::<FlowTracker>().expect("no flowtracker data!?");
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
            .downcast_mut::<FlowTracker>().expect("no flowtracker data!?");
        let window = web_sys::window().expect("window");
        if let Some(timeout_id) = flow_tracker.timeout_id {
            // DOM implements no return value for this, so I guess pray() it works!?
            window.clear_interval_with_handle(timeout_id);
            flow_tracker.timeout_id = None;
        }

    }
}
