mod bandwidth_graph;
mod dns_tracker;
mod flow_tracker;
mod tabs;
mod utils;
use std::{sync::Arc, time::Duration};

use bandwidth_graph::BandwidthGraph;
use dns_tracker::DnsTracker;
use flow_tracker::FlowTracker;
use tabs::{Tab, Tabs, TabsContext};
use web_sys::{MessageEvent, WebSocket};

use wasm_bindgen::prelude::*;
macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

pub(crate) use console_log;

use crate::utils::sleep; // this allows other modules to use console_log!()

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);
}

#[wasm_bindgen(module = "/js/utils.js")]
extern "C" {
    // populate the cfg JsValue with a ChartConfig struct to JSON
    fn plot_chart(element_id: &str, cfg: JsValue, verbose: bool) -> JsValue;
    // Above is a PITA to get working, just pass the JSON as a string
    pub fn plot_json_chart(s: &str, json: &str, verbose: bool) -> JsValue;
    pub fn plot_json_chart_update(chat: JsValue, data_json: &str, verbose: bool);
}

fn create_websocket() -> Result<WebSocket, JsValue> {
    let location = web_sys::window().expect("web_sys::window()").location();
    // connect back to server with same host + port and select wss vs. ws
    let proto = match location.protocol()?.as_str() {
        "https:" => "wss",
        "http:" => "ws",
        _ => {
            console_log!(
                "Weird location.protocol(): - {} - default to wss://",
                location.protocol().unwrap()
            );
            "wss"
        } // default to more secure wss
    };
    let url = format!("{}://{}/ws", proto, location.host()?);
    let ws = WebSocket::new(url.as_str())?;
    Ok(ws)
}

fn init_tabs(ws: WebSocket) -> Result<Tabs, JsValue> {
    // throw together some test tabs
    let test_tabs: Vec<Tab> = ["alpha", "beta", "gamma"]
        .into_iter()
        .map(|t| Tab {
            name: t.to_string(),
            text: t.to_string(),
            on_activate: Some(move |tab, _tabs, _ws| {
                let d = web_sys::window()
                    .expect("window")
                    .document()
                    .expect("document");
                let content = d
                    .get_element_by_id(tabs::TAB_CONTENT)
                    .expect("tab content div");
                content.set_inner_html(format!("Content for the {} tab", tab.name).as_str());
            }),
            on_deactivate: None,
            data: None,
        })
        .collect();
    let mut tabs = Vec::new();
    tabs.push(BandwidthGraph::new());
    tabs.push(FlowTracker::new());
    tabs.push(DnsTracker::new());
    tabs.extend(test_tabs);
    let tabs = Arc::new(std::sync::Mutex::new(TabsContext::new(
        tabs,
        flow_tracker::FLOW_TRACKER_TAB.to_string(),
    )));
    let tabs_clone = tabs.clone();
    tabs.lock().unwrap().construct(tabs_clone, ws.clone())?;
    Ok(tabs)
}

/**
 * Handle a message from the server, from the websocket
 */

fn handle_ws_message(e: MessageEvent, ws: WebSocket, tabs: Tabs) -> Result<(), JsValue> {
    let raw_msg = e.data().as_string().unwrap();
    match serde_json::from_str(raw_msg.as_str()) {
        Ok(msg) => {
            use desktop_common::ServerToGuiMessages::*;
            match msg {
                VersionCheck(ver) => handle_version_check(ver),
                DumpFlowsReply(flows) => {
                    flow_tracker::handle_dumpflows_reply(flows, ws.clone(), tabs.clone())
                }
                DumpDnsCache(cache) => dns_tracker::handle_dump_dns_cache_reply(cache, ws, tabs),
                DumpAggregateCountersReply(counters) => {
                    bandwidth_graph::handle_aggregate_counters(counters, ws, tabs)
                }
            }
        }
        Err(e) => {
            console_log!("Got unparsable message from server: {} :: '{}'", e, raw_msg);
            Ok(())
        }
    }
}
/**
 * Are the server and GUI running from the same code base?
 * This can get out of sync if the server needs to reload
 */

fn handle_version_check(ver: String) -> Result<(), JsValue> {
    if ver == desktop_common::get_git_hash_version() {
        console_log!("Both GUI and desktop are running version: {}", ver);
    } else {
        console_log!(
            "GUI is running version {} but desktop is {}!! Reload!",
            desktop_common::get_git_hash_version(),
            ver
        );
        // TODO: make this cleaner/less scary for the user - maybe an alert?
        // reload the page
        web_sys::window().expect("window").location().reload()?;
    }
    Ok(())
}

#[wasm_bindgen(start)]
pub async fn run() -> Result<(), JsValue> {
    utils::set_panic_hook();
    let ws = create_websocket()?;
    // wait until the socket is fully connected before we finish out init
    while ws.ready_state() == 0 {
        console_log!(
            "Waiting for websocket to finish connecting: current state is {}",
            ws.ready_state()
        );
        sleep(Duration::from_millis(10)).await?;
    }
    let tabs = init_tabs(ws.clone())?;

    // Need both tabs and ws to launch the rx closure
    let ws_clone = ws.clone();
    let tabs_clone = tabs.clone();
    let onmessage_callback = Closure::<dyn FnMut(_)>::new(move |e: MessageEvent| {
        // double clone needed to match function prototypes - apparently(!?)
        if let Err(js_value) = handle_ws_message(e, ws_clone.clone(), tabs_clone.clone()) {
            // TODO: reload whole document on JsValue("need to reload")
            console_log!("Error! {:?}", js_value);
        }
    });

    ws.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
    onmessage_callback.forget(); // MAGIC: tell rust not to deallocate this!

    console_log!("working!?");
    Ok(())
}
