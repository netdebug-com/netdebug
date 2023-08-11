mod flow_tracker;
mod tabs;
mod utils;
use std::sync::Arc;

use flow_tracker::FlowTracker;
use tabs::{Tab, Tabs, TabsContext};
use web_sys::{MessageEvent, WebSocket};

use wasm_bindgen::prelude::*;
macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

pub(crate) use console_log; // this allows other modules to use console_log!()

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);
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
    let mut tabs: Vec<Tab> = ["alpha", "beta", "gamma"]
        .into_iter()
        .map(|t| Tab {
            name: t.to_string(),
            text: t.to_string(),
            on_activate: Some(move |tab, _ws| {
                let d = web_sys::window()
                    .expect("window")
                    .document()
                    .expect("document");
                let content = d.get_element_by_id("tab_content").expect("tab content div");
                content.set_inner_html(format!("Content for the {} tab", tab.name).as_str());
            }),
            on_deactivate: None,
            data: None,
        })
        .collect();
    tabs.push(FlowTracker::new());
    let tabs = Arc::new(std::sync::Mutex::new(TabsContext::new(
        tabs,
        "alpha".to_string(),
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
    let msg: desktop_common::ServerToGuiMessages = serde_json::from_str(raw_msg.as_str()).unwrap();
    use desktop_common::ServerToGuiMessages::*;
    match msg {
        VersionCheck(ver) => handle_version_check(ver),
        DumpFlowsReply(flows) => handle_dumpflows_reply(flows, ws.clone(), tabs.clone()),
    }
}

fn handle_dumpflows_reply(flows: Vec<String>, _ws: WebSocket, tabs: Tabs) -> Result<(), JsValue> {
    // this is a reply just for the flow tracker tab; ignore if it's not active
    // note that even when we cancel the timer event for the flow tracker and change the
    // active tab to something else, we could still get this event if we lose the race
    if tabs.lock().unwrap().get_active_tab() == flow_tracker::FLOW_TRACKER_TAB {
        // TODO: log as a table
        for flow in flows {
            console_log!("Flow: {}", flow);
        }
    }
    Ok(())
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
pub fn run() -> Result<(), JsValue> {
    utils::set_panic_hook();
    let ws = create_websocket()?;
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
