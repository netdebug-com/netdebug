use std::collections::HashMap;

use desktop_common::GuiToServerMessages;
use itertools::Itertools;
use wasm_bindgen::prelude::Closure;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{Element, MessageEvent, WebSocket};

use crate::tabs::{Tab, Tabs};
use crate::{console_log, html, log};

#[derive(Debug, Clone)]
pub struct StatCounters {
    timeout_id: Option<i32>,
}

pub const STAT_COUNTERS_TAB: &str = "stat_counters";
pub const STAT_COUNTERS_TABLE: &str = "__TABLE_stat_counters";

impl StatCounters {
    pub(crate) fn new() -> Tab {
        Tab {
            name: STAT_COUNTERS_TAB.to_string(),
            text: "Stat Counters".to_string(),
            on_activate: Some(|tab, tabs, ws| {
                StatCounters::on_activate(tab, tabs, ws);
            }),
            on_deactivate: Some(|tab, _tabs, ws| {
                StatCounters::on_deactivate(tab, ws);
            }),
            data: Some(Box::new(StatCounters { timeout_id: None })),
        }
    }

    /**
     * Setup a periodic timer to send out DumpStatCounters messages
     */

    pub fn on_activate(tab: &mut Tab, _tabs: Tabs, ws: WebSocket) {
        let d = web_sys::window()
            .expect("window")
            .document()
            .expect("document");
        let content = d
            .get_element_by_id(crate::tabs::TAB_CONTENT)
            .expect("tab content div");
        content.set_inner_html(""); // clear previous tab

        let headers = ["Counter Name", "Value"]
            .into_iter()
            .map(|h| {
                let e = html!("th").unwrap();
                e.set_inner_html(h);
                e
            })
            .collect::<Vec<Element>>();
        let tr = html!("tr").unwrap();
        for e in headers {
            tr.append_child(&e).unwrap();
        }

        let thead = html!("thead", {}, tr).unwrap();
        let table = html!(
            "table",
            {"class" => "content-table"},
            &thead,
            html!("tbody", { "id" => STAT_COUNTERS_TABLE}).unwrap()
        )
        .expect("table");
        content.append_child(&table).expect("context.append");
        // send one message immediately to get us started
        let msg = GuiToServerMessages::DumpStatCounters();
        if let Err(e) = ws.send_with_str(&serde_json::to_string(&msg).unwrap()) {
            console_log!("Error talking to server: {:?}", e);
        }
        // and start a timer closure to do every 5sec for periodic updates
        let periodic = Closure::<dyn FnMut(_)>::new(move |_e: MessageEvent| {
            let msg = GuiToServerMessages::DumpStatCounters();
            if let Err(e) = ws.send_with_str(&serde_json::to_string(&msg).unwrap()) {
                console_log!("Error talking to server: {:?}", e);
            }
        });
        let stat_counters = tab
            .get_tab_data::<StatCounters>()
            .expect("no stat_counters data!?");
        let window = web_sys::window().expect("window");
        match window.set_interval_with_callback_and_timeout_and_arguments_0(
            periodic.as_ref().unchecked_ref(),
            5000,
        ) {
            // save the timeout id so we can cancel it later
            Ok(timeout) => stat_counters.timeout_id = Some(timeout),
            Err(e) => console_log!("Failed to set_timeout() for DNS Tracker!?: {:?}", e),
        }
        periodic.forget();
    }

    /**
     * Cancel the DumpDNSCache timer when this tab is deactivated
     */
    pub fn on_deactivate(tab: &mut Tab, _ws: WebSocket) {
        let stat_counters = tab
            .get_tab_data::<StatCounters>()
            .expect("no stat counters data!?");
        let window = web_sys::window().expect("window");
        if let Some(timeout_id) = stat_counters.timeout_id {
            // DOM implements no return value for this, so I guess pray() it works!?
            window.clear_interval_with_handle(timeout_id);
            stat_counters.timeout_id = None;
        }
    }
}

pub fn handle_dump_stat_counters_reply(
    counter_map: HashMap<String, u64>,
    _ws: WebSocket,
    tabs: Tabs,
) -> Result<(), JsValue> {
    // this message is just for the stat counters tab; ignore if it's not active
    // note that even when we cancel the timer event for the dns tracker and change the
    // active tab to something else, we could still get this event if we lose the race\
    if tabs.lock().unwrap().get_active_tab_name() != STAT_COUNTERS_TAB {
        return Ok(());
    }
    let d = web_sys::window()
        .expect("window")
        .document()
        .expect("document");
    let tbody = d
        .get_element_by_id(STAT_COUNTERS_TABLE)
        .expect(STAT_COUNTERS_TABLE);
    tbody.set_inner_html("");

    let mut counter_vec_60 = counter_map
        .iter()
        .filter(|(k, _)| k.ends_with(".60"))
        .collect_vec();
    counter_vec_60.sort();
    for (counter_name, value) in &counter_vec_60 {
        let name_elem = html!("td").unwrap();
        name_elem.set_inner_html(counter_name);
        let value_elem = html!("td").unwrap();
        value_elem.set_inner_html(&value.to_string());
        let row = html!("tr", {}, name_elem, value_elem).unwrap();
        tbody.append_child(&row).unwrap();
    }
    Ok(())
}
