use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{Duration, Utc};
use desktop_common::GuiToServerMessages;
use libconntrack_wasm::{pretty_print_duration, DnsTrackerEntry};
use wasm_bindgen::prelude::Closure;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{Element, MessageEvent, WebSocket};

use crate::tabs::{Tab, Tabs};
use crate::{console_log, html, log};

#[derive(Debug, Clone)]
pub struct DnsTracker {
    timeout_id: Option<i32>,
}
pub const DNS_TRACKER_TAB: &str = "dns_tracker";
pub const DNS_TRACKER_TABLE: &str = "__TABLE_dns_tracker";

impl DnsTracker {
    pub(crate) fn new() -> Tab {
        Tab {
            name: DNS_TRACKER_TAB.to_string(),
            text: "DNS Tracker".to_string(),
            on_activate: Some(|tab, ws| {
                DnsTracker::on_activate(tab, ws);
            }),
            on_deactivate: Some(|tab, ws| {
                DnsTracker::on_deactivate(tab, ws);
            }),
            data: Some(Box::new(DnsTracker { timeout_id: None })),
        }
    }

    /**
     * Setup a periodic timer to send out DumpDnsCache messages
     * Also setup the table with the table headers so that the
     * updates only update the data
     */

    pub fn on_activate(tab: &mut Tab, ws: WebSocket) {
        let d = web_sys::window()
            .expect("window")
            .document()
            .expect("document");
        let content = d.get_element_by_id("tab_content").expect("tab content div");
        content.set_inner_html("");

        let headers = ["Hostname", "IP Address", "Created", "TTL", "RTT"]
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
            html!("tbody", { "id" => DNS_TRACKER_TABLE}).unwrap()
        )
        .expect("table");
        content.append_child(&table).expect("context.append");
        // send one message immediately to get us started
        let msg = GuiToServerMessages::DumpDnsCache();
        if let Err(e) = ws.send_with_str(&serde_json::to_string(&msg).unwrap()) {
            console_log!("Error talking to server: {:?}", e);
        }
        // and start a timer closure to do every 500ms for periodic updates
        let periodic = Closure::<dyn FnMut(_)>::new(move |_e: MessageEvent| {
            let msg = GuiToServerMessages::DumpDnsCache();
            if let Err(e) = ws.send_with_str(&serde_json::to_string(&msg).unwrap()) {
                console_log!("Error talking to server: {:?}", e);
            }
        });
        let dns_tracker = tab
            .data
            .as_mut()
            .expect("No dns_tracker data!?")
            .downcast_mut::<DnsTracker>()
            .expect("no dns_tracker data!?");
        let window = web_sys::window().expect("window");
        match window.set_interval_with_callback_and_timeout_and_arguments_0(
            periodic.as_ref().unchecked_ref(),
            500,
        ) {
            // save the timeout id so we can cancel it later
            Ok(timeout) => dns_tracker.timeout_id = Some(timeout),
            Err(e) => console_log!("Failed to set_timeout() for DNS Tracker!?: {:?}", e),
        }
        periodic.forget();
    }

    /**
     * Cancel the DumpDNSCache timer when this tab is deactivated
     */
    pub fn on_deactivate(tab: &mut Tab, _ws: WebSocket) {
        let dns_tracker = tab
            .data
            .as_mut()
            .expect("No dns tracker data!?")
            .downcast_mut::<DnsTracker>()
            .expect("no dns tracker data!?");
        let window = web_sys::window().expect("window");
        if let Some(timeout_id) = dns_tracker.timeout_id {
            // DOM implements no return value for this, so I guess pray() it works!?
            window.clear_interval_with_handle(timeout_id);
            dns_tracker.timeout_id = None;
        }
    }
}

pub fn handle_dump_dns_cache_reply(
    cache: HashMap<IpAddr, DnsTrackerEntry>,
    _ws: WebSocket,
    tabs: Tabs,
) -> Result<(), JsValue> {
    // this message is just for the dns tracker tab; ignore if it's not active
    // note that even when we cancel the timer event for the dns tracker and change the
    // active tab to something else, we could still get this event if we lose the race
    if tabs.lock().unwrap().get_active_tab() != DNS_TRACKER_TAB {
        return Ok(());
    }
    let d = web_sys::window()
        .expect("window")
        .document()
        .expect("document");
    let tbody = d
        .get_element_by_id(DNS_TRACKER_TABLE)
        .expect(DNS_TRACKER_TABLE);
    tbody.set_inner_html(""); // clear the table (??)
    let mut sorted_cache: Vec<(IpAddr, DnsTrackerEntry)> = cache.into_iter().collect();
    let now = Utc::now();
    sorted_cache.sort_by(|(ip_a, a), (ip_b, b)| {
        // first by rtt (highest to lowest), then by hostname then IP
        b.rtt
            .cmp(&a.rtt)
            .then(a.hostname.cmp(&b.hostname).then(ip_a.cmp(ip_b)))
    });
    for (ip_addr, dns_entry) in &sorted_cache {
        let hostname = html!("td").unwrap();
        hostname.set_inner_html(&dns_entry.hostname);
        let ip = html!("td").unwrap();
        ip.set_inner_html(format!("{}", ip_addr).as_str());
        let created_time = now - dns_entry.created;
        let created = html!("td").unwrap();
        created.set_inner_html(format!("{} ago", pretty_print_duration(&created_time)).as_str());
        let ttl = html!("td").unwrap();
        if let Some(ttl_value) = dns_entry.ttl {
            ttl.set_inner_html(pretty_print_duration(&ttl_value).as_str());
        } else {
            ttl.set_inner_html("-");
        }
        let rtt = html!("td").unwrap();
        if let Some(rtt_value) = dns_entry.rtt {
            rtt.set_inner_html(pretty_print_duration(&rtt_value).as_str());
            // TODO: normalize these numbers by some fraction of typical RTT, e.g., 20%
            if rtt_value > Duration::milliseconds(10) {
                rtt.set_attribute("style", "color:red;background-color:black").unwrap();
            } else if rtt_value > Duration::milliseconds(5) {
                rtt.set_attribute("style", "color:yellow;background-color:black").unwrap();
            }
        } else {
            rtt.set_inner_html("-");
        }
        // these fields need to be inserted into the tr in the same order
        // as the headers were created in the on_activate() code
        tbody
            .append_child(&html!("tr", {}, hostname, ip, created, ttl, rtt).unwrap())
            .unwrap();
    }
    Ok(())
}
