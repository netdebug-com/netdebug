use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::net::IpAddr;

use chrono::{DateTime, Duration, Utc};
use desktop_common::GuiToServerMessages;
use libconntrack_wasm::{pretty_print_duration, DnsTrackerEntry};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::Closure;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{Element, MessageEvent, WebSocket};

use crate::tabs::{Tab, Tabs};
use crate::{console_log, html, log};

/**
 * We use this to sort/order/identify this row for comparisons purposes
 *
 * We can't sort on any field not represented in this key
 */
#[serde_with::serde_as]
#[derive(Debug, Clone, Hash, Serialize, Deserialize, PartialEq, Eq)]
struct DnsRowKey {
    hostname: String,
    #[serde_as(as = "Option<serde_with::DurationMicroSeconds<i64>>")]
    rtt: Option<Duration>,
}

impl DnsRowKey {
    fn new(dns_entry: &DnsTrackerEntry) -> DnsRowKey {
        DnsRowKey {
            hostname: dns_entry.hostname.clone(),
            rtt: dns_entry.rtt.clone(),
        }
    }
}

impl Display for DnsRowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string(self).unwrap())
    }
}
impl From<DnsTrackerEntry> for DnsRowKey {
    fn from(value: DnsTrackerEntry) -> Self {
        DnsRowKey {
            hostname: value.hostname.clone(),
            rtt: value.rtt.clone(),
        }
    }
}

impl TryFrom<String> for DnsRowKey {
    type Error = serde_json::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        serde_json::from_str(&value)
    }
}

// define how we want keys (and thus rows) ordered
impl std::cmp::Ord for DnsRowKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // sort by rtt from high to low first, then hostname
        // TODO: add custom sorting functions so we can runtime sort by other things
        other
            .rtt
            .cmp(&self.rtt)
            .then(self.hostname.cmp(&other.hostname))
    }
}

// ensure that PartialOrd agrees with (full)Ord
impl std::cmp::PartialOrd for DnsRowKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // we have a full ordering defined, so just always return that
        Some(self.cmp(&other))
    }
}

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
            on_activate: Some(|tab, _tabs, ws| {
                DnsTracker::on_activate(tab, ws);
            }),
            on_deactivate: Some(|tab, _tabs, ws| {
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
        let content = d
            .get_element_by_id(crate::tabs::TAB_CONTENT)
            .expect("tab content div");
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
            .get_tab_data::<DnsTracker>()
            .expect("no dns_tracker data!?");
        let window = web_sys::window().expect("window");
        match window.set_interval_with_callback_and_timeout_and_arguments_0(
            periodic.as_ref().unchecked_ref(),
            1000,
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
            .get_tab_data::<DnsTracker>()
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
    if tabs.lock().unwrap().get_active_tab_name() != DNS_TRACKER_TAB {
        return Ok(());
    }
    let d = web_sys::window()
        .expect("window")
        .document()
        .expect("document");
    let tbody = d
        .get_element_by_id(DNS_TRACKER_TABLE)
        .expect(DNS_TRACKER_TABLE);

    // build a reverse map of DnsEntries to IPs
    let mut entries2ips: HashMap<DnsTrackerEntry, Vec<IpAddr>> = HashMap::new();
    for (ip, dns_entry) in cache {
        entries2ips.entry(dns_entry).or_insert(Vec::new()).push(ip);
    }
    let mut sorted_cache: Vec<(DnsTrackerEntry, Vec<IpAddr>)> = entries2ips.into_iter().collect();
    let now = Utc::now();
    sorted_cache.sort_by(|(a, _a), (b, _b)| DnsRowKey::new(a).cmp(&DnsRowKey::new(b)));
    // merge sort-esque merge the new data with the old, updating where it already exists
    // NOTE: it seems like it's hard to get a persistent/non-dynamic list of children from the DOM
    // so we do two passes: one to add/update rows, and one to remove old rows
    let mut old_row_index = 0;
    let mut new_rows = sorted_cache.iter();
    let old_rows = tbody.children();
    let mut new_row = new_rows.next();
    // rust is annoying in that you can't YET have two let statement in the same clause
    // otherwise, would have written:
    // while let Some(new_row) = new_rows.next() AND let Some(old_row) = old_rows.items(old_row_index)
    // this should be equivalent to that
    let mut keep_these_keys = HashSet::new();
    loop {
        let (dns_entry, ips) = match new_row {
            Some((dns_entry, ips)) => (dns_entry, ips),
            None => {
                break;
            }
        };
        let old_row = match old_rows.item(old_row_index) {
            Some(old_row) => old_row,
            None => {
                break;
            }
        };
        let new_row_key = DnsRowKey::new(dns_entry);
        let old_row_key = DnsRowKey::try_from(old_row.get_attribute("name").unwrap()).unwrap();
        if old_row_key.hostname == dns_entry.hostname {
            // old and new rows are the same, just update
            update_dns_entry_row(dns_entry, &ips, &old_row, &now);
            keep_these_keys.insert(new_row_key.to_string());
            new_row = new_rows.next();
            old_row_index += 1; // this keeps us pointing a the same old_row
            continue;
        } else {
            match new_row_key.cmp(&old_row_key) {
                std::cmp::Ordering::Less => {
                    // add the new entry
                    let new_row_elm = new_dns_entry_row(&dns_entry, &ips, &now).unwrap();
                    old_row
                        .insert_adjacent_element("beforebegin", &new_row_elm)
                        .unwrap();
                    keep_these_keys.insert(new_row_key.to_string());
                    new_row = new_rows.next();
                    old_row_index += 1; // to keep looking at the same old_row, after we added this item
                }
                std::cmp::Ordering::Greater => {
                    // remove the stale entry
                    old_row.remove();
                    // no change to old_row_index; the list got smaller
                }
                // Don't use this for testing equality b/c the rtt's might not precisely match
                // that's why we check above by hostname
                std::cmp::Ordering::Equal => {
                    panic!("This should never happen; already checked dns_entires for eq")
                }
            }
        }
    }
    // after we exit, one of these iterators will be done, so only one clause will be run
    // add any remaining new rows
    while let Some((dns_entry, ips)) = new_rows.next() {
        let new_row_key = DnsRowKey::new(&dns_entry);
        keep_these_keys.insert(new_row_key.to_string());
        let new_row_elm = new_dns_entry_row(&dns_entry, &ips, &now).unwrap();
        tbody.append_child(&new_row_elm).unwrap();
    }
    // now walk the list of rows in the table and remove any we don't want to keep
    // wish the DOM API implemented a rust-style Iterator()
    while old_row_index < old_rows.length() {
        let old_row = old_rows.item(old_row_index).unwrap();
        let old_row_key = old_row.get_attribute("name").unwrap();
        if !keep_these_keys.contains(&old_row_key) {
            old_row.remove();
        } else {
            old_row_index += 1;
        }
    }
    Ok(())
}

fn new_dns_entry_row(
    dns_entry: &&DnsTrackerEntry,
    ips: &[IpAddr],
    now: &DateTime<Utc>,
) -> Result<Element, JsValue> {
    let hostname = html!("td").unwrap();
    hostname.set_inner_html(&dns_entry.hostname);
    let ip = generate_ips_details(ips);
    let ttl = html!("td").unwrap();
    if let Some(ttl_value) = dns_entry.ttl {
        ttl.set_inner_html(pretty_print_duration(&ttl_value).as_str());
    } else {
        ttl.set_inner_html("-");
    }
    let created = html!("td").unwrap();
    write_created_td(&now, &dns_entry.created, &created);
    let rtt = html!("td").unwrap();
    if let Some(rtt_value) = dns_entry.rtt {
        rtt.set_inner_html(pretty_print_duration(&rtt_value).as_str());
        // TODO: normalize these numbers by some fraction of typical RTT, e.g., 20%
        if rtt_value > Duration::milliseconds(10) {
            rtt.set_attribute("style", "color:red;background-color:black")
                .unwrap();
        } else if rtt_value > Duration::milliseconds(5) {
            rtt.set_attribute("style", "color:yellow;background-color:black")
                .unwrap();
        }
    } else {
        rtt.set_inner_html("-");
    }
    // these fields need to be inserted into the tr in the same order
    // as the headers were created in the on_activate() code
    let row_key = DnsRowKey::new(&dns_entry).to_string();
    html!("tr", { "name" => row_key.as_str() }, hostname, ip, created, ttl, rtt)
}

fn write_created_td(now: &DateTime<Utc>, created: &DateTime<Utc>, created_elm: &Element) {
    let created_time = *now - created;
    created_elm.set_inner_html(format!("{} seconds ago", created_time.num_seconds()).as_str());
}

/**
 * Update a DNS entry
 *
 * The only thing that needs to change from update to update is the 'created' field,
 */
fn update_dns_entry_row(
    dns_entry: &DnsTrackerEntry,
    _ips: &[IpAddr],
    old_row: &Element,
    now: &DateTime<Utc>,
) {
    const CREATED_FIELD: u32 = 2;
    if let Some(created) = old_row.children().item(CREATED_FIELD) {
        write_created_td(now, &dns_entry.created, &created);
    }
}

/*  Show the list of IPs as
*  <details>
*    <summary> X addresses </summary>
*    <ul>
*      <li> ...
*      <li> ...
*     </ul>
* </details>
* ... unless it's a single IP
*/
fn generate_ips_details(ips: &[IpAddr]) -> Element {
    let td = html!("td").unwrap();
    if ips.len() == 1 {
        td.set_inner_html(format!("{}", ips[0]).as_str());
    } else {
        let ui = html!("ui").unwrap();
        for ip in ips {
            let li = html!("li").unwrap();
            li.set_inner_html(ip.to_string().as_str());
            ui.append_child(&li).unwrap();
        }
        let summary = html!("summary").unwrap();
        summary.set_inner_html(
            format!(
                "{} address{}",
                ips.len(),
                if ips.len() > 1 { "es" } else { "" }
            )
            .as_str(),
        );
        let ip_details = html!("details", {}, summary, ui).unwrap();
        td.append_child(&ip_details).unwrap();
    }
    td
}
