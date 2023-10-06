use std::fmt::Display;
use std::net::IpAddr;

use chrono::{DateTime, Duration, Utc};
use desktop_common::GuiToServerMessages;
use libconntrack_wasm::{ConnectionMeasurements, IpProtocol};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::Closure;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{window, Element, HtmlElement, MessageEvent, WebSocket};

use crate::tabs::{Tab, Tabs};
use crate::{console_log, html, log};
use itertools::Itertools;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FlowRowKey {
    local_ip: IpAddr,
    local_l4_port: u16,
    remote_ip: IpAddr,
    remote_l4_port: u16,
    ip_proto: IpProtocol,
    last_packet_time: DateTime<Utc>,
    // TODO: add some perf information, e.g., pkt loss rate or bandwidth
}
impl FlowRowKey {
    fn new(measurements: &ConnectionMeasurements) -> FlowRowKey {
        FlowRowKey {
            local_ip: measurements.local_ip,
            local_l4_port: measurements.local_l4_port,
            remote_ip: measurements.remote_ip,
            remote_l4_port: measurements.remote_l4_port,
            ip_proto: measurements.ip_proto.clone(),
            last_packet_time: measurements.last_packet_time,
        }
    }
}

impl Ord for FlowRowKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // most recently updated flows first, then by IP
        self.last_packet_time
            .cmp(&other.last_packet_time)
            .then(self.remote_ip.cmp(&other.remote_ip))
    }
}

impl PartialOrd for FlowRowKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(&other)) // make PartialOrd match (full)Ord
    }
}

impl Display for FlowRowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", serde_json::to_string(self).unwrap(),)
    }
}

impl From<ConnectionMeasurements> for FlowRowKey {
    fn from(value: ConnectionMeasurements) -> Self {
        FlowRowKey {
            local_ip: value.local_ip,
            local_l4_port: value.local_l4_port,
            remote_ip: value.remote_ip,
            remote_l4_port: value.remote_l4_port,
            ip_proto: value.ip_proto,
            last_packet_time: value.last_packet_time,
        }
    }
}

impl TryFrom<String> for FlowRowKey {
    type Error = serde_json::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        serde_json::from_str(&value)
    }
}

#[derive(Debug, Clone)]
pub struct FlowTracker {
    timeout_id: Option<i32>,
    selected_flow: Option<FlowRowKey>,
    outstanding_request: Option<DateTime<Utc>>,
}

pub const FLOW_TRACKER_TAB: &str = "flow_tracker";
pub const FLOW_TRACKER_TABLE: &str = "__TABLE_flow_tracker";
pub const FLOW_TRACKER_DETAILS: &str = "__DIV_flow_tracker_details";

impl FlowTracker {
    pub(crate) fn new() -> Tab {
        Tab {
            name: FLOW_TRACKER_TAB.to_string(),
            text: "Flow Tracker".to_string(),
            on_activate: Some(|tab, tabs, ws| {
                FlowTracker::on_activate(tab, tabs, ws);
            }),
            on_deactivate: Some(|tab, _tabs, ws| {
                FlowTracker::on_deactivate(tab, ws);
            }),
            data: Some(Box::new(FlowTracker {
                timeout_id: None,
                selected_flow: None,
                outstanding_request: None,
            })),
        }
    }

    /**
     * Setup a periodic timer to send out DumpFlow messages and split the
     * tabcontent div in half for the flows view (left) and the detailed view (right)
     * and add some buttons on the top (Pause/Refresh, Group By...)
     */

    pub fn on_activate(tab: &mut Tab, tabs: Tabs, ws: WebSocket) {
        let d = web_sys::window()
            .expect("window")
            .document()
            .expect("document");
        let content = d
            .get_element_by_id(crate::tabs::TAB_CONTENT)
            .expect("tab content div");
        content.set_inner_html(""); // clear previous tab

        /* setup table for left side */
        let th_flow_key = html!("th").unwrap();
        th_flow_key.set_inner_html("Flow Key");
        let th_applications = html!("th").unwrap();
        th_applications.set_inner_html("Applications(s)");
        let th_send = html!("th").unwrap();
        th_send.set_inner_html("Send Bandwidth");
        let th_recv = html!("th").unwrap();
        th_recv.set_inner_html("Recv Bandwidth");
        let thead = html!(
            "thead",
            {},
            html!("tr", {}, th_applications, th_send, th_recv, th_flow_key).unwrap()
        )
        .unwrap();
        let table = html!(
            "table",
            {"class" => "content-table"},
            &thead,
            html!("tbody", { "id" => FLOW_TRACKER_TABLE}).unwrap()
        )
        .expect("table");
        let table_div = html!("div", {"class" => "flow_table"}, table).unwrap();
        content.append_child(&table_div).expect("content.append");

        // create the div for the detailed flow/right view
        let detailed_div =
            html!("div", { "id"=> FLOW_TRACKER_DETAILS, "class" => "flow_details"}).unwrap();
        content
            .append_child(&detailed_div)
            .expect("content2.append");

        // send one message immediately to get us started
        let msg = GuiToServerMessages::DumpFlows();
        if let Err(e) = ws.send_with_str(&serde_json::to_string(&msg).unwrap()) {
            console_log!("Error talking to server: {:?}", e);
        }
        let flow_tracker = tab
            .get_tab_data::<FlowTracker>()
            .expect("no flowtracker data!?");
        flow_tracker.outstanding_request = Some(Utc::now());
        // and start a timer closure to do every 500ms for periodic updates
        setup_periodic_callback(flow_tracker, tabs.clone(), ws.clone());
        setup_buttons(flow_tracker, tabs, &content, ws.clone());
    }

    /**
     * Cancel the DumpFlows timer when this tab is deactivated
     */
    pub fn on_deactivate(tab: &mut Tab, _ws: WebSocket) {
        let flow_tracker = tab
            .get_tab_data::<FlowTracker>()
            .expect("no flowtracker data!?");
        let window = web_sys::window().expect("window");
        if let Some(timeout_id) = flow_tracker.timeout_id {
            // DOM implements no return value for this, so I guess pray() it works!?
            window.clear_interval_with_handle(timeout_id);
            flow_tracker.timeout_id = None;
        }
    }
}

/**
 * As the name says, setup the callback
 *
 * TODO: store the timeout period in the `struct FlowTracker` for variable timeouts
 */

fn setup_periodic_callback(flow_tracker: &mut FlowTracker, tabs: Tabs, ws: WebSocket) {
    let periodic = Closure::<dyn FnMut(_)>::new(move |_e: MessageEvent| {
        {
            let mut locked = tabs.lock().unwrap();
            if locked.get_active_tab_name() != FLOW_TRACKER_TAB {
                return;
            }
            let flow_tracker = locked.get_active_tab_data::<FlowTracker>().unwrap();
            if let Some(request_time) = flow_tracker.outstanding_request {
                console_log!("Warning: not sending another DumpFlow's request - still one outstanding from {}", request_time);
                return;
            }
        }
        let msg = GuiToServerMessages::DumpFlows();
        if let Err(e) = ws.send_with_str(&serde_json::to_string(&msg).unwrap()) {
            console_log!("Error talking to server: {:?}", e);
        }
    });

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
 * Pre-Append a DIV to the content DIV (so it shows up first) with a list of buttons for the page
 * This function assumes it's being called after the intial setup_periodic()
 */
const PAUSE_BUTTON_PAUSE_MSG: &str = "Pause Refresh";
const PAUSE_BUTTON_RESTART_MSG: &str = "Restart Refresh";
fn setup_buttons(flow_tracker: &mut FlowTracker, tabs: Tabs, content: &Element, ws: WebSocket) {
    // Pause/Restart button - pause or restart the periodic refresh of the page
    let pause_button = html!("button").unwrap().dyn_into::<HtmlElement>().unwrap();
    if flow_tracker.timeout_id.is_some() {
        pause_button.set_inner_html(PAUSE_BUTTON_PAUSE_MSG);
    } else {
        pause_button.set_inner_html(PAUSE_BUTTON_RESTART_MSG);
    }

    let tabs_clone = tabs.clone();
    let on_click = Closure::<dyn FnMut(_)>::new(move |e: MessageEvent| {
        // all of these clone()'s are so that we can call this function many times
        // instead of just once, e.g., so it's a FnMut rather than a FnOnce
        let window = web_sys::window().expect("window");
        let mut tabs_lock = tabs.lock().unwrap();
        let flow_tracker = tabs_lock
            .get_active_tab_data::<FlowTracker>()
            .expect("Not a flowtracker!?");
        match flow_tracker.timeout_id {
            Some(timeout_id) => {
                // there is an active timer; cancel it, and rename the pause button
                flow_tracker.timeout_id = None;
                window.clear_interval_with_handle(timeout_id);
                let button = e.target().unwrap().dyn_into::<Element>().unwrap();
                button.set_inner_html(PAUSE_BUTTON_RESTART_MSG);
            }
            None => {
                // resetup the periodic callback
                setup_periodic_callback(flow_tracker, tabs_clone.clone(), ws.clone());
                let button = e.target().unwrap().dyn_into::<Element>().unwrap();
                button.set_inner_html(PAUSE_BUTTON_PAUSE_MSG);
            }
        }
    });
    pause_button.set_onclick(Some(on_click.as_ref().unchecked_ref()));
    on_click.forget();
    let buttons_div = html!("div", {"style" => "width:100%"}).unwrap();
    buttons_div.append_child(&pause_button).unwrap();
    // put it 'afterbegin' so it shows up first
    content
        .insert_adjacent_element("afterbegin", &buttons_div)
        .unwrap();
}

pub fn handle_dumpflows_reply(
    mut flows: Vec<ConnectionMeasurements>,
    _ws: WebSocket,
    tabs: Tabs,
) -> Result<(), JsValue> {
    // first, sort the flows
    flows.sort_by(|a, b| {
        // sort by the max rate (tx or rx) so that most active flows show at the top
        let max_a = std::cmp::max(&a.tx_byte_rate, &a.rx_byte_rate);
        let max_b = std::cmp::max(&b.tx_byte_rate, &b.rx_byte_rate);
        max_b.cmp(max_a)
    });
    // put all of the locked tabs code in the same block
    let selected_flow = match tabs.lock() {
        Ok(mut tabs) => {
            // this message is just for the flow tracker tab; ignore if it's not active
            // note that even when we cancel the timer event for the flow tracker and change the
            // active tab to something else, we could still get this event if we lose the race
            // use all of this to figure out if the user has selected a flow for inspection
            if tabs.get_active_tab_name() != FLOW_TRACKER_TAB {
                return Ok(()); // if the user switched contexts, just ignore this message
            } else {
                let flow_tracker = tabs
                    .get_active_tab_data::<FlowTracker>()
                    .expect("Not a flow tracker!?");
                if let Some(request_time) = flow_tracker.outstanding_request {
                    let now = Utc::now();
                    if (now - request_time) > Duration::milliseconds(300) {
                        console_log!(
                            "Performance problem: DumpFlows took {} milliseconds",
                            (now - request_time).num_milliseconds()
                        );
                    }
                }
                flow_tracker.outstanding_request = None; // mark we've received this request
                match flow_tracker.selected_flow.clone() {
                    Some(selected_key) => Some(selected_key),
                    None => {
                        // if there is no key selected, e.g., if this is the first time
                        // loading this page, just select the first key, if there are any
                        if let Some(measurements) = flows.iter().next() {
                            let selected_key = Some(FlowRowKey::new(measurements));
                            tabs.get_active_tab_data::<FlowTracker>()
                                .expect("flowtracker")
                                .selected_flow = selected_key.clone();
                            selected_key
                        } else {
                            None // no keys, don't select anything
                        }
                    }
                }
            }
        }
        Err(e) => {
            console_log!("Error getting tabs lock: {}", e);
            return Err(JsValue::from_str(
                format!("Error getting tabs lock: {}", e).as_str(),
            ));
        }
    };
    let d = web_sys::window()
        .expect("window")
        .document()
        .expect("document");
    let tbody = d
        .get_element_by_id(FLOW_TRACKER_TABLE)
        .expect(FLOW_TRACKER_TABLE);
    tbody.set_inner_html(""); // clear the table
    for measurements in flows.into_iter() {
        let flow_row_key = FlowRowKey::new(&measurements);
        let flow_elm = html!("td").unwrap();
        let remote = if let Some(remote) = &measurements.remote_hostname {
            remote.clone()
        } else {
            format!("[{}]", measurements.remote_ip)
        };
        flow_elm.set_inner_html(
            format!(
                "{} ::{} --> {}::{}",
                measurements.ip_proto,
                measurements.local_l4_port,
                remote,
                measurements.remote_l4_port
            )
            .as_str(),
        );
        let apps = if !measurements.associated_apps.is_empty() {
            measurements
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
        let send_bw_elm = html!("td").unwrap();
        send_bw_elm.set_inner_html(
            format!(
                "{}",
                measurements
                    .tx_byte_rate
                    .get_pretty_rate_per_second("Bytes/s")
            )
            .as_str(),
        );
        let recv_bw_elm = html!("td").unwrap();
        recv_bw_elm.set_inner_html(
            format!(
                "{}",
                measurements
                    .rx_byte_rate
                    .get_pretty_rate_per_second("Byte/s")
            )
            .as_str(),
        );
        let row = html!("tr", 
                    {"name" => flow_row_key.to_string().as_str()
                }, app_elm, send_bw_elm, recv_bw_elm, flow_elm)
        .unwrap()
        .dyn_into::<HtmlElement>()
        .unwrap();
        let tabs_clone = tabs.clone();
        let on_click = Closure::<dyn FnMut(_)>::new(move |e: MessageEvent| {
            // all of these clone()'s are so that we can call this function many times
            // instead of just once, e.g., so it's a FnMut rather than a FnOnce
            let mut tabs_lock = tabs_clone.lock().unwrap();
            let flow_tracker = tabs_lock
                .get_active_tab_data()
                .expect("Not a flowtracker!?");
            update_flow_tracker_detail(flow_tracker, e);
        });
        row.set_onclick(Some(on_click.as_ref().unchecked_ref()));
        on_click.forget();
        if let Some(selected_flow) = &selected_flow {
            if *selected_flow == flow_row_key {
                row.set_class_name("active-row"); // this makes CSS highlight this row
                draw_details(&measurements);
                // selected elements get 'Pin'd to the top
                tbody.insert_adjacent_element("afterbegin", &row).unwrap();
            } else {
                // all other elements get appended to the bottom in their sorted order
                tbody.append_child(&row).unwrap();
            }
        } else {
            // all other elements get appended to the bottom in their sorted order
            tbody.append_child(&row).unwrap();
        }
    }
    Ok(())
}

fn update_flow_tracker_detail(flow_tracker: &mut FlowTracker, e: MessageEvent) {
    let mut target = e.target().unwrap().dyn_into::<Element>().unwrap();
    // we get the on_click on the specific td, not the tr, so go up the DOM tree
    // until we find the tr
    while target.get_attribute("name").is_none() {
        target = target.parent_node().unwrap().dyn_into::<Element>().unwrap();
    }
    let new_row = target;
    // unselect old row
    new_row.set_class_name("active-row"); // matches string in CSS
    let new_row_name = new_row.get_attribute("name").unwrap();
    let new_row_key = FlowRowKey::try_from(new_row_name).unwrap();
    if let Some(old_row_key) = &flow_tracker.selected_flow {
        let tbody = window()
            .expect("window")
            .document()
            .expect("document")
            .get_element_by_id(FLOW_TRACKER_TABLE)
            .expect(FLOW_TRACKER_TABLE);
        let old_flow_key_str = old_row_key.to_string();
        // walk the list of flows to turn off the prev selected flow
        // TODO: figure out if we care about O(N) perf here
        for i in 0..tbody.children().length() {
            let row = tbody.children().item(i).unwrap();
            if row.get_attribute("name").unwrap() == old_flow_key_str {
                row.set_class_name(""); // unselect
                break; // only one allowed at a time, unselect it
            }
        }
    }
    flow_tracker.selected_flow = Some(new_row_key);
    // for now, wait until the next refresh to draw the details window, otherwise
    // we'd have to keep the measurements state for each flow, which might be a PITA
}

/**
 * Update the right 'details' DIV with the details on a selected flow
 */
fn draw_details(measurements: &ConnectionMeasurements) {
    let document = window().expect("window").document().expect("document");
    let details_view = document.get_element_by_id(FLOW_TRACKER_DETAILS).unwrap();
    details_view.set_inner_html(""); // clear the DIV
                                     // draw the hostname if we see it
    let h2 = html!("h2").unwrap();
    if let Some(hostname) = &measurements.remote_hostname {
        h2.set_inner_html(&hostname);
    } else {
        h2.set_inner_html(format!("IP {}", measurements.remote_ip).as_str());
    }
    details_view.append_child(&h2).unwrap();
    if measurements.probe_report_summary.summary.is_empty() {
        // default to printing the json if we don't know anything prettier
        let json = serde_json::to_string_pretty(measurements).unwrap();
        let pre_format = html!("pre").unwrap();
        pre_format.set_inner_html(&json);
        details_view.append_child(&pre_format).unwrap();
    } else {
        let list = render_measurement_ttl_list(measurements);
        details_view.append_child(&list).unwrap();
    }
}

/**
 * Convert a ProbeReportSummary to a nice(ish) html text format.
 *
 * TODO: replace this with a graphical representation
 */

fn render_measurement_ttl_list(measurements: &ConnectionMeasurements) -> Element {
    let list = html!("ol").unwrap();
    let n_nodes = measurements.probe_report_summary.raw_reports.len(); // each report should have 1 result per ttl
    for ttl in measurements.probe_report_summary.summary.keys().sorted() {
        let nodes = measurements.probe_report_summary.summary.get(ttl).unwrap();
        if nodes.len() == 1 {
            // simple and hopefully common case; all probes have the same reply type
            let li = html!("li").unwrap();
            let node = nodes.first().unwrap();
            let comments = node.comments.iter().join(",");
            li.set_inner_html(
                format!(
                    "{} {} {} {}",
                    node.name(),
                    if let Some(ip) = node.ip {
                        ip.to_string()
                    } else {
                        "".to_string()
                    },
                    if let Some((min, avg, max)) = node.stats() {
                        format!("RTT stats: min={}, avg={}, max={}", min, avg, max,)
                    } else {
                        "".to_string()
                    },
                    if comments.is_empty() {
                        // do we have any comments from probe reassembly?
                        "".to_string()
                    } else {
                        format!("({} :: \"{}\")", node.comments.len(), comments)
                    },
                )
                .as_str(),
            );
            list.append_child(&li).unwrap();
        } else {
            // multiple different replies for the same TTL
            // this can happen with packet loss or route flapping
            // it shouldn't happen often as all packets in a probe report should hit
            // the same ECMP bucket
            let para = html!("p").unwrap();
            para.set_inner_html(format!("TTL {:3} -------", ttl).as_str());
            let sub_list = html!("ol").unwrap();
            para.append_child(&sub_list).unwrap();
            list.append_child(&html!("li", {}, para).unwrap()).unwrap();
            for node in nodes {
                let n_replies = node.comments.len(); // one comment per reply
                let percent = 100.0 * n_replies as f64 / n_nodes as f64;
                // TODO: sort by frequency?
                let sub_li = html!("li").unwrap();
                sub_li
                    .set_inner_html(format!("{:4}% - {} :: {}", percent, n_replies, node).as_str());
                sub_list.append_child(&sub_li).unwrap();
            }
        }
    }
    list
}
