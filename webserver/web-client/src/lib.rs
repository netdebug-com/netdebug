mod utils;

use common::{get_git_hash_version, Message};
use graph::Graph;
use utils::set_panic_hook;
use wasm_bindgen::prelude::*;
use web_sys::{Element, HtmlButtonElement, HtmlTextAreaElement, MessageEvent, WebSocket};

pub mod consts;
use crate::consts::*;
pub mod tabs;
use crate::tabs::*;
pub mod graph;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

pub(crate) use console_log; // this allows other modules to use console_log!()

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);
}

#[wasm_bindgen(module = "/js/utils.js")]
extern "C" {
    // each return the chart so that subsequent calls must clear the chart before
    // re-plotting

    // populate the cfg JsValue with a ChartConfig struct to JSON
    fn plot_chart(element_id: &str, cfg: JsValue, verbose: bool) -> JsValue;
    // Above is a PITA to get working, just pass the JSON as a string
    pub fn plot_json_chart(s: &str, json: &str, verbose: bool) -> JsValue;
    pub fn plot_json_chart_update(chat: JsValue, data_json: &str, verbose: bool);
    // lost too much time fuxzing with wasm2js stuff - just pass
    // the nine variables explicitly - sigh
    fn plot_latency_chart(
        element_id: &str,
        best_isp: f64,
        best_home: f64,
        best_app: f64,
        typical_isp: f64,
        typical_home: f64,
        typical_app: f64,
        worst_isp: f64,
        worst_home: f64,
        worst_app: f64,
        verbose: bool,
    ) -> JsValue;
}

#[wasm_bindgen(start)]
pub fn run() -> Result<(), JsValue> {
    // setup better error messages
    console_error_panic_hook::set_once();
    set_panic_hook();

    let window = web_sys::window().expect("no global 'window' exists!?");
    let document = window.document().expect("should have a document on window");
    let body = document.body().expect("document should have a body");

    // the only thing in the HTML
    let root_div = lookup_by_id("root_div").expect("Div 'root_div' not found!?");
    root_div.set_class_name("tabs");
    // tabs are listed left to right in this order
    setup_main_tab(&document, &root_div)?;
    setup_insights_tab(&document, &root_div)?;
    setup_graph_tab(&document, &body, &root_div)?;
    setup_probes_tab(&document, &root_div)?;
    setup_annotate_tab(&document, &root_div)?;
    // put build info at the bottom of the page
    let div = build_info_div(&document)?;
    body.append_child(&div)?;

    // more dynamic things are setup by run_webtest()
    Ok(())
}
/****
 * This starts the actual webtest assuming run() has already set
 * everything up
 */

#[wasm_bindgen]
pub fn run_webtest() -> Result<(), JsValue> {
    let location = web_sys::window().unwrap().location();
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

    let ws_clone = ws.clone();

    setup_annotation_onclick_message(ws.clone())?;
    let mut graph = Graph::new(10, "canvas".to_string()); // this gets moved into the closure
    let onmessage_callback = Closure::<dyn FnMut(_)>::new(move |e: MessageEvent| {
        // double clone needed to match function prototypes - apparently(!?)
        if let Err(js_value) = handle_ws_message(e, ws_clone.clone(), &mut graph) {
            // TODO: reload whole document on JsValue("need to reload")
            console_log!("Error! {:?}", js_value);
        }
    });

    ws.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
    onmessage_callback.forget(); // MAGIC: tell rust not to deallocate this!

    Ok(())
}

/**
 * Now that we have a valid websocket, setup an 'onclick' callback
 * for the annotation's submit button
 */

fn setup_annotation_onclick_message(ws: WebSocket) -> Result<(), JsValue> {
    let button = lookup_by_id(ANNOTATE_INPUT_BUTTON)
        .unwrap()
        .dyn_into::<HtmlButtonElement>()?;

    let button_clone = button.clone();

    let onclick_callback = Closure::<dyn FnMut(_)>::new(move |_e: MessageEvent| {
        let text_area = lookup_by_id(ANNOTATE_TEXT_AREA)
            .unwrap()
            .dyn_into::<HtmlTextAreaElement>()
            .unwrap();
        let annotation = text_area.value();
        let msg = common::Message::SetUserAnnotation { annotation };
        if let Err(e) = ws.send_with_str(&serde_json::to_string(&msg).unwrap()) {
            console_log!("Error sending annotation: {:?}", e);
        } else {
            // change the button text to indicate we sent the annotation
            button_clone.set_inner_html("Update Annotation");
        }
    });

    button.set_onclick(Some(onclick_callback.as_ref().unchecked_ref()));
    onclick_callback.forget(); // MAGIC: tell rust not to deallocate this!

    Ok(())
}

#[allow(dead_code)] // this will eventually be useful
fn lookup_by_id(id: &str) -> Option<Element> {
    web_sys::window()?.document()?.get_element_by_id(id)
}

fn handle_ws_message(e: MessageEvent, ws: WebSocket, graph: &mut Graph) -> Result<(), JsValue> {
    let raw_msg = e.data().as_string().unwrap();
    let msg: common::Message = serde_json::from_str(raw_msg.as_str()).unwrap();
    use common::Message::*;
    match msg {
        // TODO: add logic to reload client on version check mismatch
        VersionCheck { git_hash } => handle_version_check(git_hash, &ws),
        Ping1FromServer {
            server_timestamp_ms: t,
            probe_round,
            max_rounds,
        } => handle_ping1(&t, &ws, probe_round, max_rounds),
        SetUserAnnotation { annotation: _ }
        | Ping2FromClient {
            server_timestamp_ms: _,
            client_timestamp_ms: _,
            probe_round: _,
            max_rounds: _,
        } => {
            console_log!("Ignoring client msg from server: {:?}", msg);
            Ok(())
        }
        Ping3FromServer {
            server_rtt: rtt,
            client_timestamp_ms: t,
            probe_round,
            max_rounds,
        } => handle_ping3(&rtt, &t, &ws, graph, probe_round, max_rounds),
        ProbeReport {
            report,
            probe_round,
        } => handle_probe_report(report, probe_round, graph),
        Insights { insights } => handle_insights(insights),
    }
}

fn handle_insights(
    insights: Vec<common::analysis_messages::AnalysisInsights>,
) -> Result<(), JsValue> {
    let document = web_sys::window().unwrap().document().unwrap();
    let tab_div = lookup_by_id(INSIGHTS_TAB).unwrap();
    let table = document.create_element("table").unwrap();
    tab_div.set_inner_html(""); // delete old value
    tab_div.append_child(&table).unwrap();
    let header = document.create_element("tr").unwrap();
    for th in ["Result", "Insight", "Details", "Raw"] {
        let e = document.create_element("th").unwrap();
        e.set_inner_html(th);
        header.append_child(&e).unwrap();
    }
    table.append_child(&header).unwrap();

    for insight in insights {
        let row = document.create_element("tr").unwrap();
        let good = document.create_element("td").unwrap();
        if let Some(goodness) = insight.goodness() {
            good.set_inner_html(goodness.to_string().as_str());
        } else {
            good.set_inner_html("-");
        }
        row.append_child(&good).unwrap();

        let insight_td = document.create_element("td").unwrap();
        let insight_name = insight.name();
        insight_td.set_inner_html(insight_name.as_str());
        row.append_child(&insight_td).unwrap();

        let comment = document.create_element("td").unwrap();
        comment.set_inner_html(insight.comment().as_str());
        row.append_child(&comment).unwrap();

        let raw = document.create_element("td").unwrap();
        raw.set_inner_html(format!("{:?}", insight).as_str());
        row.append_child(&raw).unwrap();
        table.append_child(&row).unwrap();
    }
    Ok(())
}

fn handle_probe_report(
    report: common::ProbeReport,
    probe_round: u32,
    graph: &mut Graph,
) -> Result<(), JsValue> {
    // console_log!("Round {} -- report\n{}", probe_round, report);
    graph.add_data_probe_report(report, probe_round);
    Ok(())
}

fn handle_ping3(
    rtt: &f64,
    t: &f64,
    _ws: &WebSocket,
    graph: &mut Graph,
    probe_round: u32,
    max_rounds: u32,
) -> Result<(), JsValue> {
    // console_log!("Got Ping3 from server");
    let window = web_sys::window().expect("window should be available");
    let performance = window
        .performance()
        .expect("performance should be available");
    let now = performance.now();
    let local_rtt = now - t;
    // old code to add directly to html
    // let document = web_sys::window().unwrap().document().unwrap();
    // let list = document.get_element_by_id(TIME_LOG).unwrap();
    // let li = document.create_element("li")?;
    // let msg = format!("Server rtt {} ms client rtt {} ms", rtt, local_rtt);
    graph.set_max_rounds(max_rounds); // should be constant the whole time
    graph.add_data(*rtt, local_rtt, now);
    update_probe_progress_meter(probe_round, max_rounds)?;
    // li.set_inner_html(&msg);
    // list.append_child(&li)?;
    Ok(())
}

fn update_probe_progress_meter(probe_round: u32, _max_rounds: u32) -> Result<(), JsValue> {
    let progress = lookup_by_id(PROGRESS_METER).expect("No progress meter!?");
    progress.set_attribute("value", format!("{}", probe_round).as_str())?;
    Ok(())
}

fn handle_ping1(t: &f64, ws: &WebSocket, probe_round: u32, max_rounds: u32) -> Result<(), JsValue> {
    // console_log!("Got Ping1 from server");
    let window = web_sys::window().expect("window should be available");
    let performance = window
        .performance()
        .expect("performance should be available");
    let client_ts = performance.now();
    let reply = Message::Ping2FromClient {
        server_timestamp_ms: *t,
        client_timestamp_ms: client_ts,
        probe_round,
        max_rounds,
    };
    ws.send_with_str(serde_json::to_string(&reply).unwrap().as_str())
}

fn handle_version_check(git_hash: String, ws: &WebSocket) -> Result<(), JsValue> {
    if common::Message::check_version(&git_hash) {
        console_log!(
            "Version checked passed: both client and server on {}",
            git_hash
        );
        let reply = common::Message::make_version_check();
        ws.send_with_str(serde_json::to_string(&reply).unwrap().as_str())
    } else {
        console_log!(
            "Server has version {} != client version {}",
            &git_hash,
            get_git_hash_version(),
        );
        Err(JsValue::from_str(
            format!("need reload for new version").as_str(),
        ))
    }
}
