mod utils;

use std::{collections::HashMap, vec};

use common::{get_git_hash_version, Message, ProbeReport, ProbeReportEntry, ProbeReportSummary};
use itertools::Itertools;
use js_sys::Date;
use plotters::coord::Shift;
use plotters::prelude::*;
use plotters_canvas::CanvasBackend;
use sorted_vec::SortedVec;
use utils::set_panic_hook;
use wasm_bindgen::prelude::*;
use web_sys::{Document, Element, HtmlElement, MessageEvent, WebSocket};

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen(module = "/js/utils.js")]
extern "C" {
    // populate the cfg JsValue with a ChartConfig struct to JSON
    fn plot_chart(element_id: &str, cfg: JsValue, verbose: bool);
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
    );
    pub fn json_parse(s: &str) -> JsValue;
}

const _TIME_LOG: &str = "time_log";
const MAIN_TAB: &str = "main_tab";
const GRAPH_TAB: &str = "graph_tab";
const PROBE_TAB: &str = "probe_tab";
const _TEST_TAB: &str = "test_tab";
const PROGRESS_METER: &str = "probe_progress_meter";

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
    setup_main_tab(&document, &root_div)?;
    setup_graph_tab(&document, &body, &root_div)?;
    setup_probes_tab(&document, &root_div)?;
    // setup_test_tab(&document, &body, &root_div)?;
    let div = build_info_div(&document)?;
    body.append_child(&div)?;

    // canvas example - https://rustwasm.github.io/docs/wasm-bindgen/examples/2d-canvas.html

    Ok(())
}

fn _setup_test_tab(
    document: &Document,
    body: &HtmlElement,
    root_div: &Element,
) -> Result<(), JsValue> {
    let button = create_tabs_button(document, _TEST_TAB, false)?;
    let label = create_tabs_label(document, "Testing", _TEST_TAB)?;
    let div = create_tabs_content(document, _TEST_TAB)?;

    let canvas = document.create_element("canvas")?;
    canvas.set_id("test_canvas"); // come back if we need manual double buffering
    let (width, height) = calc_height(&document, &body);
    let width = 9 * width / 10;
    let height = 4 * height / 5;
    canvas.set_attribute("width", format!("{}", width).as_str())?;
    canvas.set_attribute("height", format!("{}", height).as_str())?;

    div.append_child(&canvas)?;

    root_div.append_child(&button)?;
    root_div.append_child(&label)?;
    root_div.append_child(&div)?;

    plot_latency_chart(
        "test_canvas",
        100.0,
        150.0,
        155.0,
        100.0,
        250.0,
        255.0,
        100.0,
        450.0,
        455.0,
        false,
    );

    Ok(())
}

fn setup_graph_tab(
    document: &Document,
    body: &HtmlElement,
    root_div: &Element,
) -> Result<(), JsValue> {
    let button = create_tabs_button(document, GRAPH_TAB, false)?;
    let label = create_tabs_label(document, "Graph", GRAPH_TAB)?;
    let div = create_tabs_content(document, GRAPH_TAB)?;

    let canvas = document.create_element("canvas").unwrap();
    canvas.set_id("canvas"); // come back if we need manual double buffering
    let (width, height) = calc_height(&document, &body);
    let width = 9 * width / 10;
    let height = 4 * height / 5;
    console_log!("Setting height to {}, width to {}", height, width);
    canvas.set_attribute("width", format!("{}", width).as_str())?;
    canvas.set_attribute("height", format!("{}", height).as_str())?;

    div.append_child(&canvas)?;

    root_div.append_child(&button)?;
    root_div.append_child(&label)?;
    root_div.append_child(&div)?;
    Ok(())
}

fn setup_probes_tab(document: &Document, root_div: &Element) -> Result<(), JsValue> {
    let button = create_tabs_button(document, PROBE_TAB, false)?;
    let label = create_tabs_label(document, "Probes", PROBE_TAB)?;
    let div = create_tabs_content(document, PROBE_TAB)?;

    div.set_inner_html("Waiting for probes!");
    root_div.append_child(&button)?;
    root_div.append_child(&label)?;
    root_div.append_child(&div)?;
    Ok(())
}

fn setup_main_tab(document: &Document, root_div: &Element) -> Result<(), JsValue> {
    let button = create_tabs_button(document, MAIN_TAB, true)?;
    let label = create_tabs_label(document, "Summary", MAIN_TAB)?;
    let div = create_tabs_content(document, MAIN_TAB)?;

    /*
     * <label for="file">Downloading progress:</label>
     * <progress id="file" value="32" max="100"> 32% </progress>
     */

    let progress_label = document.create_element("label")?;
    progress_label.set_attribute("for", PROGRESS_METER)?;
    progress_label.set_inner_html("Sending Probes:");

    let progress = document.create_element("progress")?;
    progress.set_id(PROGRESS_METER);
    progress.set_attribute("value", "0")?;
    progress.set_attribute("max", "100")?; // will get overwriten by update

    div.append_child(&progress_label)?;
    div.append_child(&progress)?;
    root_div.append_child(&button)?;
    root_div.append_child(&label)?;
    root_div.append_child(&div)?;
    Ok(())
}

/**
* The CSS magic for tabs REQUIRES that elements are declared in this order:
*  1) radio button with class=tabs__radio
*  2) tab lable    with class=tabs__label
*  3) tab content  with class=tabs__content
 <input type="radio" class="tabs__radio" name="tabs-example" id="tab1" checked>
 <label for="tab1" class="tabs__label">Tab #1</label>
 <div class="tabs__content">
   CONTENT for Tab #1
 </div>
*/

fn create_tabs_content(document: &Document, name: &str) -> Result<Element, JsValue> {
    let div = document.create_element("div")?;
    div.set_class_name("tabs__content");
    div.set_id(name);
    Ok(div)
}

fn create_tabs_label(document: &Document, text: &str, tab: &str) -> Result<Element, JsValue> {
    let label = document.create_element("label")?;
    label.set_class_name("tabs__label");
    label.set_attribute("for", format!("{}__id", tab).as_str())?;
    label.set_inner_html(text);
    Ok(label)
}

fn create_tabs_button(document: &Document, id: &str, checked: bool) -> Result<Element, JsValue> {
    let button = document.create_element("input")?;
    button.set_attribute("type", "radio")?;
    if checked {
        // selected by default
        button.set_attribute("checked", "true")?;
    }
    // all of the buttons in the same group need to share this name
    button.set_attribute("name", "top-level-tabs")?;
    button.set_class_name("tabs__radio");
    button.set_id(format!("{}__id", id).as_str());
    Ok(button)
}

fn build_info_div(document: &Document) -> Result<Element, JsValue> {
    let div = document.create_element("div").unwrap();
    div.set_inner_html("Build info:");
    let list = document.create_element("ul")?;
    let list_item = document.create_element("li")?;
    // what date does this show?
    list_item.set_inner_html(format!("Last Modified = {}", document.last_modified()).as_str());
    list.append_child(&list_item)?;
    let list_item = document.create_element("li")?;
    list_item.set_inner_html(format!("GitHash = {}", common::get_git_hash_version()).as_str());
    list.append_child(&list_item)?;
    div.append_child(&list)?;
    Ok(div)
}

// see https://stackoverflow.com/questions/1145850/how-to-get-height-of-entire-document-with-javascript
// for why height and width are complex to calculate
fn calc_height(document: &Document, body: &HtmlElement) -> (i32, i32) {
    let html = document.document_element().unwrap();
    let possible_heights = vec![
        body.scroll_height(),
        body.offset_height(),
        html.client_height(),
        html.scroll_height(),
    ];
    let possible_widths = vec![
        body.scroll_width(),
        body.offset_width(),
        html.client_width(),
        html.scroll_width(),
    ];
    (
        *possible_widths.iter().max().unwrap(),
        *possible_heights.iter().max().unwrap(),
    )
}
#[derive(Debug, PartialEq, PartialOrd)]
struct PingData {
    pub rtt: f64,
    pub time_stamp: f64,
}

// b/c we're based on f64 and float semantics are crazy,
// we have to implement our own Eq and Ord implementations
// these are technically Wrong (e.g., NaN is technically != NaN)
// but good enough for our purposes
impl Eq for PingData {}

impl Ord for PingData {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rtt.total_cmp(&other.rtt)
    }
}

struct Graph {
    data_server: SortedVec<PingData>,
    data_client: SortedVec<PingData>,
    data_probes: HashMap<String, SortedVec<PingData>>,
    data_points_per_draw: usize,
    root: DrawingArea<CanvasBackend, Shift>,
    autoscale_max: f64,
    probe_report_summary: ProbeReportSummary,
    max_rounds: Option<u32>,
}

impl Graph {
    fn new(data_points_per_draw: usize) -> Graph {
        let backend = CanvasBackend::new("canvas").expect("cannot find canvas");
        let root = backend.into_drawing_area();

        Graph {
            data_server: SortedVec::new(),
            data_client: SortedVec::new(),
            data_probes: HashMap::new(),
            data_points_per_draw,
            root,
            probe_report_summary: ProbeReportSummary::new(),
            autoscale_max: f64::MIN,
            max_rounds: None,
        }
    }

    fn add_data(&mut self, server_rtt: f64, client_rtt: f64, time_stamp: f64) {
        if self.autoscale_max < server_rtt {
            self.autoscale_max = server_rtt;
        }
        if self.autoscale_max < client_rtt {
            self.autoscale_max = client_rtt;
        }
        self.data_server.push(PingData {
            rtt: server_rtt,
            time_stamp,
        });
        self.data_client.push(PingData {
            rtt: client_rtt,
            time_stamp,
        });

        // did we get enough data to be worth redrawing the graph?
        if self.data_server.len() % self.data_points_per_draw == 0 {
            self.draw();
        }
    }

    /**
     * Copy in the data from the probe reports
     *
     * NOTE: because we're decoupling the probe report data from the application
     * data and sorting them independently, it's not the case that the data lines
     * up in time, e.g., the p75 of the application data and the p75 of the probe report
     * data may not occur at the same time
     */

    fn add_data_probe_report(&mut self, probe_report: ProbeReport, probe_round: u32) {
        for (_ttl, probe) in &probe_report.probes {
            // extract a name for the hop (e.g. "TTL=x" or "NAT") plus rtt, etc. info
            if let Some((key, rtt, ts)) = match probe {
                ProbeReportEntry::RouterReplyFound {
                    ttl,
                    out_timestamp_ms,
                    rtt_ms,
                    src_ip: _,
                    comment: _,
                } => Some((format!("ttl={}", ttl), rtt_ms, out_timestamp_ms)),
                ProbeReportEntry::NatReplyFound {
                    ttl: _,
                    out_timestamp_ms,
                    rtt_ms,
                    src_ip: _,
                    comment: _,
                } => Some(("NAT".to_string(), rtt_ms, out_timestamp_ms)),
                ProbeReportEntry::EndHostReplyFound {
                    ttl: _,
                    out_timestamp_ms,
                    rtt_ms,
                    comment: _,
                } => Some(("EndHost".to_string(), rtt_ms, out_timestamp_ms)),
                ProbeReportEntry::NoReply {
                    ttl: _,
                    out_timestamp_ms: _,
                    comment: _,
                }
                | ProbeReportEntry::NoOutgoing { ttl: _, comment: _ }
                | ProbeReportEntry::RouterReplyNoProbe {
                    ttl: _,
                    in_timestamp_ms: _,
                    src_ip: _,
                    comment: _,
                }
                | ProbeReportEntry::NatReplyNoProbe {
                    ttl: _,
                    in_timestamp_ms: _,
                    src_ip: _,
                    comment: _,
                }
                | ProbeReportEntry::EndHostNoProbe {
                    ttl: _,
                    in_timestamp_ms: _,
                    comment: _,
                } => None,
            } {
                let d = PingData {
                    rtt: *rtt,
                    time_stamp: *ts,
                };
                if let Some(probes) = self.data_probes.get_mut(&key) {
                    probes.push(d);
                } else {
                    self.data_probes.insert(key, SortedVec::from(vec![d]));
                }
            }
        }
        self.probe_report_summary.update(probe_report);
        if let Some(max_rounds) = self.max_rounds {
            if max_rounds <= probe_round {
                // got all of the probe reports!
                self.update_probe_report_summaries();
            }
        } else {
            console_log!("Weird: called Graph::add_data_probe_report with a max_rounds");
        }
    }

    fn draw(&mut self) {
        // put into a commulative distribution function
        let plot_server: Vec<(f64, f64)> = self
            .data_server
            .iter()
            .enumerate()
            .map(|(idx, ping)| {
                (
                    ping.rtt,
                    100.0 * (idx as f64 + 1.0) / (self.data_server.len() as f64),
                )
            })
            .collect();
        let plot_client: Vec<(f64, f64)> = self
            .data_client
            .iter()
            .enumerate()
            .map(|(idx, ping)| {
                (
                    ping.rtt,
                    100.0 * (idx as f64 + 1.0) / (self.data_client.len() as f64),
                )
            })
            .collect();
        // console_log!("data: {:?}", plot_server);
        let font: FontDesc = ("sans-serif", 20.0).into();

        self.root.fill(&WHITE).unwrap();
        // draw a new chart
        let mut chart = ChartBuilder::on(&self.root)
            .margin(20)
            .caption(
                format!(
                    "CDF (% < Y) of Client-Server Application RTT: {:?}",
                    Date::new_0().to_time_string()
                ),
                font,
            )
            .x_label_area_size(60)
            .y_label_area_size(60)
            .build_cartesian_2d(0f64..100.0, 0.0..self.autoscale_max)
            .unwrap();

        let y_off = 8; // !? need a fudge factor to get the legend to line up with the series label text
        chart
            .draw_series(LineSeries::new(
                plot_server.iter().map(|v| (v.1, v.0)),
                &BLACK,
            ))
            .unwrap()
            .label("Application S->C->S RTT CDF(% < Y)")
            .legend(move |(x, y)| {
                PathElement::new(vec![(x, y - y_off), (x + 20, y - y_off)], &BLACK)
            });
        chart
            .draw_series(LineSeries::new(
                plot_client.iter().map(|v| (v.1, v.0)),
                &RED,
            ))
            .unwrap()
            .label("Application C->S->C RTT CDF(% < Y)")
            .legend(move |(x, y)| {
                PathElement::new(vec![(x, y - y_off), (x + 20, y - y_off)], &RED)
            });
        // Plot the data from each TTL's RTT's
        for (idx, key) in self.data_probes.keys().sorted().enumerate() {
            // TODO: pretty up the color selection algorithm
            let color = Palette99::pick(idx as usize).mix(0.9);
            if let Some(data_points) = self.data_probes.get(key) {
                let data: Vec<(f64, f64)> = data_points
                    .iter()
                    .enumerate()
                    .map(|(idx, ping)| {
                        (
                            ping.rtt,
                            100.0 * (idx as f64 + 1.0) / (data_points.len() as f64),
                        )
                    })
                    .collect();
                chart
                    .draw_series(LineSeries::new(data.iter().map(|v| (v.1, v.0)), &color))
                    .unwrap()
                    .label(format!("{} RTT CDF(% < Y)", key))
                    .legend(move |(x, y)| {
                        PathElement::new(vec![(x, y - y_off), (x + 20, y - y_off)], &color)
                    });
            }
        }

        // quick sanity check
        if plot_client.len() != plot_server.len() {
            console_log!(
                "Weird: client data points {} != server {}",
                plot_client.len(),
                plot_server.len()
            );
        }

        chart
            .configure_mesh()
            .y_desc("RTT (milliseconds)")
            .x_desc("% < Y (CDF)")
            .draw()
            .unwrap();

        chart
            .configure_series_labels()
            .position(SeriesLabelPosition::UpperLeft)
            .border_style(&BLACK)
            .background_style(&WHITE.mix(0.8))
            .draw()
            .unwrap();

        self.root.present().unwrap();
    }

    fn set_max_rounds(&mut self, max_rounds: u32) {
        if self.max_rounds.is_none() {
            self.max_rounds = Some(max_rounds);
            let progress = lookup_by_id(PROGRESS_METER).expect("No progress meter!?");
            progress
                .set_attribute("max", format!("{}", max_rounds).as_str())
                .unwrap();
        }
    }

    fn update_probe_report_summaries(&self) {
        console_log!("Got all probes - updating summaries!");
        let probes_div = lookup_by_id(PROBE_TAB).expect("Probes tab not setup!?");
        let window = web_sys::window().expect("no global 'window' exists!?");
        let document = window.document().expect("should have a document on window");
        let pre_formated = document
            .create_element("pre")
            .expect("Failed to create a 'pre'");
        // for now, just use the existing Display format
        pre_formated.set_inner_html(format!("{}", self.probe_report_summary).as_str());
        probes_div.set_inner_html(
            format!("Collected 100% of {} probes", self.max_rounds.unwrap()).as_str(),
        );
        probes_div
            .append_child(&pre_formated)
            .expect("Failed to append pre to div!?");
        // could just continue, but logically different to do a new function
        self.draw_main_latencies_chart();
    }

    /***
     * FIgure out the p1, p50, and p99 of the client data and then find the
     * NAT ("ISP") and Endhost ("home network") probe reports that most closely
     * match those in time.  Those become nine data points that we will plot
     * on the main summary.
     *
     * NOTE: the plot_latency_chart() numbers are RELATIVE, so need to calc
     * relative latencies from these absolute ones for the stacked bar chart
     *
     * TODO: de-fuglyfy this code with an enum {BEST, TYPICAL, WORST} and
     * some better control structures; too tired now to do this right
     * and this seems pretty low priority code to beautify
     */

    fn draw_main_latencies_chart(&self) {
        let best_client_index = 1;
        let typical_client_index = self.data_client.len() / 2;
        let worst_client_index = self.data_client.len() - 1;

        let best_client_time = self.data_client[best_client_index].time_stamp;
        let typical_client_time = self.data_client[typical_client_index].time_stamp;
        let worst_client_time = self.data_client[worst_client_index].time_stamp;
        let best_client_rtt = self.data_client[best_client_index].rtt;
        let typical_client_rtt = self.data_client[typical_client_index].rtt;
        let worst_client_rtt = self.data_client[worst_client_index].rtt;

        //  (time_delta, value)
        let mut best_home = (
            f64::MAX,
            PingData {
                rtt: 0.0,
                time_stamp: 0.0,
            },
        );
        let mut best_isp = (
            f64::MAX,
            PingData {
                rtt: 0.0,
                time_stamp: 0.0,
            },
        );
        let mut typical_home = (
            f64::MAX,
            PingData {
                rtt: 0.0,
                time_stamp: 0.0,
            },
        );
        let mut typical_isp = (
            f64::MAX,
            PingData {
                rtt: 0.0,
                time_stamp: 0.0,
            },
        );
        let mut worst_home = (
            f64::MAX,
            PingData {
                rtt: 0.0,
                time_stamp: 0.0,
            },
        );
        let mut worst_isp = (
            f64::MAX,
            PingData {
                rtt: 0.0,
                time_stamp: 0.0,
            },
        );
        // the raw reports were inserted by/sorted by time
        // step through and find the probes that are the closest in time to the app/client ones
        for report in &self.probe_report_summary.raw_reports {
            for probe in report.probes.values() {
                // use 'if let' instead of match as there are a LOT of probe types!
                use ProbeReportEntry::*;
                if let EndHostReplyFound {
                    ttl: _,
                    out_timestamp_ms,
                    rtt_ms,
                    comment: _,
                } = probe
                {
                    // an EndHostReply signifies the latency through the home network
                    let best_home_delta = (out_timestamp_ms - best_client_time).abs();
                    if best_home_delta < best_home.0 {
                        best_home = (
                            best_home_delta,
                            PingData {
                                rtt: *rtt_ms,
                                time_stamp: *out_timestamp_ms,
                            },
                        );
                    }
                    let typical_home_delta = (out_timestamp_ms - typical_client_time).abs();
                    if typical_home_delta < typical_home.0 {
                        typical_home = (
                            typical_home_delta,
                            PingData {
                                rtt: *rtt_ms,
                                time_stamp: *out_timestamp_ms,
                            },
                        );
                    }
                    let worst_home_delta = (out_timestamp_ms - worst_client_time).abs();
                    if worst_home_delta < worst_home.0 {
                        worst_home = (
                            worst_home_delta,
                            PingData {
                                rtt: *rtt_ms,
                                time_stamp: *out_timestamp_ms,
                            },
                        );
                    }
                } else if let NatReplyFound {
                    ttl: _,
                    out_timestamp_ms,
                    rtt_ms,
                    src_ip: _,
                    comment: _,
                } = probe
                {
                    // an NatReply signifies the latency through the ISP network
                    let best_isp_delta = (out_timestamp_ms - best_client_time).abs();
                    if best_isp_delta < best_isp.0 {
                        best_isp = (
                            best_isp_delta,
                            PingData {
                                rtt: *rtt_ms,
                                time_stamp: *out_timestamp_ms,
                            },
                        );
                    }
                    let typical_isp_delta = (out_timestamp_ms - typical_client_time).abs();
                    if typical_isp_delta < typical_isp.0 {
                        typical_isp = (
                            typical_isp_delta,
                            PingData {
                                rtt: *rtt_ms,
                                time_stamp: *out_timestamp_ms,
                            },
                        );
                    }
                    let worst_isp_delta = (out_timestamp_ms - worst_client_time).abs();
                    if worst_isp_delta < worst_isp.0 {
                        worst_isp = (
                            worst_isp_delta,
                            PingData {
                                rtt: *rtt_ms,
                                time_stamp: *out_timestamp_ms,
                            },
                        );
                    }
                }
            }
        }

        let main_div = lookup_by_id(MAIN_TAB).unwrap();
        let document = web_sys::window().unwrap().document().unwrap();
        let body = document.body().unwrap();
        let canvas = document.create_element("canvas").unwrap();
        canvas.set_id("main_canvas"); // come back if we need manual double buffering
        let (width, height) = calc_height(&document, &body);
        let width = 9 * width / 10;
        let height = 4 * height / 5;
        canvas
            .set_attribute("width", format!("{}", width).as_str())
            .unwrap();
        canvas
            .set_attribute("height", format!("{}", height).as_str())
            .unwrap();

        main_div.set_inner_html("");
        main_div.append_child(&canvas).unwrap();
        console_log!("Best ISP - {}", best_isp.1.rtt);
        console_log!("Best HOME - {}", best_home.1.rtt);
        console_log!("Best APP - {}", best_client_rtt);
        console_log!("typical ISP - {}", typical_isp.1.rtt);
        console_log!("typical HOME - {}", typical_home.1.rtt);
        console_log!("typical APP - {}", typical_client_rtt);
        console_log!("worst ISP - {}", worst_isp.1.rtt);
        console_log!("worst HOME - {}", worst_home.1.rtt);
        console_log!("worst APP - {}", worst_client_rtt);
        plot_latency_chart(
            "main_canvas",
            best_isp.1.rtt,
            best_home.1.rtt - best_isp.1.rtt,
            best_client_rtt - best_home.1.rtt,
            typical_isp.1.rtt,
            typical_home.1.rtt - typical_isp.1.rtt,
            typical_client_rtt - typical_home.1.rtt,
            worst_isp.1.rtt,
            worst_home.1.rtt - worst_isp.1.rtt,
            worst_client_rtt - worst_home.1.rtt,
            true,
        );
    }
}

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
    let mut graph = Graph::new(10); // this gets moved into the closure
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
        Ping2FromClient {
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
    }
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
