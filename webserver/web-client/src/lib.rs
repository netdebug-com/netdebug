mod utils;

use common::Message;
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

const _TIME_LOG: &str = "time_log";

#[wasm_bindgen(start)]
pub fn main() -> Result<(), JsValue> {
    // setup better error messages
    console_error_panic_hook::set_once();
    set_panic_hook();

    let window = web_sys::window().expect("no global 'window' exists!?");
    let document = window.document().expect("should have a document on window");
    let body = document.body().expect("document should have a body");

    // Manufacture the element we're gonna append
    /*
    let list = document.create_element("ol")?;
    list.set_id(TIME_LOG);
    let list_item = document.create_element("li")?;
    list_item.set_inner_html("Network isn't the problem!");
    list.append_child(&list_item)?;

    let div = lookup_by_id("root_div");
    if let Some(d) = div {
        d.append_child(&list)?;
    } else {
        body.append_child(&list)?;
    }
    */

    let canvas = document.create_element("canvas").unwrap();
    canvas.set_id("canvas"); // come back if we need manual double buffering
    let (width, height) = calc_height(&document, &body);
    let width = 4 * width / 5;
    let height = 4 * height / 5;
    console_log!("Setting height to {}, width to {}", height, width);
    canvas.set_attribute("width", format!("{}", width).as_str())?;
    canvas.set_attribute("height", format!("{}", height).as_str())?;
    body.append_child(&canvas).unwrap();

    // canvas example - https://rustwasm.github.io/docs/wasm-bindgen/examples/2d-canvas.html

    Ok(())
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
    data: SortedVec<PingData>,
    data_points_per_draw: usize,
    root: DrawingArea<CanvasBackend, Shift>,
    autoscale_min: f64,
    autoscale_max: f64,
}

impl Graph {
    fn new(data_points_per_draw: usize) -> Graph {
        let backend = CanvasBackend::new("canvas").expect("cannot find canvas");
        let root = backend.into_drawing_area();

        Graph {
            data: SortedVec::new(),
            data_points_per_draw,
            root,
            autoscale_min: f64::MAX,
            autoscale_max: f64::MIN,
        }
    }

    fn add_data(&mut self, rtt: f64, time_stamp: f64) {
        if self.autoscale_min > rtt {
            self.autoscale_min = rtt;
        }
        if self.autoscale_max < rtt {
            self.autoscale_max = rtt;
        }
        self.data.push(PingData { rtt, time_stamp });
        // did we get enough data to be worth redrawing the graph?
        if self.data.len() % self.data_points_per_draw == 0 {
            self.draw();
        }
    }

    fn draw(&mut self) {
        // put into a commulative distribution function
        let plot: Vec<(f64, f64)> = self
            .data
            .iter()
            .enumerate()
            .map(|(idx, ping)| {
                (
                    ping.rtt,
                    100.0 * (idx as f64 + 1.0) / (self.data.len() as f64),
                )
            })
            .collect();
        console_log!("data: {:?}", plot);
        let font: FontDesc = ("sans-serif", 20.0).into();

        self.root.fill(&WHITE).unwrap();
        // draw a new chart
        // TODO - manual double buffering b/c the lib doesn't do it itself
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

        chart
            .draw_series(LineSeries::new(plot.iter().map(|v| (v.1, v.0)), &BLACK))
            .unwrap()
            .label("Application RTT CDF(% < Y)")
            // .legend(move |(x, y)| PathElement::new(vec![(x - 200, y), (x - 70, y + 20)], &BLACK))
            ;

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
        handle_ws_message(e, ws_clone.clone(), &mut graph).unwrap();
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
        VersionCheck { git_hash } => handle_version_check(git_hash, &ws),
        Ping1FromServer {
            server_timestamp_ms: t,
        } => handle_ping1(&t, &ws),
        Ping2FromClient {
            server_timestamp_ms: _,
            client_timestamp_ms: _,
        } => {
            console_log!("Ignoring client msg from server: {:?}", msg);
            Ok(())
        }
        Ping3FromServer {
            server_rtt: rtt,
            client_timestamp_ms: t,
        } => handle_ping3(&rtt, &t, &ws, graph),
    }
}

fn handle_ping3(rtt: &f64, t: &f64, _ws: &WebSocket, graph: &mut Graph) -> Result<(), JsValue> {
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
    graph.add_data(*rtt, now);
    graph.add_data(local_rtt, now);
    // li.set_inner_html(&msg);
    // list.append_child(&li)?;
    Ok(())
}

fn handle_ping1(t: &f64, ws: &WebSocket) -> Result<(), JsValue> {
    // console_log!("Got Ping1 from server");
    let window = web_sys::window().expect("window should be available");
    let performance = window
        .performance()
        .expect("performance should be available");
    let client_ts = performance.now();
    let reply = Message::Ping2FromClient {
        server_timestamp_ms: *t,
        client_timestamp_ms: client_ts,
    };
    ws.send_with_str(serde_json::to_string(&reply).unwrap().as_str())
}

fn handle_version_check(git_hash: String, ws: &WebSocket) -> Result<(), JsValue> {
    if common::Message::check_version(&git_hash) {
        let reply = common::Message::make_version_check();
        ws.send_with_str(serde_json::to_string(&reply).unwrap().as_str())
    } else {
        console_log!(
            "Server has version {} != client version {}",
            &git_hash,
            env!("GIT_HASH")
        );
        Err(JsValue::from_str(
            format!("need reload for new version").as_str(),
        ))
    }
}
