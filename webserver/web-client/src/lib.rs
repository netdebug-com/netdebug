mod utils;

use utils::set_panic_hook;
use wasm_bindgen::prelude::*;
use web_sys::{WebSocket, MessageEvent, Element};

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

const TIME_LOG: &str = "time_log";

#[wasm_bindgen(start)]
pub fn main() -> Result<(), JsValue> {
    // setup better error messages
    console_error_panic_hook::set_once();
    set_panic_hook();

    let window = web_sys::window().expect("no global 'window' exists!?");
    let document = window.document().expect("should have a document on window");
    let body = document.body().expect("document should have a body");

    // Manufacture the element we're gonna append
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


    // canvas example - https://rustwasm.github.io/docs/wasm-bindgen/examples/2d-canvas.html

    Ok(())
}

#[wasm_bindgen]
pub fn run_webtest() -> Result<(), JsValue> {
    let location = web_sys::window().unwrap().location();
    let proto = match location.protocol()?.as_str() {
        "https:" => "wss",
        "http:" => "ws",
        _ => {
            console_log!("Weird location.protocol(): - {} - default to wss://",
                location.protocol().unwrap()
            ); 
            "wss"
        },     // default to more secure wss
    };
    let url = format!("{}://{}/ws", proto, location.host()?);
    let ws = WebSocket::new(url.as_str())?;

    let onmessage_callback = Closure::<dyn FnMut(_)>::new(
        move |e: MessageEvent| {
            handle_ws_message(e).unwrap();
        }
    );

    ws.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
    onmessage_callback.forget();  // MAGIC: tell rust not to deallocate this!

    Ok(())
}

fn lookup_by_id(id: &str) -> Option<Element> {
    web_sys::window()?.document()?.get_element_by_id(id)

}


fn handle_ws_message(e: MessageEvent) -> Result<(), JsValue> {
    let document = web_sys::window().unwrap().document().unwrap();
    let list = document.get_element_by_id(TIME_LOG).unwrap();
    let li = document.create_element("li")?;

    li.set_inner_html(e.data().as_string().unwrap().as_str());
    list.append_child(&li)?;
    
    Ok(())
}
