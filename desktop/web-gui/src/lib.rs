mod utils;
use web_sys::WebSocket;

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


#[wasm_bindgen(start)]
pub fn run() -> Result<(), JsValue> {
    utils::set_panic_hook();
    let _ws = create_websocket()?;
    console_log!("working!?");
    Ok(())
}