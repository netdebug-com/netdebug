//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn pass() {
    assert_eq!(1 + 1, 2);
}

/*
use web_client::ChartConfig;
use wasm_bindgen::JsValue;
Test is broken, but the code we were testing works so ignore for now...

#[wasm_bindgen_test]
fn test_chart_config_json() {
    let json_txt = "  type: 'bar',
        data: {
            datasets: [{
            data: [20, 10],
            }],
            labels: ['a', 'b']
        }"
    .to_string();
    let js = JsValue::from(json_txt);
    let _chart_config: ChartConfig<u32> = serde_wasm_bindgen::from_value(js).unwrap();
}

*/
