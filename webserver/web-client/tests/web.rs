//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;
// use web_client::{json_parse, ChartConfig, ChartDataSeries, ChartDataSets};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn pass() {
    assert_eq!(1 + 1, 2);
}

/*  REMOVED b/c we got rid of the rust chartjs bindings
#[wasm_bindgen_test]
fn test_chart_config_json() {
    let test_data = ChartDataSets {
        datasets: Vec::from([ChartDataSeries {
            data: Vec::from([20, 10]),
            label: None,
            parsing: None,
        }]),
        labels: Vec::from(["a", "b"].map(|a| a.to_string())),
    };

    let test_chart = ChartConfig {
        chart_type: "bar".to_string(),
        data: test_data,
        options: None,
    };

    let input = test_chart.json().unwrap();
    let _chart_config1: ChartConfig<u32> = serde_wasm_bindgen::from_value(input).unwrap();

    let _js_value = json_parse(
        r#"
        {
            "type": "bar",
            "data": {
                "datasets": [{
                    "data": [20, 10]
                }]
            },
            "labels": ["a", "b"]
        }
    "#,
    );
    // BROKEN!  Fix later
    // let _chart_config2: ChartConfig<u32> = serde_wasm_bindgen::from_value(js_value).unwrap();
}
*/
