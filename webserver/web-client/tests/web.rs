//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use serde_json::Value;
use wasm_bindgen_test::*;
use web_client::{ChartConfig, ChartDataSeries, ChartDataSets};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn pass() {
    assert_eq!(1 + 1, 2);
}

#[wasm_bindgen_test]
fn test_chart_config_json() {
    let test_data = ChartDataSets {
        datasets: Vec::from([ChartDataSeries {
            data: Vec::from([20, 10]),
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

    let json: Value = serde_json::from_str(
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
    )
    .unwrap();
    let js_value = serde_wasm_bindgen::to_value(&json).unwrap();
    assert_eq!(js_value.is_object(), true);
}
