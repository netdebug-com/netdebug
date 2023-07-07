/**
 * A lot of work went into creating a Rust-like wrapper around chart.js .. and it didn't work.
 * 
 * Saving it here in case there's time to fix later.
 */

#[derive(Debug, Serialize, Deserialize)]
pub struct ChartDataSeries<T> {
    pub data: Vec<T>,
    pub label: Option<String>,
    pub parsing: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChartDataSets<T> {
    // can have more than one dataset per graph
    pub datasets: Vec<ChartDataSeries<T>>,
    // labels.len() must be >= max(Vec.len())
    pub labels: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChartConfig<T> {
    /* Looks like:
    {
        type: 'bar',
        data: {
            datasets: [{
            data: [20, 10],
            }],
            labels: ['a', 'b']
        }
    }
     */
    #[serde(rename = "type")] // 'type' is a keyword in rust, can't use it
    pub chart_type: String,
    pub data: ChartDataSets<T>,
    pub options: Option<serde_json::Value>,
}

impl<T: serde::Serialize> ChartConfig<T> {
    pub fn new(chart_type: String) -> ChartConfig<T> {
        ChartConfig {
            chart_type,
            data: ChartDataSets {
                datasets: Vec::new(),
                labels: Vec::new(),
            },
            options: None,
        }
    }
    pub fn json(&self) -> Result<JsValue, serde_wasm_bindgen::Error> {
        serde_wasm_bindgen::to_value(self)
    }

    pub fn set_options(&mut self, options: &str) -> Result<(), serde_json::error::Error> {
        let json = serde_json::from_str(options)?;
        self.options = Some(json);
        Ok(())
    }
}


#[cfg(test)]
mod test {
    #[test]
    fn build_em() {
        let data = Vec::from([
            LatencyData {
                x: "Best-Case".to_string(),
                isp: 200.0,
                home: 210.0,
                app: 215.0,
            },
            LatencyData {
                x: "Typical-Case".to_string(),
                isp: 200.0,
                home: 310.0,
                app: 315.0,
            },
            LatencyData {
                x: "Worst-Case".to_string(),
                isp: 200.0,
                home: 510.0,
                app: 515.0,
            },
        ]);
        let options = serde_json::from_str(
            r#"
                {
                    "scales": {
                        "x": {
                            "stacked": true
                        },
                        "y": {
                            "stacked": true
                        }
                    }
                }
            "#,
        )
        .unwrap();
        // someone smarter would use iter() map() and zip() to one-liner this...
        let series = Vec::from([
            ChartDataSeries {
                data: data.clone(),
                label: Some("ISP Latency".to_string()),
                parsing: Some(serde_json::from_str(r#" { "yAxisKey": "isp"}"#).unwrap()),
            },
            ChartDataSeries {
                data: data.clone(),
                label: Some("Home Network Latency".to_string()),
                parsing: Some(serde_json::from_str(r#" { "yAxisKey": "home"}"#).unwrap()),
            },
            ChartDataSeries {
                data,
                label: Some("Application Latency".to_string()),
                parsing: Some(serde_json::from_str(r#" { "yAxisKey": "app"}"#).unwrap()),
            },
        ]);

        let datasets = ChartDataSets {
            datasets: series,
            labels: Vec::from(["Best-Case", "Typical-Case", "Worst-Case"].map(|s| s.to_string())),
        };

        let chart_config = ChartConfig {
            chart_type: "bar".to_string(),
            data: datasets,
            options: Some(options),
        };

        let cfg = serde_wasm_bindgen::to_value(&chart_config).unwrap();

    }
}