// this file is included directly into the WASM module by a wasm_bindgen call
// NOTE: that even though this is javascript, it is *compile time* included
// into the .wasm object file so you need to recompile if you change this

export function plot_chart(chart, cfg, verbose) {
    const ctx = document.getElementById(chart);
    if (ctx == undefined) {
        throw "Unable to find document element with id " + chart;
    }
    try {
        if (verbose) {
            console.log(
                "Creating Chart on canvas " +
                    chart +
                    " :: " +
                    JSON.stringify(cfg, undefined, 2),
            );
        }
        return new Chart(ctx, cfg);
    } catch (err) {
        console.error(
            "Error creating Chart() with canvas='" +
                chart +
                "' " +
                "with cfg=" +
                cfg +
                " :: " +
                err,
        );
    }
}

export function plot_json_chart(chart, json, verbose) {
    let cfg = JSON.parse(json);
    return plot_chart(chart, cfg, verbose);
}

export function plot_json_chart_update(chart, data_json, verbose) {
    let data = JSON.parse(data_json);
    if (verbose) {
        console.log(
            "Setting new data to :: " + JSON.stringify(data, undefined, 2),
        );
    }
    // clear out the old data
    // chart.data.datasets.forEach((dataset) => {
    // dataset.data = [];
    // });
    // this is where I'd love to have some type checking
    chart.data.datasets = data;
    chart.update("none"); // 'none' says don't re-annimate with each update
}

export function plot_latency_chart(
    chart,
    best_isp,
    best_home,
    best_app,
    typical_isp,
    typical_home,
    typical_app,
    worst_isp,
    worst_home,
    worst_app,
    verbose,
) {
    const data = [
        { x: "Best-Case", isp: best_isp, home: best_home, app: best_app },
        {
            x: "Typical-Case",
            isp: typical_isp,
            home: typical_home,
            app: typical_app,
        },
        { x: "Worst-Case", isp: worst_isp, home: worst_home, app: worst_app },
    ];

    const cfg = {
        type: "bar",
        data: {
            labels: ["Best-Case", "Typical-Case", "Worst-Case"],
            datasets: [
                {
                    label: "ISP latency (ms)",
                    data: data,
                    parsing: {
                        yAxisKey: "isp",
                    },
                },
                {
                    label: "Home Network latency (ms)",
                    data: data,
                    parsing: {
                        yAxisKey: "home",
                    },
                },
                {
                    label: "Application latency (ms)",
                    data: data,
                    parsing: {
                        yAxisKey: "app",
                    },
                },
            ],
        },
        options: {
            scales: {
                x: {
                    stacked: true,
                },
                y: {
                    stacked: true,
                    title: {
                        display: true,
                        text: "RTT (milliseconds)",
                    },
                },
            },
        },
    };

    plot_chart(chart, cfg, verbose);
}
