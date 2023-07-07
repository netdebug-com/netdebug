// this file is included directly into the WASM module by a wasm_bindgen call
// NOTE: that even though this is javascript, it is *compile time* included
// into the .wasm object file so you need to recompile if you change this

export function json_parse(s) {
    return JSON.parse(s)
}

export function plot_chart(chart, cfg, verbose) {
    try {
        console.log("Creating Chart on canvas " + chart + " :: " + JSON.stringify(cfg, undefined, 2))
        const ctx = document.getElementById(chart);
        let chart_obj = new Chart(ctx, cfg );
        if (verbose) {
            console.log(chart_obj)
        }
    }
    catch(err) {
        console.error("Error creating Chart() with cfg=" + cfg + " :: " + err)
    }
}

export function plot_latency_chart(chart, 
    best_isp,
    best_home,
    best_app,
    typical_isp,
    typical_home,
    typical_app,
    worst_isp,
    worst_home,
    worst_app,
    verbose) {

    const data = [
        {x: "Best-Case", isp: best_isp, home: best_home, app: best_app},
        {x: "Typical-Case", isp: typical_isp, home: typical_home, app: typical_app},
        {x: "Worst-Case", isp: worst_isp, home: worst_home, app: worst_app},

    ];

    const cfg = {
        type: 'bar',
        data: {
            labels: ['Best-Case', 'Typical-Case', 'Worst-Case'],
            datasets: [{
                label: 'ISP latency (ms)',
                data: data,
                parsing: {
                    yAxisKey: 'isp'
                }
            }, {
                label: 'Home Network latency (ms)',
                data: data,
                parsing: {
                    yAxisKey: 'home'
                }
            }, {
                label: 'Application latency (ms)',
                data: data,
                parsing: {
                    yAxisKey: 'app'
                }
            }]
        },
        options: {
            scales: {
                x: {
                    stacked: true
                },
                y: {
                    stacked: true
                }
            },
        },
    };

    plot_chart(chart, cfg, verbose);
}