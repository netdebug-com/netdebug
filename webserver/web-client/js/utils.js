// this file is included direction into the WASM module by a wasm_bindgen call

export function plot_chart(chart, cfg, verbose) {
    try {
        console.log("Creating Chart on canvas " + chart + " :: " + JSON.stringify(cfg))
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

export function plot_chart_test(chart) {
        plot_chart(chart, {
            type: 'bar',
            data: {
                datasets: [{
                    data: [20, 10],
                }],
                labels: ['a', 'b']
            }
        },
        true );
}