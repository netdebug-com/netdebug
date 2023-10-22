/**
 * Like common::perf_check!() but uses f64 counters from Window::Performance::now()
 */

#[macro_export]
macro_rules! perf_check {
    ($p:expr, $m:expr, $t:expr, $d:expr) => {
        (|| -> (f64, bool) {
            let now = $p.now();
            let passed = if (now - $t) > $d.as_millis() as f64 {
                console_log!(
                    "PERF_CHECK {}:{} failed: {} - {:?} > SLA of {:?}",
                    file!(),
                    line!(),
                    $m,
                    now - $t,
                    $d
                );
                false
            } else {
                true
            };
            (now, passed)
        })()
    };
}
