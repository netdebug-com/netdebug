/**
 * Init logging framework with useful defaults.
 * Alst sets RUST_BACKTRACE is not explicitly set in the env
 */
pub fn init_logging() {
    // if RUST_LOG isn't set explicitly, set RUST_LOG=info as a default
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    // if RUST_BACKTRACE isn't set explicitly, set RUST_BACKTRACE=1 as a default
    if std::env::var("RUST_BACKTRACE").is_err() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }
    env_logger::Builder::from_default_env()
        .format(|fmt, record| {
            use std::io::Write;
            let level_style = fmt.default_level_style(record.level());
            let ts = fmt.timestamp_millis();

            writeln!(
                fmt,
                "{} {} {} L{} > {}",
                ts,
                level_style.value(record.level()),
                record.target(),
                record.line().unwrap_or(0),
                record.args()
            )
        })
        .init();
}

/**
 * The `panic!()` macro will only terminate the currently executing thread but
 * not the rest of the process. This utility function sets a panic hook that
 * will abort the whole process;
 */
pub fn set_abort_on_panic() {
    use std::panic;
    let orig_panic_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        orig_panic_hook(panic_info);
        std::process::abort();
    }));
}

pub fn netdebug_init() {
    set_abort_on_panic();
    init_logging();
}
