use colored::Colorize;
use std::io::Write;

/**
 * Init logging framework with useful defaults.
 * Alst sets RUST_BACKTRACE is not explicitly set in the env
 */
pub fn init_logging() {
    init_logging_with_level("info");
}
pub fn init_logging_with_level(log_level: &str) {
    // if RUST_LOG isn't set explicitly, set RUST_LOG=info as a default
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", log_level);
    }
    // if RUST_BACKTRACE isn't set explicitly, set RUST_BACKTRACE=1 as a default
    if std::env::var("RUST_BACKTRACE").is_err() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }
    env_logger::Builder::from_default_env()
        .format(|fmt, record| {
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
        // TODO:
        // This is a quick hack to make it easier for the desktop and electron
        // to figure out what exactly is the panic/error message to display to
        // the user.
        // Eventually, we should distinguish between "expected" errors like
        // address-in-use or no permission for pcap and simply display these
        // in a nicer way.
        eprintln!(
            "##PANIC-MSG-START##\n{}\n##PANIC-MSG-END##",
            panic_info.to_string().red() //panic_info
        );
        let _ = std::io::stderr().flush();
        orig_panic_hook(panic_info);
        std::process::abort();
    }));
}

pub fn netdebug_init() {
    set_abort_on_panic();
    init_logging();
}

// NOTE: we need these for integration testing as well
// as unit testing, so we should not wrap with #[cfg(test)]
use std::sync::Once;
static START: Once = Once::new();

pub fn netdebug_test_init() {
    // for tests, by default, only log on 'error' so we don't get
    // extra messages on 'cargo t' because 'cargo t' doesn't know how
    // to capture log messages
    //
    // BUT, if you're debugging a specific test, you can always pass
    // RUST_LOG=info cargo t
    START.call_once(|| init_logging_with_level("error"));
}
