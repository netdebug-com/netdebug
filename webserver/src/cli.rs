use std::error::Error;

use clap::Parser;
use libconntrack::analyze::{self, connection_from_log};

#[derive(Parser, Debug)]
/// NetDebug CLI
struct Args {
    /// Analyze a Connection log
    #[arg(long)]
    analyze_log: String,

    /// Print Probe Summary Report
    #[arg(long, default_value_t = false)]
    print_probe_summary: bool,

    /// Print a single probe run
    #[arg(long, default_value = None)]
    print_probe_report: Option<u32>,
}

fn main() -> Result<(), Box<dyn Error>> {
    common::init::netdebug_init();
    let args = Args::parse();

    let connection = connection_from_log(&args.analyze_log)?;

    if args.print_probe_summary {
        println!(
            "Probe Report Summary:\n{}",
            connection.probe_report_summary()
        );
    } else if let Some(probe_run) = args.print_probe_report {
        if let Some(probe_report) = connection
            .probe_report_summary()
            .raw_reports
            .get(probe_run as usize)
        {
            println!("Probe report {} -- {}", probe_run, probe_report);
        } else {
            println!("Probe report {} not found", probe_run);
        }
    } else {
        let insights = analyze::analyze(connection.probe_report_summary());
        for insight in insights {
            println!("{}", insight);
        }
    }

    Ok(())
}
