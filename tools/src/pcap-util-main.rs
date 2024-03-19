use clap::{Parser, Subcommand};

use pcap_util_lib::{hacky_command, HackyCmdArgs, SumdumpCmdArgs};

#[derive(Debug, Subcommand)]
enum CliCommands {
    Sumdump(SumdumpCmdArgs),
    Hacky(HackyCmdArgs),
}

#[derive(clap::Parser, Debug)]
struct Args {
    #[command(subcommand)]
    command: CliCommands,
}

pub fn main() {
    // if RUST_LOG isn't set explicitly, set RUST_LOG=debug as a default
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "debug");
    }
    common::init::netdebug_init();
    let args = Args::parse();

    match args.command {
        CliCommands::Sumdump(_sumdump_args) => todo!(),
        CliCommands::Hacky(hacky_args) => hacky_command(hacky_args),
    }
}
