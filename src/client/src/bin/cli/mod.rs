mod schema;
mod actions;

use clap::Parser;
use std::time::Duration;
use std::process;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::schema::{Cli, Commands};
use sunbeam::is_root;

const EVENT_CAPACITY: usize = 1024;
const KEEPALIVE: Duration = Duration::from_secs(10);


fn main() {
    let file_appender = tracing_appender::rolling::daily("logs", "client.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false),
        )
        .with(fmt::layer().with_ansi(true))
        .init();
    log::set_max_level(log::LevelFilter::Info);

    let args = Cli::parse();
    args.debug.then(|| log::set_max_level(log::LevelFilter::Debug));
    match args.command {
        Commands::Connect {
             addr,
             username,
             auth_key,
             password,
             config,
             key
        } => {
            if !is_root() {
                eprintln!("This program must be run as root");
                process::exit(1);
            } // todo: remove it
            actions::connect(Commands::Connect {
                addr,
                username,
                auth_key,
                password,
                config,
                key
            }).map_err(|error| {
                eprintln!("Failed to connect: {}", error);
                process::exit(1);
            }).unwrap();
        }
    }
}
