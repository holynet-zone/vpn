mod schema;
mod actions;

use clap::Parser;
use std::process;
use tracing_subscriber::fmt;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use crate::schema::{Cli, Commands};

const LOG_DIR: &str = "logs";
const LOG_PREFIX: &str = "client.log";


fn main() {
    let args = Cli::parse();
    args.debug.then(|| log::set_max_level(log::LevelFilter::Debug));
    match args.command {
        Commands::Connect { config, key } => {
            let log_level = if args.debug {
                tracing::Level::DEBUG
            } else {
                tracing::Level::INFO
            };
            
            let file_appender = tracing_appender::rolling::daily(LOG_DIR, LOG_PREFIX);
            let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
            tracing_subscriber::registry()
                .with(fmt::layer()
                          .with_writer(non_blocking)
                          .with_ansi(false)
                          .with_max_level(log_level)
                )
                .with(fmt::layer()
                    .with_ansi(true)
                    .with_max_level(log_level)
                )
                .init();
            
            actions::connect(config, key).map_err(|error| {
                eprintln!("{}", error);
                process::exit(1);
            }).unwrap();
        }
    }
}
