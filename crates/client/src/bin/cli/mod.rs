mod schema;
mod actions;

use clap::Parser;
use std::process;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, Layer};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use crate::schema::{Cli, Commands};

const LOG_DIR: &str = "logs";
const LOG_PREFIX: &str = "client.log";

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args = Cli::parse();
    match args.command {
        Commands::Connect { config, key } => {
            let log_level = LevelFilter::from_level(if args.debug {
                tracing::Level::DEBUG
            } else {
                tracing::Level::INFO
            });
            
            let file_appender = tracing_appender::rolling::daily(LOG_DIR, LOG_PREFIX);
            let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

            let file_layer = fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false)
                .with_filter(log_level);

            let console_layer = fmt::layer()
                .with_ansi(true)
                .with_filter(log_level);

            tracing_subscriber::registry()
                .with(file_layer)
                .with(console_layer)
                .init();
            
            if let Err(err ) = actions::connect(config, key).await {
                eprintln!("{}", err);
                process::exit(1);
            }
        }
    }
}
