use super::style::styles;
use crate::command::Commands;
use crate::{LOG_DIR, LOG_PREFIX};
use clap::Parser;
use std::io::IsTerminal;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, Layer};

#[derive(Debug, Parser)]
#[clap(about = "The Holynet vpn client command-line interface.", version, arg_required_else_help = true, styles=styles())]
pub struct Opt {
    #[clap(subcommand)]
    pub cmd: Commands,
    /// Turn debugging information on
    ///
    /// This will enable verbose logging
    #[arg(short, long, default_value = "false")]
    pub debug: bool
}

impl Opt {
    pub fn init_logging(&self) {
        let log_level = LevelFilter::from_level(if self.debug {
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
            .with_ansi(std::io::stdout().is_terminal())
            .with_filter(log_level);
        
        tracing_subscriber::registry()
            .with(file_layer)
            .with(console_layer)
            .init();
        
    }
}
