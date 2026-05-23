use crate::command::Commands;
use crate::style::styles;
use crate::{LOG_DIR, LOG_PREFIX};
use clap::Parser;
use std::io::IsTerminal;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{EnvFilter, Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Parser)]
#[clap(
    about = "Holynet VPN command-line interface.",
    version,
    arg_required_else_help = true,
    styles = styles()
)]
pub struct Opt {
    #[clap(subcommand)]
    pub cmd: Commands,
    /// Enable debug logging
    #[arg(short, long, default_value = "false")]
    pub debug: bool,
}

impl Opt {
    pub fn init_logging(&self) -> anyhow::Result<WorkerGuard> {
        let appender = RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .filename_prefix(LOG_PREFIX)
            .build(LOG_DIR)?;

        let (non_blocking, guard) = tracing_appender::non_blocking(appender);

        let filter = if self.debug {
            "holynet=debug,holynet_sdk=debug"
        } else {
            "holynet=info,holynet_sdk=info"
        };

        let file_layer = fmt::layer()
            .with_writer(non_blocking)
            .with_ansi(false)
            .with_filter(EnvFilter::new(filter));

        let console_layer = fmt::layer()
            .with_ansi(std::io::stdout().is_terminal())
            .with_filter(EnvFilter::new(filter));

        tracing_subscriber::registry()
            .with(file_layer)
            .with(console_layer)
            .init();

        Ok(guard)
    }
}
