use std::{path::PathBuf, io::IsTerminal};
use clap::Parser;
use tracing::info;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, fmt, Layer};
use server::config;
use crate::{LOG_DIR, LOG_PREFIX, CONFIG_PATH_ENV};
use crate::command::Commands;
use super::style::styles;

#[derive(Debug, Parser)]
#[clap(about = "The Holynet vpn server command-line interface.", version, arg_required_else_help = true, styles=styles())]
pub struct Opt {
    #[clap(subcommand)]
    pub cmd: Commands,
    /// Config file path
    #[clap(
        long,
        default_value = "config.toml",
        env = CONFIG_PATH_ENV,
        value_name = "FILE"
    )]
    pub config: PathBuf,
    /// Turn debugging information on
    ///
    /// This will enable verbose logging
    #[arg(short, long, default_value = "false")]
    pub debug: bool
}

impl Opt {
    pub fn init_logging(&mut self) {
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

    pub fn load_config(&self, auto_create: bool) -> anyhow::Result<config::Config> {
        info!("loading configuration from file: {}", self.config.display());

        match self.config.exists() {
            false => match auto_create {
                false => Err(anyhow::anyhow!("config file does not exist")),
                true => {
                    info!("no configuration provided, using default config");
                    let default_config = config::Config::default();
                    default_config.save_as(&self.config)?;
                    Ok(default_config)
                }
            },
            true => config::Config::load(&self.config)
        }
    }
}
