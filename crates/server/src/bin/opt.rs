use std::{path::PathBuf, io::IsTerminal, fs};
use std::path::Path;
use chrono::Local;
use clap::Parser;
use tracing::{debug, info};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, fmt, Layer, EnvFilter};
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
    pub fn init_logging(&mut self) -> anyhow::Result<WorkerGuard> {
        let appender = RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .filename_prefix(LOG_PREFIX)
            .build(LOG_DIR)?;
        
        let (non_blocking, guard) = tracing_appender::non_blocking(appender);

        let filter = if self.debug { "server=debug" } else { "server=info" };
        
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

    pub fn load_config(&self, auto_create: bool) -> anyhow::Result<config::Config> {
        debug!("loading configuration from file: {}", self.config.display());

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
