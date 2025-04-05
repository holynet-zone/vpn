use std::path::PathBuf;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about, long_about = None, arg_required_else_help = true)]
pub struct Cli {
    /// Turn debugging information on
    #[arg(short, long, default_value = "false")]
    pub debug: bool,

    #[command(subcommand)]
    pub command: Commands
}

#[derive(Subcommand)]
pub enum Commands {
    /// connect to a server
    Connect {
        /// config file
        #[arg(short, long, value_name = "FILE PATH")]
        config: Option<PathBuf>,
        /// config key
        #[arg(short, long, value_name = "KEY")]
        key: Option<String>,
    }
}