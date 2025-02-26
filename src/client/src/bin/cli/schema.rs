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
        /// addr to connect
        #[arg(short, long)]
        addr: Option<String>,
        /// username
        #[arg(short, long)]
        username: Option<String>,
        /// auth key
        #[arg(short, long)]
        auth_key: Option<String>,
        /// password
        #[arg(short, long)]
        password: Option<String>,
        /// config file
        #[arg(short, long, value_name = "FILE PATH")]
        config: Option<PathBuf>,
        /// config key
        #[arg(short, long, value_name = "KEY")]
        key: Option<String>,
    }
}