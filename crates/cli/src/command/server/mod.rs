pub mod nodes;
pub mod start;
pub mod users;

use crate::command::server::nodes::NodesCmd;
use crate::command::server::start::StartCmd;
use crate::command::server::users::UsersCmd;
use clap::{Args, Subcommand};
use std::path::PathBuf;

const CONFIG_PATH_ENV: &str = "HOLYNET_SERVER_CONFIG";

#[derive(Debug, Args)]
pub struct ServerCmd {
    #[clap(subcommand)]
    pub cmd: ServerCommands,
    /// Server config file path
    #[clap(long, default_value = "config.toml", env = CONFIG_PATH_ENV, value_name = "FILE")]
    pub config: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum ServerCommands {
    /// Start the VPN server
    Start(StartCmd),
    /// Manage users
    #[clap(subcommand)]
    Users(UsersCmd),
    /// Manage the multi-node registry (import authority-signed records)
    #[clap(subcommand)]
    Nodes(NodesCmd),
    /// Print this node's public key (for `holynet authority sign --node-pk`)
    Pubkey,
}
