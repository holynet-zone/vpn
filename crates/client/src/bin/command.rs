use std::path::PathBuf;
use clap::Subcommand;
use crate::command::connect::ConnectCmd;

mod connect;

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// connect to a server
    Connect(ConnectCmd)
}
