use crate::command::connect::ConnectCmd;
use clap::Subcommand;

mod connect;

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// connect to a server
    Connect(ConnectCmd)
}
