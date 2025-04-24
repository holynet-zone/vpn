mod start;
mod users;

use clap::Subcommand;
use crate::command::{
    start::StartCmd,
    users::UsersCmd
};

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start VPN server
    Start(StartCmd),
    /// Users management
    #[clap(subcommand)]
    Users(UsersCmd),
    /// Monitor VPN server
    Monitor,
    /// Shows VPN server logs
    Logs
    // /// dev operations
    // Dev {
    //     #[command(subcommand)]
    //     commands: DevCommands,
    // },
}