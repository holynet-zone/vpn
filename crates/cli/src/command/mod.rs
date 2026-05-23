pub mod connect;
pub mod server;

use clap::Subcommand;
use connect::ConnectCmd;
use server::ServerCmd;

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Connect to a VPN server
    Connect(ConnectCmd),
    /// Server management
    #[clap(subcommand_required = true)]
    Server(ServerCmd),
}
