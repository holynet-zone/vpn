pub mod connect;
pub mod nodes;
pub mod server;

use clap::Subcommand;
use connect::ConnectCmd;
use nodes::NodesCmd;
use server::ServerCmd;

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Connect to a VPN server
    Connect(ConnectCmd),
    /// List nodes the server sees (multi-node registry)
    Nodes(NodesCmd),
    /// Server management
    #[clap(subcommand_required = true)]
    Server(ServerCmd),
}
