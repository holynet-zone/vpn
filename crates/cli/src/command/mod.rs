pub mod authority;
pub mod connect;
pub mod nodes;
pub mod route;
pub mod server;

use authority::AuthorityCmd;
use clap::Subcommand;
use connect::ConnectCmd;
use nodes::NodesCmd;
use route::RouteCmd;
use server::ServerCmd;

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Connect to a VPN server
    Connect(ConnectCmd),
    /// List nodes the server sees (multi-node registry)
    Nodes(NodesCmd),
    /// Compute the lowest-latency multi-hop path to the connection's target
    Route(RouteCmd),
    /// Network authority: generate a key and sign node records (operator side)
    #[clap(subcommand)]
    Authority(AuthorityCmd),
    /// Server management
    #[clap(subcommand_required = true)]
    Server(ServerCmd),
}
