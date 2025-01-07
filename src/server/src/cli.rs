use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use derive_more::Display;
use sunbeam::protocol::enc::AuthEnc;


#[derive(Clone, Display)]
#[display("{}\t{:?}", username, enc)]
pub struct UserRow {
    pub username: String,
    pub enc: AuthEnc,
}


#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Turn debugging information on
    #[arg(short, long, default_value = "false")]
    pub(crate) debug: bool,

    #[command(subcommand)]
    pub(crate) command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// starts vpn server
    Start {
        /// host to listen
        #[arg(short, long)]
        host: Option<String>,
        /// port to listen
        #[arg(short, long)]
        port: Option<u16>,
        #[arg(short, long)]
        iface: Option<String>,
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,
        #[arg(short, long, value_name = "FILE")]
        storage: Option<PathBuf>,
        #[arg(short, long, default_value = "false")]
        daemon: bool,
    },
    /// Users management
    Users {
        #[command(subcommand)]
        commands: Option<UsersCommands>,
    },
    /// Lists all running VPN servers
    Servers,
    /// Shows logs for a specific VPN server
    Logs {
        /// ID of the VPN server to show logs for
        #[arg(short, long, value_name = "ID")]
        id: u32,
    },
    // /// dev operations
    // Dev {
    //     #[command(subcommand)]
    //     commands: DevCommands,
    // },
}

#[derive(Subcommand)]
pub enum UsersCommands {
    /// Add a new user
    Add {
        /// enc type
        #[arg(short, long)]
        enc: Option<AuthEnc>,
        /// username
        #[arg(short, long)]
        username: Option<String>,
        /// password
        #[arg(short, long)]
        password: Option<String>,
        #[arg(short, long)]
        host: Option<String>,
        #[arg(short, long)]
        port: Option<u16>
    },
    /// Remove a user
    Remove {
        /// username
        #[arg(short, long)]
        username: String,
    },
}

// 
// #[derive(Subcommand)]
// pub enum DevCommands {
//     /// tun management
//     Tun {
//         #[command(subcommand)]
//         commands: TunCommands
//     },
//     /// enable or disable ipv4 forwarding
//     Ipv4Forwarding {
//         /// enable or disable ipv4 forwarding
//         #[command(subcommand)]
//         commands: Ipv4ForwardingCommands,
//     }
// }
// 
// #[derive(Subcommand)]
// pub enum Ipv4ForwardingCommands {
//     /// enable ipv4 forwarding
//     True,
// 
//     /// disable ipv4 forwarding
//     False
// }
// 
// #[derive(Subcommand)]
// pub enum TunCommands {
//     /// up tun interface
//     Up,
// 
//     /// down tun interface
//     Down,
// 
//     /// show tun interface status
//     Status
// }