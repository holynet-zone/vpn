use std::path::PathBuf;

use clap::{Parser, Subcommand};
use derive_more::Display;
use super::style::styles;


#[derive(Clone, Display)]
#[display("{}\tcreated at {}", pk, created_at)]
pub struct UserRow {
    pub pk: String,
    pub created_at: String,
}


#[derive(Parser)]
#[command(version, about, long_about = None, arg_required_else_help = true, styles=styles())]
pub struct Cli {
    /// Turn debugging information on
    #[arg(short, long, default_value = "false")]
    pub debug: bool,

    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start VPN server
    Start {
        /// host to listen
        #[arg(short, long)]
        host: Option<String>,
        /// port to listen
        #[arg(short, long)]
        port: Option<u16>,
        #[arg(short, long)]
        iface: Option<String>
    },
    /// Users management
    Users {
        #[command(subcommand)]
        commands: UsersCommands,
    },
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

#[derive(Subcommand)]
pub enum UsersCommands {
    /// Add a new user
    Add {
        #[arg(short, long)]
        /// server host
        host: Option<String>,
        #[arg(short, long)]
        /// server port
        port: Option<u16>,
        /// secret key (hex)
        #[arg(short, long)]
        sk: Option<String>,
        /// pre shared key (hex)
        #[arg(short, long)]
        psk: Option<String>
    },
    /// List all users
    List,
    /// Remove a user
    Remove {
        /// public key (hex)
        #[arg(short, long)]
        pk: String,
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