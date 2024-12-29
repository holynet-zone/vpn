use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {

    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    pub(crate) config: Option<PathBuf>,

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
        /// host to listen; default is 0.0.0.0
        #[arg(short, long, default_value = "0.0.0.0")]
        host: String,
        
        /// port to listen; default is 26256
        #[arg(short, long, default_value = "26256")]
        port: u16,
        
    },
    
    /// dev operations
    Dev {
        #[command(subcommand)]
        commands: DevCommands,
    },
}

#[derive(Subcommand)]
pub enum DevCommands {
    /// tun management
    Tun {
        #[command(subcommand)]
        commands: TunCommands
    },
    /// enable or disable ipv4 forwarding
    Ipv4Forwarding {
        /// enable or disable ipv4 forwarding
        #[command(subcommand)]
        commands: Ipv4ForwardingCommands,
    }
}

#[derive(Subcommand)]
pub enum Ipv4ForwardingCommands {
    /// enable ipv4 forwarding
    True,

    /// disable ipv4 forwarding
    False
}

#[derive(Subcommand)]
pub enum TunCommands {
    /// up tun interface
    Up,

    /// down tun interface
    Down,

    /// show tun interface status
    Status
}