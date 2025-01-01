mod exceptions;
mod handlers;
mod cli;
mod clients;
mod config;

use std::{process, thread};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};
use tracing_appender;

use clap::Parser;
use log::LevelFilter;
use tun::AbstractDevice;
use crate::cli::{Cli, Commands, DevCommands};
use crate::exceptions::ServerExceptions;
use crate::handlers::output_event;
use core::{DATA_SIZE, MAX_PACKET_SIZE};
use core::net::{down_tun, set_ipv4_forwarding, setup_tun, tun_status};

use mio::{Events, Interest, Poll, Token};
use mio::net::UdpSocket as MioUdpSocket;
use crate::clients::Clients;

const INTERFACE_NAME: &str = "holynet0";
const NETWORK_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 8, 0, 0));
const NETWORK_PREFIX: u8 = 24;
const EVENT_CAPACITY: usize = 1024;
const UDP: Token = Token(0);
const TUN: Token = Token(1);
const UDP_BUFFER_SIZE: usize = 65536;
const TUN_BUFFER_SIZE: usize = 65536;


fn start(address: &str) {

    let address: SocketAddr = address.parse().map_err(|error| {
        error!("Failed to parse the server address: {}", error);
        process::exit(1);
    }).unwrap();

    let socket = UdpSocket::bind(address).map_err(|error| {
        error!("Failed to bind the server socket: {}", error);
        process::exit(1);
    }).unwrap();
    let mut mio_socket = MioUdpSocket::from_std(socket);
    let clients: Arc<Clients> = Arc::new(Clients::new(&Ipv4Addr::from_str(&NETWORK_IP.to_string()).unwrap(), &NETWORK_PREFIX)); // todo: to IpAddr (ipv6)
    
    let mut tun = setup_tun(INTERFACE_NAME, &DATA_SIZE, &NETWORK_IP, &NETWORK_PREFIX).map_err(|error| {
        error!("{}", error);
        process::exit(1);
    }).unwrap();
    let tun_raw_fd = tun.as_raw_fd();
    let mut tunfd = mio::unix::SourceFd(&tun_raw_fd);

    info!("Server started on {}", address);

    info!("Enabling kernel's IPv4 forwarding.");
    set_ipv4_forwarding(true).unwrap();

    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(EVENT_CAPACITY);
    poll.registry()
        .register(&mut mio_socket, UDP, Interest::READABLE).unwrap();
    poll.registry()
        .register(&mut tunfd, TUN, Interest::READABLE).unwrap();

    let mut udp_buffer = [0u8; UDP_BUFFER_SIZE];
    let mut tun_buffer = [0u8; TUN_BUFFER_SIZE];
    
    loop {
        poll.poll(&mut events, None).unwrap();
        for event in events.iter() {
            match event.token() {
                UDP => {
                    match mio_socket.recv_from(&mut udp_buffer) {
                        Ok((n, client_addr)) => {
                            handlers::input_event(
                                &udp_buffer[0..n],
                                &mut tun,
                                &mut mio_socket,
                                &client_addr,
                                clients.clone(),
                                DATA_SIZE
                            ).unwrap_or_else(|error| match error {
                                ServerExceptions::BadPacketRequest(msg) => warn!("{}", msg),
                                _ => unreachable!()
                            });
                        }
                        Err(e) => {
                            error!("Failed to receive data: {}", e); // Todo check if just client error
                        }
                    }
                    udp_buffer.fill(0)
                }
                TUN => {
                    match tun.read(&mut tun_buffer) {
                        Ok(n) => {
                            output_event(
                                &tun_buffer[0..n],
                                &mut mio_socket,
                                clients.clone()
                            ).unwrap_or_else(|error| match error {
                                ServerExceptions::BadPacketRequest(msg) => warn!("{}", msg),
                                ServerExceptions::IOError(msg) => error!("{}", msg),
                                _ => {}
                            });
                        },
                        Err(e) => {
                            error!("Failed to receive data: {}", e); // Todo check if just client error
                        }
                    }
                    tun_buffer.fill(0)
                }
                _ => unreachable!(),
            }
        }
    }
}


fn main() {
    let file_appender = tracing_appender::rolling::daily("logs", "server.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false),
        )
        .with(fmt::layer().with_ansi(true))
        .init();

    let cli = Cli::parse();
    match cli.debug {
        true => log::set_max_level(LevelFilter::Debug),
        false => log::set_max_level(LevelFilter::Info),
    }

    match cli.command {
        Some(command) => match command {
            Commands::Start { host, port } => {
                start(&format!("{}:{}", host, port));
            },
            Commands::Dev { commands } => {
                match commands {
                    DevCommands::Tun {commands} => match commands {
                        cli::TunCommands::Up => {
                            let tun = setup_tun(
                                INTERFACE_NAME, 
                                &DATA_SIZE,
                                &NETWORK_IP, 
                                &NETWORK_PREFIX
                            ).map_err(|error| {
                                error!("{}", error);
                                process::exit(1);
                            }).unwrap();
                            println!(
                                "\n\tname: {}\n\tmtu: {}\n\taddr: {}\n\tnetmask: {}\n",
                                tun.tun_name().unwrap_or("none".to_string()), 
                                tun.mtu().map(|mtu| mtu.to_string()).unwrap_or("none".to_string()),
                                tun.address().map(|addr| addr.to_string()).unwrap_or("none".to_string()),
                                tun.netmask().map(|mask| mask.to_string()).unwrap_or("none".to_string())
                            );
                            println!(
                                "|> TUN interface has been successfully raised and will remain in this state\
                                \n|> until this application is terminated or 15 minutes have passed,\
                                \n|> after which the interface will be automatically removed!"
                            );
                            thread::sleep(Duration::from_secs(60 * 15));
                        },
                        cli::TunCommands::Down => {
                            down_tun(INTERFACE_NAME).map_err(|error| {
                                error!("{}", error);
                                process::exit(1);
                            }).unwrap();
                        },
                        cli::TunCommands::Status => {
                            let tun = tun_status(INTERFACE_NAME).map_err(|error| {
                                error!("{}", error);
                                process::exit(1);
                            }).unwrap();
                            println!(
                                "\n\tname: {}\n\tstate: {:?}\n\tmtu: {}\n\taddr: {}\n\tnetmask: {}\n",
                                tun.name, tun.state, tun.mtu, tun.ip, tun.netmask
                            );
                        }
                    },
                    DevCommands::Ipv4Forwarding { commands } => match commands {
                        cli::Ipv4ForwardingCommands::True => {
                            set_ipv4_forwarding(true).map_err(|error| {
                                error!("{}", error);
                                process::exit(1);
                            }).unwrap();
                        },
                        cli::Ipv4ForwardingCommands::False => {
                            set_ipv4_forwarding(false).map_err(|error| {
                                error!("{}", error);
                                process::exit(1);
                            }).unwrap();
                        }
                    }
                }
            }
        },
        None => {
            error!("No command provided");
            process::exit(1);
        }
    }
}
