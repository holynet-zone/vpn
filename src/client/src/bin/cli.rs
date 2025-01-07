use std::{process, thread};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use clap::{Parser, Subcommand};
use client::runtime;
use client::network::find_available_ifname;

use runtime::base::Runtime;
use sunbeam::is_root;
use sunbeam::protocol::AUTH_KEY_SIZE;
use sunbeam::protocol::enc::{kdf, AuthEnc, BodyEnc};

const EVENT_CAPACITY: usize = 1024;
const EVENT_TIMEOUT: Duration = Duration::from_millis(1);
const KEEPALIVE: Duration = Duration::from_secs(10);


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
    /// connect to a server
    Connect {
        /// addr to connect
        #[arg(short, long)]
        addr: Option<String>,
        /// AuthEnc
        #[arg(short, long)]
        auth_enc: Option<AuthEnc>,
        /// username
        #[arg(short, long)]
        username: Option<String>,
        /// auth key
        #[arg(short, long)]
        auth_key: Option<String>,
        /// password
        #[arg(short, long)]
        password: Option<String>,
        /// config file
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,
        /// config key
        #[arg(short, long, value_name = "KEY")]
        key: Option<String>,
    }
}

fn main() {
    let running = Arc::new(AtomicBool::new(true));

    let file_appender = tracing_appender::rolling::daily("logs", "client.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false),
        )
        .with(fmt::layer().with_ansi(true))
        .init();
    log::set_max_level(log::LevelFilter::Info);
    if !is_root() {
        eprintln!("This program must be run as root");
        process::exit(1);
    }

    let args = Cli::parse();
    args.debug.then(|| log::set_max_level(log::LevelFilter::Debug));
    match args.command {
        Some(Commands::Connect {
                 addr,
                 auth_enc,
                 username,
                 auth_key,
                 password,
                 config,
                 key
             }) => {
            if auth_key.is_some() && password.is_some() {
                eprintln!("Cannot provide both auth key and password");
                process::exit(1);
            }
            let config = match config {
                Some(path) => {
                    match shared::conn_config::ConnConfig::load(&path) {
                        Ok(config) => config,
                        Err(e) => {
                            eprintln!("Failed to read config file: {}", e);
                            process::exit(1);
                        }
                    }
                },
                None => match key {
                    Some(key) => {
                        match shared::conn_config::ConnConfig::from_base64(&key) {
                            Ok(config) => config,
                            Err(e) => {
                                eprintln!("Failed to parse key: {}", e);
                                process::exit(1);
                            }
                        }
                    },
                    None => {
                        if addr.is_none() || auth_enc.is_none() || username.is_none() {
                            eprintln!("addr, auth_enc and username are required");
                            process::exit(1);
                        }
                        
                        let addr = addr.unwrap();
                        let auth_enc = auth_enc.unwrap();
                        let username = username.unwrap();
                        
                        let (host, port) = {
                            if let Ok(addr) = SocketAddr::from_str(&addr) {
                                (addr.ip().to_string(), addr.port())
                            } else {
                                let parts: Vec<&str> = addr.split(':').collect();
                                if parts.len() == 2 {
                                    let host = parts[0];
                                    let port = parts[1].parse::<u16>().map_err(|_| "Invalid port").unwrap();
                                    (host.to_string(), port)
                                } else {
                                    eprint!("Invalid address");
                                    process::exit(1);
                                }
                            }
                        };
                        let mut key = [0; AUTH_KEY_SIZE];
                        match auth_key {
                            Some(str_key) => {
                                key.copy_from_slice(STANDARD_NO_PAD.decode(str_key).map_err(|error| {
                                    format!("{}", error)
                                }).unwrap().as_slice());
                            },
                            None => {
                                if password.is_none() {
                                    eprintln!("auth_key or password is required");
                                    process::exit(1);
                                }
                                let password = password.unwrap();
                                match auth_enc {
                                    AuthEnc::Aes128 => {
                                        key.copy_from_slice(&kdf::derive_key_128(
                                            &username.as_bytes(),
                                            &password.as_bytes(),
                                            "holynet".as_bytes(),
                                        ));
                                    },
                                    AuthEnc::Aes256 | AuthEnc::ChaCha20Poly1305 => {
                                        key.copy_from_slice(&kdf::derive_key_256(
                                            &username.as_bytes(),
                                            &password.as_bytes(),
                                            "holynet".as_bytes(),
                                        ));
                                    },
                                };
                            }
                        };
                        shared::conn_config::ConnConfig {
                            server: shared::conn_config::Server {
                                host,
                                port,
                                enc: BodyEnc::ChaCha20Poly1305,
                            },
                            interface: shared::conn_config::Interface {
                                name: None,
                                mtu: 1400,
                            },
                            credentials: shared::conn_config::Credentials {
                                username,
                                auth_key: key,
                                enc: auth_enc
                            },
                        }
                    }
                }
            };
            
            let server_addr = match format!("{}:{}", config.server.host, config.server.port)
                .to_socket_addrs()
                .unwrap()
                .next()
            {
                Some(addr) => addr,
                None => {
                    eprintln!("Invalid address or unable to nslookup ip");
                    process::exit(1);
                }
            };

            let mut runtime = runtime::mita::SyncMio::new();
            runtime.set_config(runtime::base::Config {
                server_addr,
                client_addr: SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0),
                interface_name: config.interface.name.unwrap_or_else(|| find_available_ifname("holynet")),
                mtu: config.interface.mtu,
                event_capacity: EVENT_CAPACITY,
                event_timeout: Some(EVENT_TIMEOUT),
                keepalive: Some(KEEPALIVE),
                username: config.credentials.username,
                auth_key: config.credentials.auth_key,
                auth_enc: config.credentials.enc,
                body_enc: config.server.enc,
            });
            runtime.run();

            // let r = running.clone();
            
            ctrlc::set_handler(move || {
                runtime.stop();
                thread::sleep(Duration::from_secs(2));
                thread::current().unpark();
            }).expect("Error setting Ctrl-C handler");
            // while running.load(std::sync::atomic::Ordering::SeqCst) {}
            thread::park();
        },
        None => {
            eprintln!("No command provided");
            process::exit(1);
        }
    }
}
