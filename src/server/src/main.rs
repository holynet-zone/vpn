use crate::runtime::base::{Runtime, RuntimeConfig};
mod cli;
mod config;
mod runtime;
mod session;
mod client;
mod daemon;
mod network;

use std::{process, thread};
use std::time::Duration;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, filter, reload, layer::SubscriberExt, util::SubscriberInitExt};

use tracing_appender;

use clap::Parser;
use inquire::Select;
use log::LevelFilter;
use rocksdb::DB;
use sunbeam::{
    protocol::{
        enc::{AuthEnc, kdf}
    }
};
use shared::conn_config:: {
    ConnConfig,
    Server,
    Credentials,
    Interface
};
use sunbeam::protocol::AUTH_KEY_SIZE;
use sunbeam::protocol::enc::{BodyEnc, IntoEnumIterator};
use crate::cli::{Cli, Commands, UserRow};
use crate::client::{delete_client, get_clients, save_client, Client};
const CONFIG_PATH_ENV: &str = "CONFIG_PATH";
const STORAGE_PATH_ENV: &str = "STORAGE_PATH";


fn main() {
    let cli = Cli::parse();

    let file_appender = tracing_appender::rolling::daily("logs", "server.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    let filter = filter::LevelFilter::INFO;
    let (filter, reload_handle) = reload::Layer::new(filter);
    tracing_subscriber::registry()
        .with(filter)
        .with(
            fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false),
        )
        .with(fmt::layer().with_ansi(true))
        .init();
    
    cli.debug.then(|| reload_handle.modify(|filter| *filter = filter::LevelFilter::DEBUG));
    match cli.command {
        Some(command) => match command {
            Commands::Start { 
                host, 
                port, 
                iface, 
                config, 
                storage, 
                daemon 
            } => {

                if daemon {
                    unimplemented!("Daemon mode is not implemented");
                }
                
                // todo logs for daemon

                let mut need_save_cfg = false;
                let mut config = match config {
                    Some(path) => config::Config::load(path.to_str().unwrap()).map_err(|error| {
                        error!("Failed to load configuration ({:?}): {}", path, error);
                        process::exit(1);
                    }).unwrap(),
                    None => match std::env::var(CONFIG_PATH_ENV) {
                        Ok(dir) => {
                            info!("Loading configuration from env: {}", dir);
                            config::Config::load(dir.as_str()).map_err(|error| {
                                error!("Failed to load configuration: {}", error);
                                process::exit(1);
                            }).unwrap()
                        },
                        Err(_) => {
                            warn!("No configuration provided, using default values");
                            need_save_cfg = true;
                            config::Config::default()
                        }
                    }
                };

                if let Some(host) = host {
                    config.general.host = host.parse().unwrap();
                }
                if let Some(port) = port {
                    config.general.port = port;
                }
                if let Some(iface) = iface {
                    config.interface.name = iface;
                } else {
                    config.interface.name = network::find_available_ifname("holynet");
                }
                if let Some(storage) = std::env::var(STORAGE_PATH_ENV).ok() {
                    config.general.storage_path = storage.into();
                }
                if let Some(storage) = storage {
                    config.general.storage_path = storage;
                }

                if need_save_cfg {
                    config.save("config.toml").map_err(|error| {
                        error!("Failed to save configuration: {}", error);
                        process::exit(1);
                    }).unwrap();
                }
                
                let mut runtime = runtime::mita::Mita::new();
                runtime.set_config(RuntimeConfig{
                    server_addr: format!("{}:{}", config.general.host, config.general.port).parse().unwrap(),
                    network_ip: config.interface.address,
                    network_prefix: config.interface.prefix,
                    mtu: config.interface.mtu,
                    interface_name: config.interface.name,
                    event_capacity: config.runtime.event_capacity as usize,
                    event_timeout: config.runtime.event_timeout.map(|timeout| Duration::from_secs(timeout)),
                    storage_path: "database".to_string(),
                });
                log::set_max_level(LevelFilter::Info);
                runtime.run();
                thread::park();
            },
            Commands::Users { commands } => {
                let storage_path = std::env::var(STORAGE_PATH_ENV).unwrap_or_else(|_| "database".to_string()); // todo: from --storage
                let mut opts = rocksdb::Options::default();
                opts.create_if_missing(true);
                let db = DB::open(&opts, storage_path).map_err(|error| {
                    error!("Failed to open the database: {}", error);
                    process::exit(1);
                }).unwrap();
                match commands {
                    Some(commands) => match commands {
                        cli::UsersCommands::Add { 
                            enc, 
                            username, 
                            password, 
                            host, 
                            port 
                        } => {
                            let enc = enc.unwrap_or_else(|| {
                                let enc_options: Vec<AuthEnc> = AuthEnc::iter().collect();
                                let enc_strings: Vec<String> = enc_options.iter().map(|e| format!("{:?}", e)).collect();
                                let selected_enc = match Select::new("Choose an encryption type:", enc_strings).prompt() {
                                    Ok(selected) => selected,
                                    Err(error) => {
                                        error!("{}", error);
                                        process::exit(1);
                                    }
                                };
                                enc_options.iter().find(|e| format!("{:?}", e) == selected_enc).unwrap().clone()
                            });
                            let host = host.unwrap_or_else(|| {
                                let host = inquire::Text::new("Enter a server host:")
                                    .with_default("127.0.0.1")
                                    .prompt()
                                    .unwrap();
                                if host.is_empty() {
                                    error!("Host cannot be empty");
                                    process::exit(1);
                                }
                                host
                            });
                            let port = port.unwrap_or_else(|| {
                                let port = inquire::Text::new("Enter a server port:")
                                    .with_default("26256")
                                    .prompt()
                                    .unwrap();
                                if port.is_empty() {
                                    error!("Port cannot be empty");
                                    process::exit(1);
                                }
                                port.parse().unwrap()
                            });
                            let username = username.unwrap_or_else(|| {
                                let username = inquire::Text::new("Enter a username (up to 128 characters):")
                                    .with_help_message("Username cannot be empty")
                                    .prompt()
                                    .unwrap();
                                if username.is_empty() {
                                    error!("Username cannot be empty");
                                    process::exit(1);
                                }
                                username
                            });
                            let password = password.unwrap_or_else(|| {
                                let password = inquire::Password::new("Enter a password:")
                                    .with_help_message("Password cannot be empty")
                                    .prompt()
                                    .unwrap();
                                if password.is_empty() {
                                    error!("Password cannot be empty");
                                    process::exit(1);
                                }
                                password
                            });
                            let mut key = [0u8; AUTH_KEY_SIZE];
                            match enc {
                                AuthEnc::Aes128 => {
                                    key[..16].copy_from_slice(&kdf::derive_key_128(
                                        &username.as_bytes(),
                                        password.as_bytes(),
                                        "holynet".as_bytes()
                                    ));
                                },
                                AuthEnc::Aes256 | AuthEnc::ChaCha20Poly1305 => {
                                    key[..32].copy_from_slice(&kdf::derive_key_256(
                                        &username.as_bytes(), 
                                        password.as_bytes(), 
                                        "holynet".as_bytes()
                                    ));
                                },
                            };
                            save_client(
                                &username.as_bytes(),
                                Client{
                                    enc: enc.clone(),
                                    auth_key: key
                                },
                                &db
                            );
                            println!("User {} has been successfully added", username);
                            let config_file = username.clone() + ".toml";
                            let config = ConnConfig {
                                server: Server {
                                    host,
                                    port,
                                    enc: BodyEnc::ChaCha20Poly1305,
                                },
                                interface: Interface {
                                    name: None,
                                    mtu: 1400,
                                },
                                credentials: Credentials {
                                    username,
                                    auth_key: key,
                                    enc
                                }
                            };
                            config.save(&config_file.parse().unwrap()).map_err(|error| {
                                error!("Failed to save configuration: {}", error);
                                process::exit(1);
                            }).unwrap();
                            println!("Configuration file has been saved to {}", config_file);
                            println!("First insert: {}", config.to_base64().unwrap());
                        },
                        cli::UsersCommands::Remove { username } => {
                            delete_client(&username.as_bytes(), &db);
                            println!("User {} has been successfully removed", username);
                        }
                    },
                    None => {
                        let users = get_clients(&db).iter().map(|(username, data)| {
                            UserRow {
                                username: username.clone(),
                                enc: data.enc.clone()
                            }
                        }).collect();
                        let selected_username = match Select::new("Choose a user:", users).prompt() {
                            Ok(selected) => {
                                selected.username
                            },
                            Err(error) => {
                                error!("{}", error);
                                process::exit(1);
                            }
                        };
                    }
                }

            },
            Commands::Servers => unimplemented!("Servers command is not implemented"),
            Commands::Logs { id } => unimplemented!("Logs command is not implemented"),

            // Commands::Dev { commands } => {
            //     match commands {
            //         DevCommands::Tun {commands} => match commands {
            //             cli::TunCommands::Up => {
            //                 let tun = setup_tun(
            //                     INTERFACE_NAME,
            //                     &DATA_SIZE,
            //                     &NETWORK_IP,
            //                     &NETWORK_PREFIX
            //                 ).map_err(|error| {
            //                     error!("{}", error);
            //                     process::exit(1);
            //                 }).unwrap();
            //                 println!(
            //                     "\n\tname: {}\n\tmtu: {}\n\taddr: {}\n\tnetmask: {}\n",
            //                     tun.tun_name().unwrap_or("none".to_string()),
            //                     tun.mtu().map(|mtu| mtu.to_string()).unwrap_or("none".to_string()),
            //                     tun.address().map(|addr| addr.to_string()).unwrap_or("none".to_string()),
            //                     tun.netmask().map(|mask| mask.to_string()).unwrap_or("none".to_string())
            //                 );
            //                 println!(
            //                     "|> TUN interface has been successfully raised and will remain in this state\
            //                     \n|> until this application is terminated or 15 minutes have passed,\
            //                     \n|> after which the interface will be automatically removed!"
            //                 );
            //                 thread::sleep(Duration::from_secs(60 * 15));
            //             },
            //             cli::TunCommands::Down => {
            //                 down_tun(INTERFACE_NAME).map_err(|error| {
            //                     error!("{}", error);
            //                     process::exit(1);
            //                 }).unwrap();
            //             },
            //             cli::TunCommands::Status => {
            //                 let tun = tun_status(INTERFACE_NAME).map_err(|error| {
            //                     error!("{}", error);
            //                     process::exit(1);
            //                 }).unwrap();
            //                 println!(
            //                     "\n\tname: {}\n\tstate: {:?}\n\tmtu: {}\n\taddr: {}\n\tnetmask: {}\n",
            //                     tun.name, tun.state, tun.mtu, tun.ip, tun.netmask
            //                 );
            //             }
            //         },
            //         DevCommands::Ipv4Forwarding { commands } => match commands {
            //             cli::Ipv4ForwardingCommands::True => {
            //                 set_ipv4_forwarding(true).map_err(|error| {
            //                     error!("{}", error);
            //                     process::exit(1);
            //                 }).unwrap();
            //             },
            //             cli::Ipv4ForwardingCommands::False => {
            //                 set_ipv4_forwarding(false).map_err(|error| {
            //                     error!("{}", error);
            //                     process::exit(1);
            //                 }).unwrap();
            //             }
            //         }
            //     }
            // }
        },
        None => {
            eprintln!("No command provided");
            process::exit(1);
        }
    }
}
