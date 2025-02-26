mod config;
mod runtime;
mod session;
mod daemon;
mod network;
mod client;
mod cli;

use std::process;
use tracing::error;
use tracing_subscriber::{fmt, filter, reload, layer::SubscriberExt, util::SubscriberInitExt};
use tracing_appender;

use clap::Parser;
use rocksdb::DB;
use crate::client::single::Clients;

const CONFIG_PATH_ENV: &str = "CONFIG_PATH";
const STORAGE_PATH_ENV: &str = "STORAGE_PATH";


fn main() {
    let cli = cli::schema::Cli::parse();

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
        cli::schema::Commands::Start { 
            host, 
            port, 
            iface, 
            config, 
            storage, 
            daemon 
        } => cli::start::start(
            host,
            port,
            iface,
            config,
            storage,
            daemon
        ),
        cli::schema::Commands::Users { commands } => {
            let storage_path = std::env::var(STORAGE_PATH_ENV).unwrap_or_else(|_| "database".to_string()); // todo: from --storage
            let mut opts = rocksdb::Options::default();
            opts.create_if_missing(true);
            let db = DB::open(&opts, storage_path).map_err(|error| {
                error!("Failed to open the database: {}", error);
                process::exit(1);
            }).unwrap();
            let clients = Clients::new(db);
            match commands {
                cli::schema::UsersCommands::Add {
                    username,
                    password,
                    host,
                    port
                } => cli::user::add(
                    &clients,
                    username,
                    password,
                    host,
                    port
                ).map_err(|error| {
                    error!("Failed to add user: {}", error);
                    process::exit(1);
                }).unwrap(),
                cli::schema::UsersCommands::Remove { username } => cli::user::remove(
                    &clients,
                    username
                ),
                cli::schema::UsersCommands::List => {
                    let raw_list = cli::user::list(&clients);
                    if raw_list.is_empty() {
                        println!("No users found");
                        process::exit(1);
                    } else {
                        println!("{}", raw_list);
                    }
                }
            }
        },
        cli::schema::Commands::Servers => unimplemented!("Servers command is not implemented"),
        cli::schema::Commands::Logs { id } => unimplemented!("Logs command is not implemented"),
    }
}
