use std::process;
use inquire::Select;
use tracing::error;
use shared::conn_config::{ConnConfig, Credentials, Interface, Server};
use sunbeam::protocol::{
    enc::EncAlg,
    keys::auth::AuthKey
};
use crate::cli::schema::UserRow;
use crate::client::single::{Client, Clients};

pub fn add(
    clients: &Clients, 
    username: Option<String>,
    password: Option<String>,
    host: Option<String>,
    port: Option<u16>,
) {
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
    let key = AuthKey::derive_from(&password.as_bytes(), &username.as_bytes());
    clients.save(
        &username.as_bytes(),
        Client{
            auth_key: key.clone()
        }
    );
    println!("User {} has been successfully created!", username);
    let config_file = username.clone() + ".toml";
    let config = ConnConfig {
        server: Server {
            host,
            port,
            enc: EncAlg::Aes256,
        },
        interface: Interface {
            name: None,
            mtu: 1400,
        },
        credentials: Credentials {
            username,
            auth_key: key
        }
    };
    config.save(&config_file.parse().unwrap()).map_err(|error| {
        error!("Failed to save configuration: {}", error);
        process::exit(1);
    }).unwrap();
    println!("Configuration file has been saved to {}", config_file);
    println!("First insert: {}", config.to_base64().unwrap());
}

pub fn remove(clients: &Clients, username: String) {
    clients.delete(&username.as_bytes());
    println!("User {} has been successfully removed", username);
}

pub fn choose_user(clients: &Clients) -> String {
    let users = clients.get_all().iter().map(|(username, _)| {
        UserRow {
            username: username.clone()
        }
    }).collect();
    match Select::new("Choose a user:", users).prompt() {
        Ok(selected) => {
            selected.username
        },
        Err(error) => {
            error!("{}", error);
            process::exit(1);
        }
    }
}
