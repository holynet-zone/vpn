use std::process;
use inquire::Select;
use tracing::error;
use shared::conn_config::{ConnConfig, Credentials, Interface, Server};
use sunbeam::protocol::{
    enc::EncAlg,
    keys::auth::AuthKey
};
use sunbeam::protocol::password::Password;
use sunbeam::protocol::username::Username;
use crate::cli::schema::UserRow;
use crate::client::single::{Client, Clients};

pub fn add(
    clients: &Clients, 
    username: Option<String>,
    password: Option<String>,
    host: Option<String>,
    port: Option<u16>,
) -> anyhow::Result<()> {
    let host = host.unwrap_or_else(|| loop {
        let host = inquire::Text::new("Enter a server host:")
            .with_default("127.0.0.1")
            .prompt()
            .unwrap();
        if host.is_empty() {
            error!("Host cannot be empty");
            continue;
        }
        break host;
    });
    
    let port = port.unwrap_or_else(|| loop {
        let port = inquire::Text::new("Enter a server port:")
            .with_default("26256")
            .prompt()
            .unwrap();
        if port.is_empty() {
            error!("Port cannot be empty");
            continue;
        }
        match port.parse() {
            Ok(port) => break port,
            Err(error) => {
                error!("Failed to parse port: {}", error);
                continue;
            }
        }
    });
    let username = Username::try_from(username.unwrap_or_else(|| loop {
        let username = inquire::Text::new("Enter a username (up to 128 characters):")
            .with_help_message("Username cannot be empty")
            .prompt()
            .unwrap();
        if username.is_empty() {
            error!("Username cannot be empty");
            continue;
        }
        break username;
    })).map_err(|error| {
        return anyhow::anyhow!("Failed to parse username: {}", error);
    })?;
    
    let password = Password::from(password.unwrap_or_else(|| loop {
        let password = inquire::Password::new("Enter a password:")
            .with_help_message("Password cannot be empty")
            .prompt()
            .unwrap();
        if password.is_empty() {
            error!("Password cannot be empty");
            continue;
        }
        break password;
    }));
    let key = AuthKey::derive_from(&password.as_slice(), &username.as_slice());
    clients.save(
        &username.as_slice(),
        Client{
            auth_key: key.clone()
        }
    );
    println!("User {} has been successfully created!", username);
    let config_file = username.to_string() + ".toml";
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
    config.save(&config_file.parse()?).map_err(|error| {
        error!("Failed to save configuration: {}", error);
        process::exit(1);
    }).unwrap();
    println!("Configuration file has been saved to {}", config_file);
    println!("First insert: {}", config.to_base64().unwrap());
    Ok(())
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
