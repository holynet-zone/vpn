use std::process;
use inquire::{required, PasswordDisplayMode, Select};
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

    let port = port.unwrap_or_else(|| {
        inquire::CustomType::new("Enter a server port:")
            .with_default(26256)
            .prompt()
            .unwrap()
    });
    
    let username = Username::try_from(username.unwrap_or_else(
        || inquire::Text::new(&format!("Enter a username (up to {} chars):", Username::SIZE))
            .with_validator(required!("This field is required"))
            .with_validator(inquire::validator::MinLengthValidator::new(1))
            .with_validator(inquire::validator::MaxLengthValidator::new(Username::SIZE))
            .with_placeholder("JKearnsl")
            .prompt()
            .unwrap()
    )).map_err(|error| {
        eprintln!("Failed to parse username: {}", error);
        process::exit(1);
    }).unwrap();
    
    let password = Password::from(password.unwrap_or_else(
        || inquire::Password::new("Enter a password:")
            .with_validator(required!("This field is required"))
            .with_validator(inquire::validator::MinLengthValidator::new(1))
            .with_display_mode(PasswordDisplayMode::Masked)
            .prompt()
            .unwrap()
    ));
    let key = AuthKey::derive_from(&password.as_slice(), &username.as_slice());
    
    clients.save(&username.as_slice(), Client{ auth_key: key.clone()});
    println!("\nUser {} has been successfully created!", username);
    
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
        eprintln!("Failed to save configuration: {}", error);
        process::exit(1);
    }).unwrap();
    println!("Configuration file has been saved as {}", config_file);
    println!("\nKEY: {}", config.to_base64().unwrap());
    Ok(())
}

pub fn remove(clients: &Clients, username: String) {
    clients.delete(&username.as_bytes());
    println!("User {} has been successfully removed", username);
}

pub fn choose(clients: &Clients) -> String {
    let users: Vec<_> = clients.get_all().iter().map(|(username, _)| {
        UserRow {
            username: username.clone()
        }
    }).collect();
    
    if users.is_empty() {
        println!("No users found");
        process::exit(1);
    }
    
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


pub fn list(clients: &Clients) -> String {
    clients.get_all().iter().map(|(username, _)| {
        username.clone()
    }).collect::<Vec<String>>().join("\n")
}
