use super::super::{
    schema::UserRow,
    style::format_opaque_bytes,
    storage::{database, Client, Clients}
};
use inquire::validator::Validation;
use inquire::required;
use shared::connection_config::{ConnectionConfig, CredentialsConfig, GeneralConfig};
use shared::keys::handshake::{PublicKey, SecretKey};
use shared::session::Alg;
use std::path::{Path, PathBuf};
use server::config;
use crate::CONFIG_PATH_ENV;

pub async fn add(
    config: Option<PathBuf>,
    host: Option<String>,
    port: Option<u16>,
    sk: Option<String>,
    psk: Option<String>
) -> anyhow::Result<()> {
    let config = match config {
        Some(path) => config::Config::load(&path)?,
        None => match std::env::var(CONFIG_PATH_ENV) {
            Ok(path) => match config::Config::load(Path::new(&path)) {
                Ok(cfg) => cfg,
                Err(err) => {
                    let cfg = config::Config::default();
                    cfg.save(Path::new("config.toml"))?;
                    eprintln!("failed to load config from env: {}", err);
                    eprintln!("using default config");
                    cfg
                }
            },
            Err(_) => match Path::new("config.toml").exists() {
                true => config::Config::load(Path::new("config.toml"))?,
                false => {
                    let cfg = config::Config::default();
                    cfg.save(Path::new("config.toml"))?;
                    eprintln!("no configuration provided, using default config");
                    cfg
                }
            }
        }
    };
    
    let host = if host.is_some() { host.unwrap() } else {
        inquire::Text::new("Enter a server host:")
            .with_default(&config.general.host)
            .with_validator(required!("This field is required"))
            .with_validator(inquire::validator::MinLengthValidator::new(7))
            .with_validator(|i: &str | match i.is_empty() {
                true => Ok(Validation::Invalid("This field is required".into())),
                false => Ok(Validation::Valid) 
            })
            .prompt()?
    }.trim().to_string();

    let port = if port.is_some() { port.unwrap() } else {
        inquire::CustomType::new("Enter a server port:")
            .with_default(config.general.port)
            .prompt()?
    };

    let sk = if sk.is_some() {
        SecretKey::try_from(sk.unwrap().as_str()).map_err(|error| {
            anyhow::anyhow!("failed to parse private key: {}", error)
        })?
    } else {
        SecretKey::generate_x25519()
    };
    let pk = PublicKey::derive_from(sk.clone());
    let psk = if psk.is_some() {
        SecretKey::try_from(psk.unwrap().as_str()).map_err(|error| {
            anyhow::anyhow!("failed to parse pre-shared key: {}", error)
        })?
    } else {
        SecretKey::generate_x25519()
    };

    println!("\nClient has been successfully created!");
    
    println!("\nPublic key {}", pk.to_hex());
    println!("Private key {}", format_opaque_bytes(sk.as_slice()));
    println!("Pre-shared key {}", format_opaque_bytes(psk.as_slice()));
    
    let clients = Clients::new(database(&config.general.storage)?);
    clients.save(Client {
        psk: psk.clone(),
        peer_pk: PublicKey::derive_from(sk.clone()),
        created_at: chrono::Utc::now(),
    }).await;
    
    let connection_config = ConnectionConfig {
        general: GeneralConfig {
            host,
            port,
            alg: Alg::Aes256
        },
        credentials: CredentialsConfig {
            private_key: sk,
            pre_shared_key: psk,
            server_public_key: PublicKey::derive_from(config.general.secret_key),
        },
        interface: None,
        runtime: None,
    };

    println!("\nConnection key\n{}", connection_config.to_base64()?);
    
    let config_path = PathBuf::from(format!(
        "connection-{}.toml", 
        chrono::Utc::now().format("%Y-%m-%d_%H-%M-%S")
    ));

    connection_config.save(config_path.as_path()).map_err(|error| {
        anyhow::anyhow!("failed to save connection config: {}", error)
    })?;
    
    println!("\nConnection config saved as {}\n", config_path.display());
    Ok(())
}

pub async fn remove(
    config: Option<PathBuf>,
    pk: String
) -> anyhow::Result<()> {
    let config = match config {
        Some(path) => config::Config::load(&path)?,
        None => match std::env::var(CONFIG_PATH_ENV) {
            Ok(path) => match config::Config::load(Path::new(&path)) {
                Ok(cfg) => cfg,
                Err(err) => return Err(anyhow::anyhow!("failed to load config from env: {}", err))
            },
            Err(_) => match Path::new("config.toml").exists() {
                true => config::Config::load(Path::new("config.toml"))?,
                false => return Err(anyhow::anyhow!("no configuration provided"))
            }
        }
    };
    
    let pk = PublicKey::try_from(pk.as_str()).map_err(|error| {
        anyhow::anyhow!("failed to parse public key: {}", error)
    })?;
    
    let clients = Clients::new(database(&config.general.storage)?);
    clients.delete(&pk).await?;
    println!("Client has been successfully removed");
    Ok(())
}

pub async fn list(config: Option<PathBuf>) -> anyhow::Result<()> {
    let config = match config {
        Some(path) => config::Config::load(&path)?,
        None => match std::env::var(CONFIG_PATH_ENV) {
            Ok(path) => match config::Config::load(Path::new(&path)) {
                Ok(cfg) => cfg,
                Err(err) => return Err(anyhow::anyhow!("failed to load config from env: {}", err))
            },
            Err(_) => match Path::new("config.toml").exists() {
                true => config::Config::load(Path::new("config.toml"))?,
                false => return Err(anyhow::anyhow!("no configuration provided"))
            }
        }
    };
    
    let clients = Clients::new(database(&config.general.storage)?);
    let users: Vec<_> = clients.get_all().await.iter().map(|client| {
        UserRow {
            pk: client.peer_pk.to_hex(),
            created_at: client.created_at.to_rfc2822()
        }
    }).collect();
    
    if users.is_empty() {
        return Err(anyhow::anyhow!("no users found"));
    }
    
    for user in users {
        println!("{}", user);
    }
    Ok(())
}

// pub fn choose(clients: &Clients) -> String {
//     let users: Vec<_> = clients.get_all().iter().map(|(username, _)| {
//         UserRow {
//             username: username.clone()
//         }
//     }).collect();
//     
//     if users.is_empty() {
//         println!("No users found");
//         process::exit(1);
//     }
//     
//     match Select::new("Choose a user:", users).prompt() {
//         Ok(selected) => {
//             selected.username
//         },
//         Err(error) => {
//             error!("{}", error);
//             process::exit(1);
//         }
//     }
// }
