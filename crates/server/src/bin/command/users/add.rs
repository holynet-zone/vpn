use std::path::PathBuf;
use clap::Parser;
use inquire::required;
use inquire::validator::Validation;
use server::config::Config;
use shared::connection_config::{ConnectionConfig, CredentialsConfig, GeneralConfig};
use shared::keys::handshake::{PublicKey, SecretKey};
use shared::session::Alg;
use crate::storage::{database, Client, Clients};
use crate::style::format_opaque_bytes;

#[derive(Debug, Parser)]
pub struct AddCmd {
    /// external server host for client, ex: 123.123.123.123
    #[arg(short, long)]
    host: Option<String>,
    #[arg(short, long)]
    /// external server port for client, default 26256 or from config
    port: Option<u16>,
    /// client secret key (hex)
    #[arg(short, long)]
    sk: Option<String>,
    /// pre shared key (hex)
    #[arg(short, long)]
    psk: Option<String>
}

impl AddCmd {
    pub async fn exec(self, config: Config) -> anyhow::Result<()> {
        let host = match self.host {
            Some(host) => host,
            None => inquire::Text::new("Enter a server host:")
                .with_default(&config.general.host)
                .with_validator(required!("This field is required"))
                .with_validator(inquire::validator::MinLengthValidator::new(7))
                .with_validator(|i: &str | match i.is_empty() {
                    true => Ok(Validation::Invalid("This field is required".into())),
                    false => Ok(Validation::Valid)
                })
                .prompt()?
        }.trim().to_string();

        let port = match self.port {
            Some(port) => port,
            None => inquire::CustomType::new("Enter a server port:")
                .with_default(config.general.port)
                .prompt()?
        };

        let sk = match self.sk {
            Some(sk) => SecretKey::try_from(sk.as_str()).map_err(|error| {
                anyhow::anyhow!("failed to parse private key: {}", error)
            })?,
            None => SecretKey::generate_x25519()
        };
        
        let pk = PublicKey::derive_from(sk.clone());
        let psk = match self.psk {
            Some(psk) => SecretKey::try_from(psk.as_str()).map_err(|error| {
                anyhow::anyhow!("failed to parse pre-shared key: {}", error)
            })?,
            None => SecretKey::generate_x25519()
        };

        println!("\nClient has been successfully created!");

        println!("\nPublicKey {}", pk);
        println!("PrivateKey {}", format_opaque_bytes(sk.as_slice()));
        println!("PreSharedKey {}", format_opaque_bytes(psk.as_slice()));

        let clients = Clients::new(database(&config.general.storage)?)?;
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
}