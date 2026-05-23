use crate::config::Config;
use crate::config::connection::{ConnectionConfig, CredentialsConfig, GeneralConfig};
use crate::storage::{Client, Clients, database};
use crate::style::{format_opaque_bytes, generate_qrcode};
use crate::{success_err, success_ok};
use clap::Args;
use holynet_sdk::crypto::{PublicKey, SecretKey};
use holynet_sdk::protocol::Alg;
use inquire::required;
use inquire::validator::Validation;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct AddCmd {
    /// External server host for client
    #[arg(short, long)]
    host: Option<String>,
    /// External server port for client
    #[arg(short, long)]
    port: Option<u16>,
    /// Client secret key (base64)
    #[arg(short, long)]
    sk: Option<String>,
    /// Pre-shared key (base64)
    #[arg(short, long)]
    psk: Option<String>,
}

impl AddCmd {
    pub async fn exec(self, config: Config) -> anyhow::Result<()> {
        let host = match self.host {
            Some(h) => h,
            None => inquire::Text::new("Enter server host:")
                .with_default(&config.general.host)
                .with_validator(required!("This field is required"))
                .with_validator(|i: &str| match i.is_empty() {
                    true => Ok(Validation::Invalid("This field is required".into())),
                    false => Ok(Validation::Valid),
                })
                .prompt()?
                .trim()
                .to_string(),
        };

        let port = match self.port {
            Some(p) => p,
            None => inquire::CustomType::new("Enter server port:")
                .with_default(config.general.port)
                .prompt()?,
        };

        let sk = match self.sk {
            Some(s) => SecretKey::try_from(s.as_str())
                .map_err(|e| anyhow::anyhow!("parse private key: {}", e))?,
            None => SecretKey::generate_x25519(),
        };

        let pk = PublicKey::from_secret(&sk);

        let psk = match self.psk {
            Some(s) => SecretKey::try_from(s.as_str())
                .map_err(|e| anyhow::anyhow!("parse pre-shared key: {}", e))?,
            None => SecretKey::generate_x25519(),
        };

        println!();
        success_ok!("PubKey", pk);
        success_ok!("PrivKey", format_opaque_bytes(sk.as_slice()));
        success_ok!("SharedKey", format_opaque_bytes(psk.as_slice()));
        println!();

        let clients = Clients::new(database(&config.general.storage)?)?;
        clients
            .save(Client {
                psk: psk.clone(),
                peer_pk: pk.clone(),
                created_at: chrono::Utc::now(),
            })
            .await;

        let connection_config = ConnectionConfig {
            general: GeneralConfig {
                host,
                port,
                alg: Alg::default(),
            },
            credentials: CredentialsConfig {
                private_key: sk,
                pre_shared_key: psk,
                server_public_key: PublicKey::from_secret(&config.general.secret_key),
            },
            interface: None,
            runtime: None,
        };

        let config_path = PathBuf::from(format!(
            "connection-{}.toml",
            chrono::Utc::now().format("%Y-%m-%d_%H-%M-%S")
        ));

        connection_config
            .save(config_path.as_path())
            .map_err(|e| anyhow::anyhow!("save connection config: {}", e))?;

        match generate_qrcode(connection_config.to_base64()?.as_bytes()) {
            Ok(qr) => println!("{}\n", qr),
            Err(e) => success_err!("generate qrcode: {}", e),
        }

        success_ok!("Saved", "config to {}", config_path.display());
        success_ok!("Key", "{}", connection_config.to_base64()?);

        Ok(())
    }
}
