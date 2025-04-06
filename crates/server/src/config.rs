use std::net::IpAddr;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use shared::keys::handshake::SecretKey;

#[derive(Serialize, Deserialize)]
pub struct General {
    pub host: String,
    pub port: u16,
    pub secret_key: SecretKey,
    pub storage: PathBuf,
}

#[derive(Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    pub mtu: u16,
    pub address: IpAddr,
    pub prefix: u8
}

#[derive(Serialize, Deserialize)]
pub struct Runtime {
    pub workers: usize,
    pub sender_buf_size: usize,
    pub session_ttl: usize, // sec
}

#[derive(Serialize, Deserialize)]
pub struct Redirect {
    pub enabled: bool,
    pub interfaces: Vec<String>,
}


#[derive(Serialize, Deserialize)]
pub struct Config {
    pub general: General,
    pub interface: Interface,
    pub runtime: Runtime,
    pub redirect: Option<Redirect>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: General {
                host: IpAddr::from([0, 0, 0, 0]).to_string(),
                port: 26256,
                secret_key: SecretKey::generate_x25519(),
                storage: PathBuf::from("database"),
            },
            interface: Interface {
                name: "holynet0".into(),
                mtu: 1420,
                address: IpAddr::from([10, 8, 0, 0]),
                prefix: 24,
            },
            runtime: Runtime {
                workers: 0, // auto
                sender_buf_size: 1000,
                session_ttl: 0, // turn off
            },
            redirect: Some(Redirect {
                enabled: false,
                interfaces: vec![],
            })
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let config = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&config)?)
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let config = toml::to_string(self)?;
        std::fs::write(path, &config)?;
        Ok(())
    }
}
