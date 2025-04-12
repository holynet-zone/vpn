use std::net::IpAddr;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use shared::keys::handshake::SecretKey;

#[derive(Serialize, Deserialize)]
pub struct GeneralConfig {
    pub host: String,
    pub port: u16,
    pub secret_key: SecretKey,
    pub storage: PathBuf,
}

#[derive(Serialize, Deserialize)]
pub struct InterfaceConfig {
    pub name: String,
    pub mtu: u16,
    pub address: IpAddr,
    pub prefix: u8
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RuntimeConfig {
    pub workers: usize,
    pub so_rcvbuf: usize,
    pub so_sndbuf: usize,
    pub out_udp_buf: usize,
    pub out_tun_buf: usize,
    pub handshake_buf: usize,
    pub data_udp_buf: usize,
    pub data_tun_buf: usize,
    pub session_ttl: usize, // sec
}

#[derive(Serialize, Deserialize)]
pub struct RedirectConfig {
    pub enabled: bool,
    pub ipv4_forwarding: bool,
    pub interfaces: Vec<String>,
}


#[derive(Serialize, Deserialize)]
pub struct Config {
    pub general: GeneralConfig,
    pub interface: InterfaceConfig,
    pub runtime: Option<RuntimeConfig>,
    pub redirect: Option<RedirectConfig>
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

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            interface: InterfaceConfig::default(),
            runtime: Some(RuntimeConfig::default()),
            redirect: Some(RedirectConfig::default())
        }
    }
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            host: IpAddr::from([0, 0, 0, 0]).to_string(),
            port: 26256,
            secret_key: SecretKey::generate_x25519(),
            storage: PathBuf::from("database"),
        }
    }
}

impl Default for InterfaceConfig {
    fn default() -> Self {
        Self {
            name: "holynet0".into(), // todo from available interface number
            mtu: 1420,
            address: IpAddr::from([10, 8, 0, 0]),
            prefix: 24,
        }
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            workers: 0, // auto
            so_rcvbuf: 1024 * 1024 * 1024,
            so_sndbuf: 1024 * 1024 * 1024,
            out_udp_buf: 1000,
            out_tun_buf: 1000,
            handshake_buf: 1000,
            data_udp_buf: 1000,
            data_tun_buf: 1000,
            session_ttl: 0, // turn off
        }
    }
}

impl Default for RedirectConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ipv4_forwarding: true, // todo
            interfaces: vec![
                // todo add default interface
            ]
        }
    }
}