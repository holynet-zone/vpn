use crate::keys::handshake::{
    SecretKey,
    PublicKey
};
use crate::session::Alg;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct GeneralConfig {
    pub host: String,
    pub port: u16,
    pub alg: Alg
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CredentialsConfig {
    pub private_key: SecretKey,
    pub pre_shared_key: SecretKey,
    pub server_public_key: PublicKey
}

#[derive(Serialize, Deserialize)]
pub struct InterfaceConfig {
    pub name: String,
    pub mtu: u16
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RuntimeConfig {
    pub handshake_timeout: u64, // ms
    pub keepalive: Option<u64>, // sec
    pub so_rcvbuf: usize,
    pub so_sndbuf: usize,
    pub out_udp_buf: usize,
    pub out_tun_buf: usize,
    pub data_udp_buf: usize,
    pub data_tun_buf: usize,
}

#[derive(Serialize, Deserialize)]
pub struct ConnectionConfig {
    pub general: GeneralConfig,
    pub credentials: CredentialsConfig,
    pub interface: Option<InterfaceConfig>,
    pub runtime: Option<RuntimeConfig>
}


impl ConnectionConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(config) => toml::from_str(&config).map_err(
                |err| anyhow::Error::from(err)
            ),
            Err(err) => Err(anyhow::Error::from(err))
        }
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let config = toml::to_string(self)?;
        std::fs::write(path, &config).map_err(
            |err| anyhow::Error::from(err)
        )
    }

    pub fn from_base64(base64: &str) -> anyhow::Result<Self> {
        let bytes = STANDARD_NO_PAD.decode(base64)?;
        bincode::deserialize(&bytes).map_err(
            |err| anyhow::Error::from(err)
        )
    }
    
    pub fn to_base64(&self) -> anyhow::Result<String> {
        let bytes = bincode::serialize(&self).map_err(
            |err| anyhow::Error::from(err)
        )?;
        Ok(STANDARD_NO_PAD.encode(&bytes))
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: 3000, // 3sec
            keepalive: Some(5), // 5sec
            so_rcvbuf: 1024 * 1024 * 1024,
            so_sndbuf: 1024 * 1024 * 1024,
            out_udp_buf: 1000,
            out_tun_buf: 1000,
            data_udp_buf: 1000,
            data_tun_buf: 1000,
        }
    }
}
