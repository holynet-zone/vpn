use crate::keys::handshake::{
    PublicKey,
    SecretKey
};
use crate::session::Alg;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::Path;
use crate::network::find_available_ifname;

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

#[derive(Clone, Serialize, Deserialize)]
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
            Ok(config) => toml::from_str(&config).map_err(anyhow::Error::from),
            Err(err) => Err(anyhow::Error::from(err))
        }
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let config = toml::to_string(self)?;
        std::fs::write(path, &config).map_err(anyhow::Error::from)
    }

    pub fn from_base64(base64: &str) -> anyhow::Result<Self> {
        let bytes = STANDARD_NO_PAD.decode(base64)?;
        let (obj, _) = bincode::serde::decode_from_slice(
            &bytes,
            bincode::config::standard()
        ).map_err(anyhow::Error::from)?;
        Ok(obj)
    }
    
    pub fn to_base64(&self) -> anyhow::Result<String> {
        let bytes = bincode::serde::encode_to_vec(
            self,
            bincode::config::standard()
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

impl Default for InterfaceConfig {
    fn default() -> Self {
        Self {
            name: find_available_ifname("holynet"),
            mtu: 1500
        }
    }
}