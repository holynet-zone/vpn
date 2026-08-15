use crate::network::find_available_ifname;
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use holynet_sdk::crypto::{PublicKey, SecretKey};
use holynet_sdk::protocol::Alg;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct GeneralConfig {
    pub host: String,
    pub port: u16,
    pub alg: Alg,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CredentialsConfig {
    pub private_key: SecretKey,
    pub pre_shared_key: SecretKey,
    pub server_public_key: PublicKey,
}

fn default_offload() -> bool {
    true
}

#[derive(Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    pub name: String,
    pub mtu: u16,
    /// Enable Linux TUN GRO/TSO offload. Auto-falls back to per-packet if the
    /// kernel rejects it or the `--no-offload` CLI flag is passed.
    #[serde(default = "default_offload")]
    pub offload: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RuntimeConfig {
    pub handshake_timeout: u64,
    pub keepalive: Option<u64>,
    /// Parallel encrypt workers on the send path. `0` auto-sizes to one worker
    /// per logical CPU; `1` keeps the single-task path; `>= 2` sets an explicit
    /// WireGuard-style encrypt pool.
    #[serde(default)]
    pub encrypt_workers: usize,
    /// Parallel decrypt workers on the receive path. `0` auto-sizes to one
    /// worker per logical CPU; `1` keeps the single-task path; `>= 2` sets an
    /// explicit WireGuard-style decrypt pool (the lever for the reverse/download
    /// direction).
    #[serde(default)]
    pub decrypt_workers: usize,
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
    pub runtime: Option<RuntimeConfig>,
}

impl ConnectionConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        toml::from_str(&content).map_err(anyhow::Error::from)
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        std::fs::write(path, toml::to_string(self)?).map_err(anyhow::Error::from)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
            .expect("failed to serialize connection config")
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let (obj, _) = bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map_err(anyhow::Error::from)?;
        Ok(obj)
    }

    pub fn from_base64(base64: &str) -> anyhow::Result<Self> {
        let bytes = STANDARD_NO_PAD.decode(base64)?;
        Self::from_bytes(&bytes)
    }

    pub fn to_base64(&self) -> anyhow::Result<String> {
        Ok(STANDARD_NO_PAD.encode(self.to_bytes()))
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: 3000,
            keepalive: Some(5),
            encrypt_workers: 0,
            decrypt_workers: 0,
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
            mtu: 1420,
            offload: true,
        }
    }
}
