use std::net::IpAddr;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize)]
pub struct General {
    pub debug: bool,
    pub host: IpAddr,
    pub port: u16,
    pub storage_path: PathBuf,
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
    pub event_capacity: u64,
    pub event_timeout: Option<u64>,
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
                debug: false,
                host: IpAddr::from([0, 0, 0, 0]),
                port: 26256,
                storage_path: PathBuf::from("database"),
            },
            interface: Interface {
                name: "holynet0".to_string(),
                mtu: 1420,
                address: IpAddr::from([10, 8, 0, 0]),
                prefix: 24,
            },
            runtime: Runtime {
                event_capacity: 1024,
                event_timeout: None,
            },
            redirect: Some(Redirect {
                enabled: false,
                interfaces: vec![],
            }),
        }
    }
}

impl Config {
    pub fn load(path: &str) -> Result<Config, String> {
        let config = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        Ok(toml::from_str(&config).map_err(|e| e.to_string())?)
    }

    pub fn save(&self, path: &str) -> Result<(), String> {
        let config = toml::to_string(self).map_err(|e| e.to_string())?;
        std::fs::write(path, &config).map_err(|e| e.to_string())?;
        Ok(())
    }
}
