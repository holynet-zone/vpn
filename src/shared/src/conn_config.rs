use std::path::PathBuf;
use sunbeam::protocol::enc::EncAlg;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sunbeam::protocol::keys::auth::AuthKey;
use sunbeam::protocol::username::Username;

#[derive(Serialize, Deserialize)]
pub struct Server {
    pub host: String,
    pub port: u16,
    pub enc: EncAlg,
}

#[derive(Serialize, Deserialize)]
pub struct Credentials {
    pub username: Username,
    pub auth_key: AuthKey
}

#[derive(Serialize, Deserialize)]
pub struct Interface {
    pub name: Option<String>,
    pub mtu: u16
}

#[derive(Serialize, Deserialize)]
pub struct ConnConfig {
    pub server: Server,
    pub interface: Interface,
    pub credentials: Credentials,
}


impl ConnConfig {
    pub fn load(path: &PathBuf) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(config) => toml::from_str(&config).map_err(|error| {
                format!("{}", error)
            }),
            Err(text) => Err(format!("Cannot load config file: {}", text)),
        }
    }

    pub fn save(&self, path: &PathBuf) -> Result<(), String> {
        let config = toml::to_string(self).unwrap();
        match std::fs::write(path, &config) {
            Ok(_) => Ok(()),
            Err(text) => Err(format!("Cannot save config file: {}", text)),
        }
    }

    pub fn from_base64(base64: &str) -> Result<Self, String> {
        let bytes = STANDARD_NO_PAD.decode(base64).map_err(|error| {
            format!("{}", error)
        })?;
        bincode::deserialize(&bytes).map_err(|error| {
            format!("{}", error)
        })
    }
    
    pub fn to_base64(&self) -> Result<String, String> {
        let bytes = bincode::serialize(&self).map_err(|error| {
            format!("{}", error)
        })?;
        Ok(STANDARD_NO_PAD.encode(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> ConnConfig {
        ConnConfig {
            server: Server {
                host: "localhost".to_string(),
                port: 8080,
                enc: EncAlg::ChaCha20Poly1305,
            },
            interface: Interface {
                name: None,
                mtu: 1460,
            },
            credentials: Credentials {
                username: Username::try_from("test".to_string()).unwrap(),
                auth_key: AuthKey::generate()
            },
        }
    }

    #[test]
    fn test_config_base64_serialization_deserialization() {
        let config = make_config();
        let base64 = config.to_base64().unwrap();
        let deserialized_config = ConnConfig::from_base64(&base64).unwrap();

        assert_eq!(config.credentials.auth_key, deserialized_config.credentials.auth_key);
    }
}
