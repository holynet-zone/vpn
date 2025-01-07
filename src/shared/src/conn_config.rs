use std::path::PathBuf;
use sunbeam::protocol::enc::{AuthEnc, BodyEnc};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sunbeam::protocol::AUTH_KEY_SIZE;


#[derive(Serialize, Deserialize)]
pub struct Server {
    pub host: String,
    pub port: u16,
    pub enc: BodyEnc,
}

#[derive(Serialize, Deserialize)]
pub struct Credentials {
    pub username: String,
    #[serde(serialize_with = "serialize_auth_key", deserialize_with = "deserialize_auth_key")]
    pub auth_key: [u8; AUTH_KEY_SIZE],
    pub enc: AuthEnc,
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

fn serialize_auth_key<S>(key: &[u8; AUTH_KEY_SIZE], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let base64 = STANDARD_NO_PAD.encode(key);
    serializer.serialize_str(&base64)
}

fn deserialize_auth_key<'de, D>(deserializer: D) -> Result<[u8; AUTH_KEY_SIZE], D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let base64 = String::deserialize(deserializer)?;
    let bytes = STANDARD_NO_PAD.decode(&base64).map_err(Error::custom)?;
    if bytes.len() != AUTH_KEY_SIZE {
        return Err(Error::custom(format!(
            "Invalid auth_key length: expected {}, got {}",
            AUTH_KEY_SIZE,
            bytes.len()
        )));
    }

    let mut array = [0u8; AUTH_KEY_SIZE];
    array.copy_from_slice(&bytes);
    Ok(array)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> ConnConfig {
        ConnConfig {
            server: Server {
                host: "localhost".to_string(),
                port: 8080,
                enc: BodyEnc::ChaCha20Poly1305,
            },
            interface: Interface {
                name: None,
                mtu: 1460,
            },
            credentials: Credentials {
                username: "admin".to_string(),
                auth_key: [0u8; AUTH_KEY_SIZE],
                enc: AuthEnc::Aes128,
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