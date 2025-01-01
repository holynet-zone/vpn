use crate::exceptions::CoreExceptions;
use crate::exceptions::CoreExceptions::IOError;
use crate::sunbeam::enc::{AuthEnc, BodyEnc};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Server {
    pub host: String,
    pub port: u16,
    pub enc: BodyEnc,
}

#[derive(Serialize, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub auth_key: String,
    pub enc: AuthEnc,
}

#[derive(Serialize, Deserialize)]
pub struct ConnConfig {
    pub server: Server,
    pub credentials: Credentials,
}


impl ConnConfig {
    pub fn load(path: &str) -> Result<Self, CoreExceptions> {
        match std::fs::read_to_string(path) {
            Ok(config) => toml::from_str(&config).map_err(|error| {
                IOError(format!("{}", error))
            }),
            Err(text) => Err(IOError(format!("Cannot load config file: {}", text))),
        }
    }

    pub fn save(&self, path: &str) -> Result<(), CoreExceptions> {
        let config = toml::to_string(self).unwrap();
        match std::fs::write(path, &config) {
            Ok(_) => Ok(()),
            Err(text) => Err(IOError(format!("Cannot save config file: {}", text))),
        }
    }

    pub fn from_base64(base64: &str) -> Result<Self, CoreExceptions> {
        let bytes = STANDARD_NO_PAD.decode(base64).map_err(|error| {
            IOError(format!("{}", error))
        })?;
        bincode::deserialize(&bytes).map_err(|error| {
            IOError(format!("{}", error))
        })
    }
    
    pub fn to_base64(&self) -> Result<String, CoreExceptions> {
        let bytes = bincode::serialize(&self).map_err(|error| {
            IOError(format!("{}", error))
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
                enc: BodyEnc::ChaCha20Poly1305,
            },
            credentials: Credentials {
                username: "admin".to_string(),
                auth_key: "key".to_string(),
                enc: AuthEnc::Aes128,
            },
        }
    }
    
    #[test]
    fn test_config_base64_serialization_deserialization() {
        let config = make_config();
        let base64 = config.to_base64().unwrap();
        ConnConfig::from_base64(&base64).unwrap();
    }
}
