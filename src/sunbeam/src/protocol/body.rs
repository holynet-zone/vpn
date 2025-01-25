use crate::protocol::bytes::{FromBytes, ToBytes};
use crate::protocol::enc::{aes256, chacha20_poly1305, EncAlg};
use crate::protocol::keys::session::SessionKey;
use crate::protocol::keys::Key;
use crate::protocol::SessionId;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::net::IpAddr;
use std::ops::Deref;
use anyhow::anyhow;

pub trait DisEncBody {}

pub struct EncBody(pub Vec<u8>);

impl EncBody {
    const MAX_SIZE: usize = u16::MAX as usize;
    
    pub fn enchant<T: ToBytes, const SIZE: usize >(body: T, key: Key<SIZE>, alg: EncAlg) -> Self {
        let raw_body = body.to_bytes().unwrap();
        Self::from(match alg {
            EncAlg::Aes256 => {
                aes256::encrypt(&raw_body, key.as_slice().try_into().unwrap())
            },
            EncAlg::ChaCha20Poly1305 => {
                chacha20_poly1305::encrypt(&raw_body, key.as_slice().try_into().unwrap())
            }
        })
    }
    pub fn disenchant<T: FromBytes, const SIZE: usize >(
        &self, key: Key<SIZE>, 
        alg: EncAlg
    ) -> anyhow::Result<T> {
        let raw_body = match match alg {
            EncAlg::Aes256 => {
                aes256::decrypt(&self.0, key.as_slice().try_into()?)
            },
            EncAlg::ChaCha20Poly1305 => {
                chacha20_poly1305::decrypt(&self.0, key.as_slice().try_into()?)
            }
        } {
            Some(data) => if data.len() > Self::MAX_SIZE {
                return Err(anyhow!(
                    "decryption failed: Size of the decrypted data is too large ({} > {})", 
                    data.len(), 
                    Self::MAX_SIZE
                ));
            } else {
                data
            },
            None => return Err(anyhow!("decryption failed".to_string()))
        };
        
        T::from_bytes(&raw_body)
    }
}

impl From<Vec<u8>> for EncBody {
    fn from(data: Vec<u8>) -> Self {
        Self(data)
    }
}

impl From<&[u8]> for EncBody {
    fn from(data: &[u8]) -> Self {
        Self(data.to_vec())
    }
}

impl TryFrom<ClientBody> for EncBody {
    type Error = String;

    fn try_from(body: ClientBody) -> Result<Self, Self::Error> {
        let bytes = body.to_bytes().map_err(|e| e.to_string())?;
        if bytes.len() > Self::MAX_SIZE {
            return Err(format!(
                "ClientBody size is too large ({} > {})", bytes.len(), Self::MAX_SIZE
            ));
        }
        Ok(Self::from(bytes))
    }
}

impl TryFrom<ServerBody> for EncBody {
    type Error = String;

    fn try_from(body: ServerBody) -> Result<Self, Self::Error> {
        let bytes = body.to_bytes().map_err(|e| e.to_string())?;
        if bytes.len() > Self::MAX_SIZE {
            return Err(format!(
                "ServerBody size is too large ({} > {})", bytes.len(), Self::MAX_SIZE
            ));
        }
        Ok(Self::from(bytes))
    }
}

impl Deref for EncBody {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for EncBody {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut buffer = Vec::new();
        if self.0.len() > u16::MAX as usize {
            return Err(serde::ser::Error::custom(
                format!("body size is too large ({} > {})", self.0.len(), u16::MAX)
            ));
        }
        buffer.extend_from_slice(&(self.0.len() as u16).to_be_bytes());
        buffer.extend_from_slice(&self.0);
        serializer.serialize_bytes(&buffer)
    }
}

impl<'de> Deserialize<'de> for EncBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data = Vec::<u8>::deserialize(deserializer)?;
        if data.len() < 2 {
            return Err(de::Error::custom("invalid body size"));
        }
        let size = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < size + 2 {
            return Err(de::Error::custom("invalid body size"));
        }
        Ok(Self(data[2..size + 2].to_vec()))
    }
}


#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub enum ClientBody {
    /// Represents a structure of useful data,
    /// in particular an ip packet taken from a user tun
    /// 
    /// The size of this type is variable. To store the length of a vector, the u16 type is used, 
    /// the size of which is 2 bytes => the size of this vector is 2 bytes + x - the number 
    /// of elements in the vector
    Data(Vec<u8>),
    /// This type contains a timestamp from the beginning of the UNIX epoch in milliseconds - the time the package was created
    ///
    /// This is important to calculate both (Round-Trip Time) *RTT* and (One-Way Delay) *OWD*  
    ///   
    /// The size of this type is 16 bytes
    KeepAlive(u128),
    /// This type is used by the user when he wants to connect to the server. 
    /// Note that the `sid` field of the `ClientPacket` type
    /// must be set to `0`, otherwise the server will ignore the request
    /// 
    /// The size of this type is 1 byte
    /// 
    Connection {
        /// Note that the type of the `enc` field is `EncAlg`, and in the user configuration 
        /// file it is `AuthEnc` - this is not done to confuse you
        /// 
        /// The point is that the `AuthEnc` type cannot be changed on the user side, because 
        /// then the user password would have to be reissued on the server side
        /// 
        /// The `enc` field of the `EncAlg` type in this context means the encryption type 
        /// that the server will use for further communication with the client once 
        /// the connection is successfully established and the payload flow begins. 
        /// It does not mean the encryption type for authentication!
        /// 
        /// The size of this type is 1 byte
        enc: EncAlg
    },
    Disconnection
}


#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub enum ServerDisconnectState {
    /// If the username or password is incorrect, the connection is refused
    InvalidCredentials,
    /// The server administrator can limit the number of devices from which one can connect using
    /// one cred. By default, this is 10 devices - it is set at the stage of creating a client
    MaxConnectedDevices(u32),
    /// If the number of available IP addresses or session identifiers has expired, 
    /// the server cannot successfully establish a new connection
    ServerOverloaded,
    /// If the structure of the request was violated (for example, instead of the expected uid = 0, 
    /// another identifier was specified),
    InvalidPacketFormat,
    /// When a server goes down, it must notify all active clients about it.
    ServerShutdown
}


/// If the user data is correct, and it is possible to allocate a user session,
/// then the connection is considered successful - the server returns useful
/// data for configuration
///
/// The size of this type:  
/// * If holynet ipv4 and dns ipv4: 5 + 1 + 4 + 128 + 5 = 143 bytes
/// * If holynet ipv6 and dns ipv4: 17 + 1 + 4 + 128 + 5 = 155 bytes
/// * If holynet ipv4 and dns ipv6: 5 + 1 + 4 + 128 + 17 = 155 bytes
/// * If holynet ipv6 and dns ipv6: 17 + 1 + 4 + 128 + 17 = 167 bytes
#[derive(Serialize, Deserialize)]
pub struct Setup {
    /// This field contains the IP address of the user VPN interface
    ///
    /// The size of this type is from (1+4) to (1+16) bytes.
    /// Maximum size is 17 bytes
    pub ip: IpAddr,
    /// This field contains the prefix of the user VPN interface
    ///
    /// The size of this type is 1 byte
    pub prefix: u8,
    /// This field contains the numeric session identifier. 
    /// There can be (4,294,967,295 - 1) active devices connected to one server at the same time. 
    /// Note that `sid` with value `0` is reserved and is used only during authentication! 
    /// The client cannot get `sid` with value `0`!
    ///
    /// The size of this type is 4 bytes
    pub sid: SessionId,
    /// This field contains the encryption key that the client should use for 
    /// this session and the selected encryption algorithm (`EncAlg`)
    pub key: SessionKey,
    /// This field contains the MTU of the user VPN interface
    ///
    /// The size of this type is from (1+4) bytes to (1+16) bytes
    pub dns: IpAddr,
}


#[derive(Serialize, Deserialize)]
pub enum ServerBody {
    /// Represents a structure of useful data,
    /// in particular an ip packet taken from a server tun
    /// 
    /// The size of this type is variable. To store the length of a vector, the u16 type is used, 
    /// the size of which is 2 bytes => the size of this vector is 2 bytes + x - the number 
    /// of elements in the vector
    Data(Vec<u8>),
    /// This type contains two important fields: server_ts and client_ts - meaning the timestamp
    /// since the UNIX epoch in milliseconds!
    ///
    /// This is important to calculate both (Round-Trip Time) *RTT* and (One-Way Delay) *OWD*
    /// 
    /// The size of this type is 32 bytes
    KeepAlive { server_ts: u128, client_ts: u128 },
    /// This type represents a response to a connection request.
    /// Please note that if the structure of the request was violated (for example,
    /// instead of the expected uid = 0, another identifier was specified),
    /// the server will not expect a connection request, and upon receiving such a body,
    /// it will simply ignore it
    Connection(Setup),
    Disconnection(ServerDisconnectState)
}

impl DisEncBody for ClientBody {}
impl DisEncBody for ServerBody {}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::keys::auth::AuthKey;

    #[test]
    fn encode_decode_client_body() {
        let original_body = ClientBody::Disconnection;
        let key = AuthKey::generate();
        
        let enc_body = EncBody::enchant(original_body.clone(), key.clone(), EncAlg::Aes256);
        let dec_body: ClientBody = enc_body.disenchant(key, EncAlg::Aes256).unwrap();
        
        assert_eq!(original_body, dec_body);
    }
}