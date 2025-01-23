///
///```Holynet protocol
///  ____              ____
/// / ___| _   _ _ __ | __ )  ___  __ _ _ __ ___
/// \___ \| | | | '_ \|  _ \ / _ \/ _  | '_ ' _ \
///  ___) | |_| | | | | |_) |  __/ (_| | | | | | |
/// |____/ \__,_|_| |_|____/ \___|\__,_|_| |_| |_|
/// ```
///

pub mod body;
pub mod bytes;
pub mod enc;
pub mod username;
pub mod keys;
pub mod password;

use serde::{Deserialize, Serialize};
use self::body::EncBody;

pub type SessionId = u32;


/// ClientPacket  
/// This type represents the structure of client requests to the vpn server
#[derive(Serialize, Deserialize)]
pub struct ClientPacket {
    /// Session identifier  
    /// Assigned during user authentication. Serves to identify 
    /// user devices and reduce the number of conflicts, as well 
    /// as to simplify the search for the response address
    ///   
    /// For the initial connection for authentication purposes, 
    /// it is set to *0*. This means that the value *0* is always 
    /// reserved and cannot be assigned to a user!
    pub sid: SessionId,
    /// Packet body  
    /// Contains the payload, may be encrypted
    pub body: EncBody,
    /// The buffer may contain the username during authentication
    /// or other information
    pub buffer: Vec<u8>
}


/// ServerPacket  
/// This type represents the structure of server responses
#[derive(Serialize, Deserialize)]
pub struct ServerPacket(pub EncBody);


#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::body::ServerBody;
    use crate::protocol::body::{ClientBody, Setup};
    use crate::protocol::bytes::ToBytes;
    use crate::protocol::enc::EncAlg;
    use crate::protocol::keys::auth::AuthKey;
    use crate::protocol::keys::session::SessionKey;
    use crate::protocol::username::Username;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_client_body_data(len: usize) -> ClientBody {
        ClientBody::Data(vec![0; len])
    }

    fn make_client_body_keepalive() -> ClientBody {
        ClientBody::KeepAlive(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        )
    }

    fn make_client_body_connection(enc: EncAlg) -> ClientBody {
        ClientBody::Connection {
            enc
        }
    }
    
    fn make_creds() -> (Username, AuthKey) {
        (Username::try_from("test".to_string()).unwrap(), AuthKey::generate())
    }

    fn make_server_body_connected(sid: u32) -> ServerBody {
        ServerBody::Connection(Setup {
            ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
            prefix: 24,
            sid,
            key: SessionKey::generate(),
            dns: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
        })
    }


    fn make_server_body_keepalive(cts: u128) -> ServerBody {
        ServerBody::KeepAlive{
            server_ts: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            client_ts: cts
        }
    }

    fn make_server_body_data(len: usize) -> ServerBody {
        ServerBody::Data(vec![0; len])
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////    Connection test    //////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////

    #[test]
    fn test_connection_aes256() {
        // Client
        let client_body = make_client_body_connection(EncAlg::Aes256);
        let (username, key) = make_creds();
        let packet = ClientPacket {
            sid: 0,
            body: EncBody::enchant(client_body.clone(), key.clone(), EncAlg::Aes256),
            buffer: username.to_vec()
        };
        let client_serialized = packet.to_bytes().unwrap();

        // Server
        let deserialized_packet: ClientPacket = bincode::deserialize(&client_serialized).unwrap();
        assert_eq!(deserialized_packet.sid, 0);
        let deserialized_body: ClientBody = deserialized_packet.body.disenchant(key.clone(), EncAlg::Aes256).unwrap();
        assert_eq!(client_body, deserialized_body);
        let server_body = EncBody::enchant(make_server_body_connected(1), key, EncAlg::Aes256);
        let server_packet = ServerPacket(server_body);
        let server_serialized = server_packet.to_bytes().unwrap();
        println!(
            "test_connection_aes256: \nClientPacketSize: {}\nServerPacketSize: {}\n",
            client_serialized.len(),
            server_serialized.len()
        );
    }

    #[test]
    fn test_connection_chacha20_poly1305() {
        // Client
        let client_body = make_client_body_connection(EncAlg::Aes256);
        let (username, key) = make_creds();
        let packet = ClientPacket {
            sid: 0,
            body: EncBody::enchant(client_body.clone(), key.clone(), EncAlg::ChaCha20Poly1305),
            buffer: username.to_vec()
        };
        let client_serialized = packet.to_bytes().unwrap();

        // Server
        let deserialized_packet: ClientPacket = bincode::deserialize(&client_serialized).unwrap();
        assert_eq!(deserialized_packet.sid, 0);
        let deserialized_body: ClientBody = deserialized_packet.body.disenchant(key.clone(), EncAlg::ChaCha20Poly1305).unwrap();
        assert_eq!(client_body, deserialized_body);
        let server_body = EncBody::enchant(make_server_body_connected(1), key, EncAlg::ChaCha20Poly1305);
        let server_packet = ServerPacket(server_body);
        let server_serialized = server_packet.to_bytes().unwrap();
        println!(
            "test_connection_chacha20_poly1305: \nClientPacketSize: {}\nServerPacketSize: {}\n",
            client_serialized.len(),
            server_serialized.len()
        );
    }
    ////////////////////////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////    KeepAlive test    ///////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////
    
    #[test]
    fn test_keepalive_aes256() {
        // Client
        let client_body = make_client_body_keepalive();
        let (_, key) = make_creds();
        let packet = ClientPacket {
            sid: 1,
            body: EncBody::enchant(client_body.clone(), key.clone(), EncAlg::Aes256),
            buffer: vec![]
        };
        let client_serialized = packet.to_bytes().unwrap();

        // Server
        let deserialized_packet: ClientPacket = bincode::deserialize(&client_serialized).unwrap();
        assert_ne!(deserialized_packet.sid, 0);
        let deserialized_body: ClientBody = deserialized_packet.body.disenchant(key.clone(), EncAlg::Aes256).unwrap();
        assert_eq!(client_body, deserialized_body);
        let client_timestamp = match deserialized_body {
            ClientBody::KeepAlive(ts) => ts,
            _ => panic!("Invalid body type")
        };
        let server_body = EncBody::enchant(make_server_body_keepalive(client_timestamp), key, EncAlg::Aes256);
        let server_serialized = ServerPacket(server_body).to_bytes().unwrap();
        println!(
            "test_keepalive_aes256: \nClientPacketSize: {}\nServerPacketSize: {}\n",
            client_serialized.len(),
            server_serialized.len()
        );
    }

    #[test]
    fn test_keepalive_chacha20_poly1305() {
        // Client
        let client_body = make_client_body_keepalive();
        let (_, key) = make_creds();
        let packet = ClientPacket {
            sid: 1,
            body: EncBody::enchant(client_body.clone(), key.clone(), EncAlg::ChaCha20Poly1305),
            buffer: vec![]
        };
        let client_serialized = packet.to_bytes().unwrap();

        // Server
        let deserialized_packet: ClientPacket = bincode::deserialize(&client_serialized).unwrap();
        assert_ne!(deserialized_packet.sid, 0);
        let deserialized_body: ClientBody = deserialized_packet.body.disenchant(key.clone(), EncAlg::ChaCha20Poly1305).unwrap();
        assert_eq!(client_body, deserialized_body);
        let client_timestamp = match deserialized_body {
            ClientBody::KeepAlive(ts) => ts,
            _ => panic!("Invalid body type")
        };
        let server_body = EncBody::enchant(make_server_body_keepalive(client_timestamp), key, EncAlg::ChaCha20Poly1305);
        let server_serialized = ServerPacket(server_body).to_bytes().unwrap();
        println!(
            "test_keepalive_chacha20_poly1305: \nClientPacketSize: {}\nServerPacketSize: {}\n",
            client_serialized.len(),
            server_serialized.len()
        );
    }
    ////////////////////////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////    Data test    ////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////
    
    #[test]
    fn test_data_aes256() {
        // Client
        let tun_ip_size = 1500;
        let client_body = make_client_body_data(tun_ip_size);
        let (_, key) = make_creds();
        let packet = ClientPacket {
            sid: 1,
            body: EncBody::enchant(client_body.clone(), key.clone(), EncAlg::Aes256),
            buffer: vec![]
        };
        let client_serialized = packet.to_bytes().unwrap();

        // Server
        let deserialized_packet: ClientPacket = bincode::deserialize(&client_serialized).unwrap();
        assert_ne!(deserialized_packet.sid, 0);
        let decrypted_body = deserialized_packet.body.disenchant(key.clone(), EncAlg::Aes256).unwrap();
        assert_eq!(client_body, decrypted_body);

        let server_body = EncBody::enchant(make_server_body_data(tun_ip_size), key, EncAlg::Aes256);
        let server_serialized = ServerPacket(server_body).to_bytes().unwrap();

        println!(
            "test_data_aes128: \
            \nTunIpSize: {}\
            \nClientPacketSize: {}\
            \nClientEncBodySize: {}\
            \nClientPackDx: {}\
            \nServer(packet/body)Size: {}\
            \nServerPackDx: {}\n",
            tun_ip_size,
            client_serialized.len(),
            deserialized_packet.body.len(),
            client_serialized.len() - tun_ip_size,
            server_serialized.len(),
            server_serialized.len() - tun_ip_size
        );
    }

    #[test]
    fn test_data_chacha20_poly1305() {
        // Client
        let tun_ip_size = 1500;
        let client_body = make_client_body_data(tun_ip_size);
        let (_, key) = make_creds();
        let packet = ClientPacket {
            sid: 1,
            body: EncBody::enchant(client_body.clone(), key.clone(), EncAlg::ChaCha20Poly1305),
            buffer: vec![]
        };
        let client_serialized = packet.to_bytes().unwrap();

        // Server
        let deserialized_packet: ClientPacket = bincode::deserialize(&client_serialized).unwrap();
        assert_ne!(deserialized_packet.sid, 0);
        let decrypted_body = deserialized_packet.body.disenchant(key.clone(), EncAlg::ChaCha20Poly1305).unwrap();
        assert_eq!(client_body, decrypted_body);

        let server_body = EncBody::enchant(make_server_body_data(tun_ip_size), key, EncAlg::ChaCha20Poly1305);
        let server_serialized = ServerPacket(server_body).to_bytes().unwrap();

        println!(
            "test_data_aes128: \
            \nTunIpSize: {}\
            \nClientPacketSize: {}\
            \nClientEncBodySize: {}\
            \nClientPackDx: {}\
            \nServer(packet/body)Size: {}\
            \nServerPackDx: {}\n",
            tun_ip_size,
            client_serialized.len(),
            deserialized_packet.body.len(),
            client_serialized.len() - tun_ip_size,
            server_serialized.len(),
            server_serialized.len() - tun_ip_size
        );
    }
    ////////////////////////////////////////////////////////////////////////////////////////////////
}
