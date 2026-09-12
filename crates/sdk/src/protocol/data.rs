use std::net::IpAddr;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use super::varint::{read_u32, read_u128, read_usize};
use super::{EdgeMetric, NodeEntry};

/// Bodies encrypted inside a Noise transport message.
#[derive(Serialize, Deserialize)]
pub enum DataServerBody {
    Packet(Bytes),
    /// Contains the client's timestamp (microseconds since process start)
    KeepAlive(u128),
    /// Contains the shutdown initiation code
    Disconnect(u8),
    LeaseGrant(IpAddr),
    NodeList(Vec<NodeEntry>),
    /// Inter-node routing overlay snapshot for client-side path planning.
    EdgeList(Vec<EdgeMetric>),
}

#[derive(Serialize, Deserialize)]
pub enum DataClientBody {
    Packet(Bytes),
    /// Contains timestamp (microseconds since process start)
    KeepAlive(u128),
    LeaseRequest,
    NodeListRequest,
    EdgeListRequest,
}

// Zero-copy borrowed views decoded from PLAIN_BUF
//
// These types borrow directly from the thread-local PLAIN_BUF after
// noise_decrypt writes the plaintext into it. They avoid a heap allocation
// for the packet payload by handing back a &[u8] slice into the buffer.
//
// Wire format is identical to the serde-derived DataClientBody / DataServerBody
// (bincode serde encodes enum variants as varint u32, and byte sequences as
// varint-usize length + raw bytes — see protocol/varint.rs for the spec).

/// Borrowed view of a decrypted `DataClientBody` message.
/// Lives as long as the PLAIN_BUF borrow passed to `from_plain_buf`.
pub(crate) enum DataClientBodyRef<'a> {
    Packet(&'a [u8]),
    KeepAlive(u128),
    LeaseRequest,
    NodeListRequest,
    EdgeListRequest,
}

impl<'a> DataClientBodyRef<'a> {
    /// Decode a `DataClientBody` from a bincode-serde-encoded buffer without
    /// allocating. Returns `None` on truncation or unknown variant.
    pub(crate) fn from_plain_buf(buf: &'a [u8]) -> Option<Self> {
        let (variant, buf) = read_u32(buf)?;
        match variant {
            0 => {
                // Packet(Bytes) — encoded as varint-usize length + raw bytes
                let (len, buf) = read_usize(buf)?;
                let data = buf.get(..len)?;
                Some(DataClientBodyRef::Packet(data))
            }
            1 => {
                // KeepAlive(u128) — encoded as varint u128
                let (ts, _) = read_u128(buf)?;
                Some(DataClientBodyRef::KeepAlive(ts))
            }
            2 => Some(DataClientBodyRef::LeaseRequest),
            3 => Some(DataClientBodyRef::NodeListRequest),
            4 => Some(DataClientBodyRef::EdgeListRequest),
            _ => None,
        }
    }
}

fn read_ip_addr(buf: &[u8]) -> Option<(IpAddr, &[u8])> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    let (variant, buf) = read_u32(buf)?;
    match variant {
        0 => {
            let octets: [u8; 4] = buf.get(..4)?.try_into().ok()?;
            Some((IpAddr::V4(Ipv4Addr::from(octets)), &buf[4..]))
        }
        1 => {
            let octets: [u8; 16] = buf.get(..16)?.try_into().ok()?;
            Some((IpAddr::V6(Ipv6Addr::from(octets)), &buf[16..]))
        }
        _ => None,
    }
}

/// Borrowed view of a decrypted `DataServerBody` message.
pub(crate) enum DataServerBodyRef<'a> {
    Packet(&'a [u8]),
    KeepAlive(u128),
    Disconnect(u8),
    LeaseGrant(IpAddr),
    NodeList(Vec<NodeEntry>),
    EdgeList(Vec<EdgeMetric>),
}

impl<'a> DataServerBodyRef<'a> {
    /// Decode a `DataServerBody` from a bincode-serde-encoded buffer without
    /// allocating. Returns `None` on truncation or unknown variant.
    pub(crate) fn from_plain_buf(buf: &'a [u8]) -> Option<Self> {
        let (variant, buf) = read_u32(buf)?;
        match variant {
            0 => {
                let (len, buf) = read_usize(buf)?;
                let data = buf.get(..len)?;
                Some(DataServerBodyRef::Packet(data))
            }
            1 => {
                let (ts, _) = read_u128(buf)?;
                Some(DataServerBodyRef::KeepAlive(ts))
            }
            2 => {
                // Disconnect(u8) — u8 is always 1 byte in bincode
                let (&code, _) = buf.split_first()?;
                Some(DataServerBodyRef::Disconnect(code))
            }
            3 => {
                let (ip, _) = read_ip_addr(buf)?;
                Some(DataServerBodyRef::LeaseGrant(ip))
            }
            4 => {
                // NodeList(Vec<NodeEntry>) is a rare control message; decode it
                // with full bincode (not the zero-copy path) since it owns data.
                let (nodes, _): (Vec<NodeEntry>, _) =
                    bincode::serde::decode_from_slice(buf, bincode::config::standard()).ok()?;
                Some(DataServerBodyRef::NodeList(nodes))
            }
            5 => {
                // EdgeList(Vec<EdgeMetric>): rare owned control message, full bincode.
                let (edges, _): (Vec<EdgeMetric>, _) =
                    bincode::serde::decode_from_slice(buf, bincode::config::standard()).ok()?;
                Some(DataServerBodyRef::EdgeList(edges))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::crypto::make_noise_pair_for_test;

    /// Encode a DataClientBody with bincode serde, then decode via
    /// DataClientBodyRef::from_plain_buf and verify the result matches.
    fn encode_client(body: &DataClientBody) -> Vec<u8> {
        let mut buf = [0u8; 65536];
        let n =
            bincode::serde::encode_into_slice(body, &mut buf, bincode::config::standard()).unwrap();
        buf[..n].to_vec()
    }

    fn encode_server(body: &DataServerBody) -> Vec<u8> {
        let mut buf = [0u8; 65536];
        let n =
            bincode::serde::encode_into_slice(body, &mut buf, bincode::config::standard()).unwrap();
        buf[..n].to_vec()
    }

    #[test]
    fn test_client_packet_roundtrip() {
        let payload = vec![1u8, 2, 3, 4, 5];
        let body = DataClientBody::Packet(Bytes::from(payload.clone()));
        let enc = encode_client(&body);
        let dec = DataClientBodyRef::from_plain_buf(&enc).unwrap();
        match dec {
            DataClientBodyRef::Packet(data) => assert_eq!(data, &payload[..]),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_client_keepalive_roundtrip() {
        for ts in [0u128, 42, 1_000_000, 5_000_000_000, u64::MAX as u128] {
            let body = DataClientBody::KeepAlive(ts);
            let enc = encode_client(&body);
            let dec = DataClientBodyRef::from_plain_buf(&enc).unwrap();
            match dec {
                DataClientBodyRef::KeepAlive(v) => assert_eq!(v, ts, "ts={ts}"),
                _ => panic!("wrong variant"),
            }
        }
    }

    #[test]
    fn test_server_packet_roundtrip() {
        let payload = vec![0xDEu8, 0xAD, 0xBE, 0xEF];
        let body = DataServerBody::Packet(Bytes::from(payload.clone()));
        let enc = encode_server(&body);
        let dec = DataServerBodyRef::from_plain_buf(&enc).unwrap();
        match dec {
            DataServerBodyRef::Packet(data) => assert_eq!(data, &payload[..]),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_server_keepalive_roundtrip() {
        for ts in [0u128, 1_000_000, u64::MAX as u128] {
            let body = DataServerBody::KeepAlive(ts);
            let enc = encode_server(&body);
            let dec = DataServerBodyRef::from_plain_buf(&enc).unwrap();
            match dec {
                DataServerBodyRef::KeepAlive(v) => assert_eq!(v, ts),
                _ => panic!("wrong variant"),
            }
        }
    }

    #[test]
    fn test_client_lease_request_roundtrip() {
        let enc = encode_client(&DataClientBody::LeaseRequest);
        match DataClientBodyRef::from_plain_buf(&enc).unwrap() {
            DataClientBodyRef::LeaseRequest => {}
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_server_lease_grant_roundtrip() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let cases = [
            IpAddr::V4(Ipv4Addr::new(10, 8, 0, 7)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x42)),
        ];
        for ip in cases {
            let enc = encode_server(&DataServerBody::LeaseGrant(ip));
            match DataServerBodyRef::from_plain_buf(&enc).unwrap() {
                DataServerBodyRef::LeaseGrant(got) => assert_eq!(got, ip),
                _ => panic!("wrong variant"),
            }
        }
    }

    fn sample_node(label: &str) -> NodeEntry {
        use crate::crypto::{PublicKey, SecretKey};
        NodeEntry {
            node_pk: PublicKey::from_secret(&SecretKey::generate_x25519()),
            endpoint: "203.0.113.7:51820".parse().unwrap(),
            subnet: "10.0.64.0".parse().unwrap(),
            prefix: 18,
            label: label.to_string(),
        }
    }

    #[test]
    fn test_client_node_list_request_roundtrip() {
        let enc = encode_client(&DataClientBody::NodeListRequest);
        match DataClientBodyRef::from_plain_buf(&enc).unwrap() {
            DataClientBodyRef::NodeListRequest => {}
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_server_node_list_roundtrip() {
        for nodes in [
            vec![],
            vec![sample_node("ru")],
            vec![sample_node("ru"), sample_node("us")],
        ] {
            let enc = encode_server(&DataServerBody::NodeList(nodes.clone()));
            match DataServerBodyRef::from_plain_buf(&enc).unwrap() {
                DataServerBodyRef::NodeList(got) => assert_eq!(got, nodes),
                _ => panic!("wrong variant"),
            }
        }
    }

    #[test]
    fn test_client_edge_list_request_roundtrip() {
        let enc = encode_client(&DataClientBody::EdgeListRequest);
        match DataClientBodyRef::from_plain_buf(&enc).unwrap() {
            DataClientBodyRef::EdgeListRequest => {}
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_server_edge_list_roundtrip() {
        use crate::crypto::{PublicKey, SecretKey};
        use crate::protocol::EdgeMetric;
        let a = PublicKey::from_secret(&SecretKey::generate_x25519());
        let b = PublicKey::from_secret(&SecretKey::generate_x25519());
        for edges in [
            vec![],
            vec![EdgeMetric {
                from: a.clone(),
                to: b.clone(),
                rtt_micros: Some(1234),
                updated_ms: 99,
            }],
            vec![EdgeMetric {
                from: a,
                to: b,
                rtt_micros: None,
                updated_ms: 7,
            }],
        ] {
            let enc = encode_server(&DataServerBody::EdgeList(edges.clone()));
            match DataServerBodyRef::from_plain_buf(&enc).unwrap() {
                DataServerBodyRef::EdgeList(got) => assert_eq!(got, edges),
                _ => panic!("wrong variant"),
            }
        }
    }

    #[test]
    fn test_server_disconnect_roundtrip() {
        for code in [0u8, 1, 42, 255] {
            let body = DataServerBody::Disconnect(code);
            let enc = encode_server(&body);
            let dec = DataServerBodyRef::from_plain_buf(&enc).unwrap();
            match dec {
                DataServerBodyRef::Disconnect(c) => assert_eq!(c, code),
                _ => panic!("wrong variant"),
            }
        }
    }

    #[test]
    fn test_large_payload_1400_bytes() {
        let payload = vec![0xABu8; 1400];
        let body = DataClientBody::Packet(Bytes::from(payload.clone()));
        let enc = encode_client(&body);
        let dec = DataClientBodyRef::from_plain_buf(&enc).unwrap();
        match dec {
            DataClientBodyRef::Packet(data) => assert_eq!(data, &payload[..]),
            _ => panic!("wrong variant"),
        }
    }

    /// End-to-end: noise_encrypt → noise_decrypt_data_client_into → verify payload
    #[test]
    fn test_noise_roundtrip_via_body_ref() {
        use crate::runtime::crypto::{
            DataClientActionRef, noise_decrypt_data_client_into, noise_encrypt,
        };

        let (tx, rx) = make_noise_pair_for_test();
        let payload = vec![1u8, 2, 3, 4, 5];
        let body = DataClientBody::Packet(Bytes::from(payload.clone()));
        let enc = noise_encrypt(&body, &tx, 0).unwrap();

        let mut plain = [0u8; 65536];
        match noise_decrypt_data_client_into(&enc, &rx, &mut plain, 0).unwrap() {
            DataClientActionRef::Forward(packet) => assert_eq!(packet, &payload[..]),
            _ => panic!("wrong action"),
        }
    }

    #[test]
    fn test_noise_roundtrip_keepalive() {
        use crate::runtime::crypto::{
            DataClientActionRef, noise_decrypt_data_client_into, noise_encrypt,
        };

        let (tx, rx) = make_noise_pair_for_test();
        let ts = 0xDEAD_CAFE_1234_5678u128;
        let body = DataClientBody::KeepAlive(ts);
        let enc = noise_encrypt(&body, &tx, 0).unwrap();

        let mut plain = [0u8; 65536];
        match noise_decrypt_data_client_into(&enc, &rx, &mut plain, 0).unwrap() {
            DataClientActionRef::KeepAlive(v) => assert_eq!(v, ts),
            _ => panic!("wrong action"),
        }
    }
}
