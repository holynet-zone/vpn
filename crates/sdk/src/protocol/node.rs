use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::crypto::PublicKey;

/// A node in the multi-node registry as advertised to clients over the control
/// channel. Describes who owns which slice of address space and where to reach
/// them. Liveness (alive/rtt) is an overlay computed per-observer and is not
/// part of this durable record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeEntry {
    /// Node's static Noise public key (endpoint identity).
    pub node_pk: PublicKey,
    /// Reachable UDP endpoint (host:port) clients dial to connect.
    pub endpoint: SocketAddr,
    /// Base address of the subnet this node owns.
    pub subnet: IpAddr,
    /// Prefix length of the owned subnet.
    pub prefix: u8,
    /// Human label (continent / site name).
    pub label: String,
}
