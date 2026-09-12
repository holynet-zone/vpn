use serde::{Deserialize, Serialize};

use crate::crypto::PublicKey;

/// A directed inter-node link measurement: node `from` observed node `to` at
/// `rtt_micros` round-trip (or unreachable when `None`) as of `updated_ms`.
///
/// This is an ephemeral routing overlay, not durable identity: nodes measure
/// their own outgoing edges (probing peers with `NodePing`) and gossip them so a
/// client can weight a multi-hop path it could never measure itself (it only
/// sees its own vantage point). Edges are self-reported and unsigned; they only
/// bias path selection and never affect data-plane correctness (the client's
/// end-to-end Noise session with the final node still protects the payload).
/// Merged last-writer-wins per `(from, to)` on `updated_ms`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeMetric {
    pub from: PublicKey,
    pub to: PublicKey,
    /// Round-trip time in microseconds, or `None` if `to` was probed but silent.
    pub rtt_micros: Option<u32>,
    /// LWW clock (unix millis) when `from` took this measurement.
    pub updated_ms: u64,
}
