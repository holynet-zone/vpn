//! Node-to-node registry gossip (Phase 3.2 live anti-entropy).
//!
//! Periodically pushes this node's full signed record set to every active peer's
//! advertised endpoint. Records are self-authenticating, so a peer merges them
//! straight into its CRDT registry (rejecting anything not signed by the trusted
//! authority). Push-only epidemic: the operator seeds one node, records spread
//! transitively as each node re-advertises what it has learned.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::watch;
use tracing::{debug, warn};

use super::session::Sessions;
use crate::crypto::PublicKey;
use crate::gateway::transport::Transport;
use crate::protocol::EdgeMetric;
use crate::runtime::client::probe_node;
use crate::runtime::crypto::{TYPE_NODE_EDGES, TYPE_NODE_SYNC};

/// How long a revoked tombstone is retained before GC. It must exceed the
/// longest survivable partition (a lagging peer still holding the pre-revocation
/// record would otherwise resurrect the node), so this is deliberately weeks.
const TOMBSTONE_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Per-peer timeout when a node probes its neighbours for the routing overlay.
const EDGE_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(super) async fn gossip_loop<T: Transport>(
    mut stop: watch::Receiver<bool>,
    transport: Arc<T>,
    sessions: Sessions,
    self_pk: PublicKey,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    // Skip the immediate first tick so we do not gossip an empty set at startup.
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            _ = ticker.tick() => {
                // Reap tombstones older than the TTL, in step with each push.
                let cutoff = now_millis().saturating_sub(TOMBSTONE_TTL.as_millis() as u64);
                let reaped = sessions.gc_tombstones(cutoff);
                if reaped > 0 {
                    debug!("reaped {} expired tombstone(s)", reaped);
                }

                // Measure this node's edges to its peers and fold them into the
                // overlay so the snapshot we push carries fresh local metrics.
                let local = probe_peers(&sessions, &self_pk).await;
                if !local.is_empty() {
                    sessions.merge_edges(local);
                }

                let snapshot = sessions.sync_snapshot();
                let targets = sessions.gossip_targets(&self_pk);
                if snapshot.is_empty() || targets.is_empty() {
                    continue;
                }
                let frame = match frame_of(TYPE_NODE_SYNC, &snapshot) {
                    Some(f) => f,
                    None => continue,
                };
                let edge_frame = frame_of(TYPE_NODE_EDGES, &sessions.edge_snapshot());
                for addr in targets {
                    if let Err(e) = transport.send_to(&frame, &addr).await {
                        debug!("gossip send to {} failed: {}", addr, e);
                    }
                    if let Some(ef) = &edge_frame
                        && let Err(e) = transport.send_to(ef, &addr).await
                    {
                        debug!("edge gossip send to {} failed: {}", addr, e);
                    }
                }
            }
        }
    }
    debug!("gossip loop stopped");
}

/// Build a `type | bincode(items)` gossip frame, or `None` on encode failure.
fn frame_of<S: serde::Serialize>(ty: u8, items: &S) -> Option<Vec<u8>> {
    match bincode::serde::encode_to_vec(items, bincode::config::standard()) {
        Ok(payload) => {
            let mut frame = Vec::with_capacity(1 + payload.len());
            frame.push(ty);
            frame.extend_from_slice(&payload);
            Some(frame)
        }
        Err(e) => {
            warn!("gossip encode failed: {}", e);
            None
        }
    }
}

/// Probe every active peer once from this node's vantage and return one
/// `EdgeMetric` per peer (`from = self`), reachable or not.
async fn probe_peers(sessions: &Sessions, self_pk: &PublicKey) -> Vec<EdgeMetric> {
    let peers = sessions.peer_entries(self_pk);
    if peers.is_empty() {
        return Vec::new();
    }
    let now = now_millis();
    let futs = peers.into_iter().map(|(to, endpoint)| {
        let from = self_pk.clone();
        async move {
            let rtt = probe_node(endpoint, EDGE_PROBE_TIMEOUT).await;
            EdgeMetric {
                from,
                to,
                rtt_micros: rtt.map(|d| d.as_micros().min(u32::MAX as u128) as u32),
                updated_ms: now,
            }
        }
    });
    futures::future::join_all(futs).await
}

/// Decode a `NodeEdges` payload (bincode `Vec<EdgeMetric>`) and merge it into the
/// routing overlay. Returns the number of entries applied.
pub(super) fn on_node_edges(sessions: &Sessions, payload: &[u8]) -> usize {
    match bincode::serde::decode_from_slice(payload, bincode::config::standard()) {
        Ok((edges, _)) => sessions.merge_edges(edges),
        Err(e) => {
            warn!("edge gossip decode failed: {}", e);
            0
        }
    }
}

/// Decode a `NodeSync` payload (bincode `Vec<NodeRecord>`) and merge it into the
/// live registry. Returns the number of records applied.
pub(super) fn on_node_sync(sessions: &Sessions, payload: &[u8]) -> usize {
    match bincode::serde::decode_from_slice(payload, bincode::config::standard()) {
        Ok((records, _)) => sessions.merge_records(records),
        Err(e) => {
            warn!("gossip decode failed: {}", e);
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecretKey;
    use crate::identity::AccountKey;
    use crate::protocol::NodeEntry;
    use crate::registry::{NodeRecord, NodeRegistry};
    use crate::runtime::server::session::Sessions;
    use std::net::SocketAddr;

    fn node(label: &str, port: u16) -> (PublicKey, NodeEntry) {
        let pk = PublicKey::from_secret(&SecretKey::generate_x25519());
        let entry = NodeEntry {
            node_pk: pk.clone(),
            endpoint: SocketAddr::new("203.0.113.1".parse().unwrap(), port),
            subnet: "10.0.0.0".parse().unwrap(),
            prefix: 18,
            label: label.to_string(),
        };
        (pk, entry)
    }

    fn payload(records: &[NodeRecord]) -> Vec<u8> {
        bincode::serde::encode_to_vec(records, bincode::config::standard()).unwrap()
    }

    #[test]
    fn on_node_sync_merges_and_updates_node_list() {
        let auth = AccountKey::generate();
        let (a_pk, a_entry) = node("a", 5001);
        let (_b_pk, b_entry) = node("b", 5002);

        let mut reg = NodeRegistry::new(auth.public());
        reg.merge(NodeRecord::sign(&auth, a_entry, 1, false));
        let sessions = Sessions::with_config(
            &"10.0.0.0".parse().unwrap(),
            18,
            Vec::new(),
            Vec::new(),
            Some(reg),
        );

        assert_eq!(sessions.node_list().len(), 1);
        assert_eq!(
            sessions.gossip_targets(&a_pk),
            Vec::new(),
            "self is excluded"
        );

        let b_record = NodeRecord::sign(&auth, b_entry.clone(), 1, false);
        let applied = on_node_sync(&sessions, &payload(&[b_record]));
        assert_eq!(applied, 1);
        assert_eq!(sessions.node_list().len(), 2);
        assert_eq!(sessions.gossip_targets(&a_pk), vec![b_entry.endpoint]);

        // Re-merging the same record is a no-op (idempotent).
        let b_again = NodeRecord::sign(&auth, b_entry, 1, false);
        // A fresh signature at the same version may or may not supersede by the
        // (version, signature) tiebreak; merging our own snapshot back is the
        // real idempotency case:
        let snap = sessions.sync_snapshot();
        assert_eq!(on_node_sync(&sessions, &payload(&snap)), 0);
        let _ = b_again;
    }

    #[test]
    fn on_node_sync_rejects_untrusted_records() {
        let auth = AccountKey::generate();
        let attacker = AccountKey::generate();
        let (_pk, entry) = node("evil", 5003);

        let sessions = Sessions::with_config(
            &"10.0.0.0".parse().unwrap(),
            18,
            Vec::new(),
            Vec::new(),
            Some(NodeRegistry::new(auth.public())),
        );
        let forged = NodeRecord::sign(&attacker, entry, 1, false);
        assert_eq!(on_node_sync(&sessions, &payload(&[forged])), 0);
        assert!(sessions.node_list().is_empty());
    }

    #[test]
    fn full_wire_frame_roundtrip() {
        use crate::protocol::PacketRef;
        use crate::runtime::crypto::TYPE_NODE_SYNC;

        let auth = AccountKey::generate();
        let (_pk, entry) = node("ru", 5005);
        let sessions = Sessions::with_config(
            &"10.0.0.0".parse().unwrap(),
            18,
            Vec::new(),
            Vec::new(),
            Some(NodeRegistry::new(auth.public())),
        );

        // Build the exact frame the gossip pusher sends.
        let records = vec![NodeRecord::sign(&auth, entry, 1, false)];
        let mut frame = vec![TYPE_NODE_SYNC];
        frame.extend_from_slice(&payload(&records));

        // Parse it the way the receive path does, then merge.
        match PacketRef::from_bytes(&frame).unwrap() {
            PacketRef::NodeSync(p) => assert_eq!(on_node_sync(&sessions, p), 1),
            _ => panic!("wrong variant"),
        }
        assert_eq!(sessions.node_list().len(), 1);
    }

    #[test]
    fn merge_callback_fires_only_on_applied_records() {
        use std::sync::Mutex;

        let auth = AccountKey::generate();
        let (_pk, entry) = node("a", 6001);
        let sessions = Sessions::with_config(
            &"10.0.0.0".parse().unwrap(),
            18,
            Vec::new(),
            Vec::new(),
            Some(NodeRegistry::new(auth.public())),
        );
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = seen.clone();
        sessions.set_merge_callback(Box::new(move |recs| {
            sink.lock()
                .unwrap()
                .extend(recs.iter().map(|r| r.entry.label.clone()));
        }));

        assert_eq!(
            on_node_sync(
                &sessions,
                &payload(&[NodeRecord::sign(&auth, entry, 1, false)])
            ),
            1
        );
        assert_eq!(*seen.lock().unwrap(), vec!["a".to_string()]);

        // Re-merging our own snapshot applies nothing → callback must not fire.
        let n = seen.lock().unwrap().len();
        on_node_sync(&sessions, &payload(&sessions.sync_snapshot()));
        assert_eq!(
            seen.lock().unwrap().len(),
            n,
            "stale merge must not invoke the sink"
        );
    }

    #[test]
    fn gc_tombstones_reaps_and_notifies_reap_sink() {
        use std::sync::Mutex;

        let auth = AccountKey::generate();
        let (_pk, entry) = node("gone", 6100);
        let sessions = Sessions::with_config(
            &"10.0.0.0".parse().unwrap(),
            18,
            Vec::new(),
            Vec::new(),
            Some(NodeRegistry::new(auth.public())),
        );
        let reaped = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = reaped.clone();
        sessions.set_reap_callback(Box::new(move |recs| {
            sink.lock()
                .unwrap()
                .extend(recs.iter().map(|r| r.entry.label.clone()));
        }));

        // Old tombstone (version 100) is merged, then reaped under a later cutoff.
        on_node_sync(
            &sessions,
            &payload(&[NodeRecord::sign(&auth, entry, 100, true)]),
        );
        assert_eq!(sessions.gc_tombstones(1000), 1);
        assert_eq!(*reaped.lock().unwrap(), vec!["gone".to_string()]);
        // Idempotent: nothing left, sink not invoked again.
        assert_eq!(sessions.gc_tombstones(1000), 0);
        assert_eq!(reaped.lock().unwrap().len(), 1);
    }

    #[test]
    fn on_node_edges_merges_lww() {
        use crate::protocol::EdgeMetric;

        let auth = AccountKey::generate();
        let sessions = Sessions::with_config(
            &"10.0.0.0".parse().unwrap(),
            18,
            Vec::new(),
            Vec::new(),
            Some(NodeRegistry::new(auth.public())),
        );
        let a = PublicKey::from_secret(&SecretKey::generate_x25519());
        let b = PublicKey::from_secret(&SecretKey::generate_x25519());
        let edge = |rtt: Option<u32>, ts: u64| EdgeMetric {
            from: a.clone(),
            to: b.clone(),
            rtt_micros: rtt,
            updated_ms: ts,
        };
        let enc = |e: &[EdgeMetric]| {
            bincode::serde::encode_to_vec(e, bincode::config::standard()).unwrap()
        };

        assert_eq!(on_node_edges(&sessions, &enc(&[edge(Some(1000), 10)])), 1);
        // Newer wins.
        assert_eq!(on_node_edges(&sessions, &enc(&[edge(Some(2000), 20)])), 1);
        // Stale is a no-op.
        assert_eq!(on_node_edges(&sessions, &enc(&[edge(Some(500), 5)])), 0);
        let snap = sessions.edge_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].rtt_micros, Some(2000));
        assert_eq!(snap[0].updated_ms, 20);
    }

    #[test]
    fn on_node_sync_noop_without_registry() {
        let auth = AccountKey::generate();
        let (_pk, entry) = node("x", 5004);
        let sessions = Sessions::new(&"10.0.0.0".parse().unwrap(), 18);
        let rec = NodeRecord::sign(&auth, entry, 1, false);
        assert_eq!(on_node_sync(&sessions, &payload(&[rec])), 0);
    }
}
