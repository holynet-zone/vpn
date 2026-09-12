//! Node-to-node registry gossip (Phase 3.2 live anti-entropy).
//!
//! Periodically pushes this node's full signed record set to every active peer's
//! advertised endpoint. Records are self-authenticating, so a peer merges them
//! straight into its CRDT registry (rejecting anything not signed by the trusted
//! authority). Push-only epidemic: the operator seeds one node, records spread
//! transitively as each node re-advertises what it has learned.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, warn};

use super::session::Sessions;
use crate::crypto::PublicKey;
use crate::gateway::transport::Transport;
use crate::runtime::crypto::TYPE_NODE_SYNC;

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
                let snapshot = sessions.sync_snapshot();
                let targets = sessions.gossip_targets(&self_pk);
                if snapshot.is_empty() || targets.is_empty() {
                    continue;
                }
                let payload = match bincode::serde::encode_to_vec(
                    &snapshot,
                    bincode::config::standard(),
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("gossip encode failed: {}", e);
                        continue;
                    }
                };
                let mut frame = Vec::with_capacity(1 + payload.len());
                frame.push(TYPE_NODE_SYNC);
                frame.extend_from_slice(&payload);
                for addr in targets {
                    if let Err(e) = transport.send_to(&frame, &addr).await {
                        debug!("gossip send to {} failed: {}", addr, e);
                    }
                }
            }
        }
    }
    debug!("gossip loop stopped");
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
    fn on_node_sync_noop_without_registry() {
        let auth = AccountKey::generate();
        let (_pk, entry) = node("x", 5004);
        let sessions = Sessions::new(&"10.0.0.0".parse().unwrap(), 18);
        let rec = NodeRecord::sign(&auth, entry, 1, false);
        assert_eq!(on_node_sync(&sessions, &payload(&[rec])), 0);
    }
}
