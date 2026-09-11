//! Signed, mergeable node registry (Phase 3.2 anti-entropy core).
//!
//! Each node is described by a [`NodeRecord`]: a [`NodeEntry`] plus an LWW clock
//! and a revoked tombstone flag, signed by a network authority key. Because every
//! record carries its own signature, any node accepts a record from any peer once
//! the signature checks out against the trusted authority. That is what lets
//! untrusted relays carry the registry without being able to forge it.
//!
//! [`NodeRegistry`] merges records deterministically (last-writer-wins keyed on
//! `node_pk`, ordered by `(version, signature)`), so replicas converge regardless
//! of the order records arrive in. There is no consensus: adding is commutative,
//! revoking is a tombstone. The system is AP, not CP.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::crypto::PublicKey;
use crate::identity::{AccountKey, AccountPublicKey};
use crate::protocol::NodeEntry;

/// A signed, versioned registry record for one node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRecord {
    pub entry: NodeEntry,
    /// Last-writer-wins clock (e.g. unix millis). Higher supersedes lower.
    pub version: u64,
    /// Tombstone: a revoked record still propagates but is excluded from the
    /// active set.
    pub revoked: bool,
    pub authority: AccountPublicKey,
    #[serde(with = "sig_serde")]
    pub signature: [u8; 64],
}

mod sig_serde {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use serde::{Deserializer, Serializer, de};
    use std::fmt;

    pub fn serialize<S: Serializer>(sig: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&STANDARD_NO_PAD.encode(sig))
        } else {
            s.serialize_bytes(sig)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = [u8; 64];
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a 64-byte signature")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<[u8; 64], E> {
                let bytes = STANDARD_NO_PAD.decode(v).map_err(de::Error::custom)?;
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| de::Error::invalid_length(bytes.len(), &self))
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<[u8; 64], E> {
                v.try_into()
                    .map_err(|_| de::Error::invalid_length(v.len(), &self))
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<[u8; 64], A::Error> {
                let mut buf = [0u8; 64];
                for b in buf.iter_mut() {
                    *b = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                }
                Ok(buf)
            }
        }
        if d.is_human_readable() {
            d.deserialize_str(Visitor)
        } else {
            d.deserialize_bytes(Visitor)
        }
    }
}

fn signable(entry: &NodeEntry, version: u64, revoked: bool) -> Vec<u8> {
    bincode::serde::encode_to_vec(&(entry, version, revoked), bincode::config::standard())
        .expect("encode node record signable bytes")
}

impl NodeRecord {
    /// Issue a signed record for `entry` under `authority`.
    pub fn sign(authority: &AccountKey, entry: NodeEntry, version: u64, revoked: bool) -> Self {
        let signature = authority.sign(&signable(&entry, version, revoked));
        Self {
            entry,
            version,
            revoked,
            authority: authority.public(),
            signature,
        }
    }

    /// Verify the signature against the embedded authority key.
    pub fn verify(&self) -> bool {
        self.authority.verify(
            &signable(&self.entry, self.version, self.revoked),
            &self.signature,
        )
    }

    pub fn node_pk(&self) -> &PublicKey {
        &self.entry.node_pk
    }

    /// Deterministic supersession order: a record wins if its `(version,
    /// signature)` is strictly greater. Total and order-independent, so merges
    /// converge.
    fn supersedes(&self, other: &NodeRecord) -> bool {
        (self.version, &self.signature) > (other.version, &other.signature)
    }
}

/// A convergent set of node records trusting a single authority.
#[derive(Clone, Debug)]
pub struct NodeRegistry {
    trusted: AccountPublicKey,
    records: HashMap<PublicKey, NodeRecord>,
}

impl NodeRegistry {
    pub fn new(trusted: AccountPublicKey) -> Self {
        Self {
            trusted,
            records: HashMap::new(),
        }
    }

    /// Merge one record. Returns true if it changed local state. Records from an
    /// untrusted authority or with a bad signature are rejected.
    pub fn merge(&mut self, record: NodeRecord) -> bool {
        if record.authority != self.trusted || !record.verify() {
            return false;
        }
        match self.records.get(record.node_pk()) {
            Some(current) if !record.supersedes(current) => false,
            _ => {
                self.records.insert(record.entry.node_pk.clone(), record);
                true
            }
        }
    }

    pub fn merge_all(&mut self, records: impl IntoIterator<Item = NodeRecord>) -> usize {
        records.into_iter().filter(|r| self.clone_merge(r)).count()
    }

    fn clone_merge(&mut self, record: &NodeRecord) -> bool {
        self.merge(record.clone())
    }

    /// Active (non-revoked) node entries, sorted by node key for a stable order.
    pub fn active_entries(&self) -> Vec<NodeEntry> {
        let mut out: Vec<NodeEntry> = self
            .records
            .values()
            .filter(|r| !r.revoked)
            .map(|r| r.entry.clone())
            .collect();
        out.sort_by(|a, b| a.node_pk.as_bytes().cmp(b.node_pk.as_bytes()));
        out
    }

    /// All records including tombstones, for gossiping outward. Sorted by node key.
    pub fn records(&self) -> Vec<NodeRecord> {
        let mut out: Vec<NodeRecord> = self.records.values().cloned().collect();
        out.sort_by(|a, b| a.entry.node_pk.as_bytes().cmp(b.entry.node_pk.as_bytes()));
        out
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecretKey;
    use std::net::SocketAddr;

    fn entry(label: &str, port: u16) -> NodeEntry {
        NodeEntry {
            node_pk: PublicKey::from_secret(&SecretKey::generate_x25519()),
            endpoint: SocketAddr::new("203.0.113.1".parse().unwrap(), port),
            subnet: "10.0.0.0".parse().unwrap(),
            prefix: 18,
            label: label.to_string(),
        }
    }

    fn entry_for(pk: &PublicKey, label: &str) -> NodeEntry {
        NodeEntry {
            node_pk: pk.clone(),
            endpoint: "203.0.113.9:5000".parse().unwrap(),
            subnet: "10.0.0.0".parse().unwrap(),
            prefix: 18,
            label: label.to_string(),
        }
    }

    #[test]
    fn sign_verify_roundtrip() {
        let auth = AccountKey::generate();
        let rec = NodeRecord::sign(&auth, entry("ru", 1), 1, false);
        assert!(rec.verify());
        assert_eq!(rec.authority, auth.public());
    }

    #[test]
    fn tampered_record_fails_verify() {
        let auth = AccountKey::generate();
        let mut rec = NodeRecord::sign(&auth, entry("ru", 1), 1, false);
        rec.entry.label = "us".to_string();
        assert!(!rec.verify());
    }

    #[test]
    fn merge_rejects_untrusted_authority() {
        let trusted = AccountKey::generate();
        let attacker = AccountKey::generate();
        let mut reg = NodeRegistry::new(trusted.public());
        let rec = NodeRecord::sign(&attacker, entry("ru", 1), 1, false);
        assert!(!reg.merge(rec));
        assert!(reg.is_empty());
    }

    #[test]
    fn merge_rejects_forged_signature() {
        let trusted = AccountKey::generate();
        let mut reg = NodeRegistry::new(trusted.public());
        let mut rec = NodeRecord::sign(&trusted, entry("ru", 1), 1, false);
        rec.entry.label = "tampered".to_string();
        assert!(!reg.merge(rec));
    }

    #[test]
    fn lww_newer_version_wins_regardless_of_order() {
        let auth = AccountKey::generate();
        let pk = PublicKey::from_secret(&SecretKey::generate_x25519());
        let v1 = NodeRecord::sign(&auth, entry_for(&pk, "old"), 1, false);
        let v2 = NodeRecord::sign(&auth, entry_for(&pk, "new"), 2, false);

        let mut forward = NodeRegistry::new(auth.public());
        forward.merge(v1.clone());
        forward.merge(v2.clone());

        let mut reverse = NodeRegistry::new(auth.public());
        reverse.merge(v2.clone());
        reverse.merge(v1.clone());

        assert_eq!(forward.active_entries(), reverse.active_entries());
        assert_eq!(forward.active_entries().len(), 1);
        assert_eq!(forward.active_entries()[0].label, "new");
    }

    #[test]
    fn stale_merge_is_noop() {
        let auth = AccountKey::generate();
        let pk = PublicKey::from_secret(&SecretKey::generate_x25519());
        let v1 = NodeRecord::sign(&auth, entry_for(&pk, "old"), 1, false);
        let v2 = NodeRecord::sign(&auth, entry_for(&pk, "new"), 2, false);
        let mut reg = NodeRegistry::new(auth.public());
        assert!(reg.merge(v2));
        assert!(!reg.merge(v1), "older version must not overwrite newer");
        assert_eq!(reg.active_entries()[0].label, "new");
    }

    #[test]
    fn revoke_tombstone_hides_but_retains() {
        let auth = AccountKey::generate();
        let pk = PublicKey::from_secret(&SecretKey::generate_x25519());
        let add = NodeRecord::sign(&auth, entry_for(&pk, "ru"), 1, false);
        let revoke = NodeRecord::sign(&auth, entry_for(&pk, "ru"), 2, true);
        let mut reg = NodeRegistry::new(auth.public());
        reg.merge(add);
        reg.merge(revoke);
        assert!(
            reg.active_entries().is_empty(),
            "revoked node is not active"
        );
        assert_eq!(reg.records().len(), 1, "tombstone is retained for gossip");
        assert!(reg.records()[0].revoked);
    }

    #[test]
    fn revoke_then_readd_with_higher_version_wins() {
        let auth = AccountKey::generate();
        let pk = PublicKey::from_secret(&SecretKey::generate_x25519());
        let mut reg = NodeRegistry::new(auth.public());
        reg.merge(NodeRecord::sign(&auth, entry_for(&pk, "ru"), 1, false));
        reg.merge(NodeRecord::sign(&auth, entry_for(&pk, "ru"), 2, true));
        reg.merge(NodeRecord::sign(&auth, entry_for(&pk, "ru-back"), 3, false));
        let active = reg.active_entries();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].label, "ru-back");
    }

    #[test]
    fn serde_bincode_roundtrip() {
        let auth = AccountKey::generate();
        let rec = NodeRecord::sign(&auth, entry("ru", 7), 5, true);
        let bytes = bincode::serde::encode_to_vec(&rec, bincode::config::standard()).unwrap();
        let (back, _): (NodeRecord, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(back, rec);
        assert!(back.verify());
    }

    #[test]
    fn merge_all_counts_applied() {
        let auth = AccountKey::generate();
        let mut reg = NodeRegistry::new(auth.public());
        let recs = vec![
            NodeRecord::sign(&auth, entry("ru", 1), 1, false),
            NodeRecord::sign(&auth, entry("us", 2), 1, false),
        ];
        assert_eq!(reg.merge_all(recs), 2);
        assert_eq!(reg.active_entries().len(), 2);
    }
}
