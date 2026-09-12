use fjall::{Database, Keyspace, KeyspaceCreateOptions};
use holynet_sdk::registry::NodeRecord;
use tokio::task;

#[derive(Clone)]
pub struct Nodes {
    db: Keyspace,
}

impl Nodes {
    pub fn new(db: Database) -> anyhow::Result<Self> {
        let items = db.keyspace("nodes", KeyspaceCreateOptions::default)?;
        Ok(Self { db: items })
    }

    pub async fn save(&self, record: NodeRecord) {
        let db = self.db.clone();
        let key = *record.node_pk().as_bytes();
        let data = bincode::serde::encode_to_vec(&record, bincode::config::standard())
            .expect("serialize node record");
        task::spawn_blocking(move || {
            db.insert(key.as_slice(), &data).expect("save node record");
        })
        .await
        .unwrap()
    }

    /// Synchronous insert for use from non-async contexts (e.g. the SDK's
    /// gossip-merge callback). fjall inserts hit the memtable and are fast.
    pub fn save_blocking(&self, record: &NodeRecord) {
        let key = *record.node_pk().as_bytes();
        let data = bincode::serde::encode_to_vec(record, bincode::config::standard())
            .expect("serialize node record");
        if let Err(e) = self.db.insert(key.as_slice(), &data) {
            tracing::warn!("persist gossiped node record failed: {}", e);
        }
    }

    /// Synchronous delete for the SDK's tombstone-reap callback: drops a reaped
    /// record so it does not reload into the registry on the next restart.
    pub fn delete_blocking(&self, record: &NodeRecord) {
        let key = *record.node_pk().as_bytes();
        if let Err(e) = self.db.remove(key.as_slice()) {
            tracing::warn!("delete reaped node record failed: {}", e);
        }
    }

    pub async fn get_all(&self) -> Vec<NodeRecord> {
        let db = self.db.clone();
        task::spawn_blocking(move || {
            db.iter()
                .map(|guard| {
                    let value = guard.value().expect("read node record from db iter");
                    match bincode::serde::decode_from_slice(&value, bincode::config::standard()) {
                        Ok((record, _)) => record,
                        Err(err) => panic!("deserialize node record from db: {}", err),
                    }
                })
                .collect()
        })
        .await
        .unwrap()
    }
}
