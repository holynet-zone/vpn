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
