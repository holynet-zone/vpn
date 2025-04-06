use chrono::{DateTime, Utc};
use rocksdb::DB;
use serde::{Deserialize, Serialize};
use shared::keys::handshake::{PublicKey, SecretKey};
use std::sync::Arc;
use tokio::task;

#[derive(Serialize, Deserialize)]
pub struct Client {
    pub psk: SecretKey,
    pub peer_pk: PublicKey,
    pub created_at: DateTime<Utc>
}


#[derive(Clone)]
pub struct Clients {
    pub db: Arc<DB>,
}

impl Clients {
    pub fn new(db: DB) -> Self {
        Self { db: Arc::new(db) }
    }

    pub async fn get(&self, pk: &PublicKey) -> Option<Client> {
        let db = Arc::clone(&self.db);
        let pk = pk.clone(); // todo fix

        task::spawn_blocking(move || {
            Some(bincode::deserialize(
                &db.get(pk.as_slice()).expect("failed to get client from db")?
            ).expect("failed to deserialize client from db"))
        })
            .await
            .unwrap()
    }

    pub async fn get_all(&self) -> Vec<Client> {
        let db = Arc::clone(&self.db);

        task::spawn_blocking(move || {
            db.iterator(rocksdb::IteratorMode::Start)
                .map(|result| match result {
                    Ok((_, value)) => bincode::deserialize(&value)
                        .expect("failed to deserialize client from db"),
                    Err(err) => panic!("failed to read from the db iter: {}", err),
                })
                .collect()
        })
            .await
            .unwrap()
    }

    pub async fn save(&self, client: Client) {
        let db = Arc::clone(&self.db);
        let data = bincode::serialize(&client).expect("failed to serialize client");

        task::spawn_blocking(move || {
            db.put(&*client.peer_pk, &data).expect("failed to save client to db");
        })
            .await
            .unwrap()
    }

    pub async fn delete(&self, pk: &PublicKey) -> anyhow::Result<()> {
        let db = Arc::clone(&self.db);
        let pk = pk.clone(); // todo fix

        task::spawn_blocking(move || {
            db.delete(&pk.as_slice())
                .map_err(|err| anyhow::Error::from(err))
        })
            .await?
    }
}