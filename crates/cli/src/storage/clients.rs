use chrono::{DateTime, Utc};
use fjall::{Database, Keyspace, KeyspaceCreateOptions};
use holynet_sdk::crypto::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use tokio::task;

#[derive(Serialize, Deserialize)]
pub struct Client {
    pub psk: SecretKey,
    pub peer_pk: PublicKey,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct Clients {
    pub db: Keyspace,
}

impl Clients {
    pub fn new(db: Database) -> anyhow::Result<Self> {
        let items = db.keyspace("clients", KeyspaceCreateOptions::default)?;
        Ok(Self { db: items })
    }

    pub async fn get(&self, pk: &PublicKey) -> Option<Client> {
        let db = self.db.clone();
        let key = *pk.as_bytes();
        task::spawn_blocking(move || {
            let bytes = db.get(key.as_slice()).expect("get client from db")?;
            match bincode::serde::decode_from_slice(&bytes, bincode::config::standard()) {
                Ok((client, _)) => Some(client),
                Err(err) => panic!("deserialize client from db: {}", err),
            }
        })
        .await
        .unwrap()
    }

    pub async fn get_all(&self) -> Vec<Client> {
        let db = self.db.clone();
        task::spawn_blocking(move || {
            db.iter()
                .map(|guard| {
                    let value = guard.value().expect("failed to read from the db iter");
                    match bincode::serde::decode_from_slice(&value, bincode::config::standard()) {
                        Ok((client, _)) => client,
                        Err(err) => panic!("deserialize client from db: {}", err),
                    }
                })
                .collect()
        })
        .await
        .unwrap()
    }

    pub async fn save(&self, client: Client) {
        let db = self.db.clone();
        let key = *client.peer_pk.as_bytes();
        let data = bincode::serde::encode_to_vec(&client, bincode::config::standard())
            .expect("serialize client");
        task::spawn_blocking(move || {
            db.insert(key.as_slice(), &data).expect("save client to db");
        })
        .await
        .unwrap()
    }

    pub async fn delete(&self, pk: &PublicKey) -> anyhow::Result<()> {
        let db = self.db.clone();
        let key = *pk.as_bytes();
        task::spawn_blocking(move || db.remove(key.as_slice()).map_err(anyhow::Error::from)).await?
    }
}
