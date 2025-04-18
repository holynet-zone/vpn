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
            match bincode::serde::decode_from_slice(
                &db.get(pk.as_slice()).expect("get client from db")?,
                bincode::config::standard()
            ) {
                Ok((client, _)) => Some(client),
                Err(err) => panic!("deserialize client from db: {}", err)
            }
        })
            .await
            .unwrap()
    }

    pub async fn get_all(&self) -> Vec<Client> {
        let db = Arc::clone(&self.db);

        task::spawn_blocking(move || {
            db.iterator(rocksdb::IteratorMode::Start).map(|result| match result {
                Ok((_, value)) => match bincode::serde::decode_from_slice(
                    &value,
                    bincode::config::standard()
                ) {
                    Ok((client, _)) => client,
                    Err(err) => panic!("deserialize client from db: {}", err)
                },
                Err(err) => panic!("failed to read from the db iter: {}", err),
            })
            .collect()
        })
            .await
            .unwrap()
    }

    pub async fn save(&self, client: Client) {
        let db = Arc::clone(&self.db);
        let data = bincode::serde::encode_to_vec(
            &client,
            bincode::config::standard()
        ).expect("serialize client");

        task::spawn_blocking(move || {
            db.put(*client.peer_pk, &data).expect("save client to db");
        })
            .await
            .unwrap()
    }

    pub async fn delete(&self, pk: &PublicKey) -> anyhow::Result<()> {
        let db = Arc::clone(&self.db);
        let pk = pk.clone(); // todo fix

        task::spawn_blocking(move || {
            db.delete(pk.as_slice())
                .map_err(anyhow::Error::from)
        })
            .await?
    }
}