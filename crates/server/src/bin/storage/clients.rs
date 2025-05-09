use chrono::{DateTime, Utc};
use fjall::{Keyspace, PartitionCreateOptions, PartitionHandle};
use serde::{Deserialize, Serialize};
use shared::keys::handshake::{PublicKey, SecretKey};
use tokio::task;

#[derive(Serialize, Deserialize)]
pub struct Client {
    pub psk: SecretKey,
    pub peer_pk: PublicKey,
    pub created_at: DateTime<Utc>
}


#[derive(Clone)]
pub struct Clients {
    pub db: PartitionHandle
}

impl Clients {
    pub fn new(db: Keyspace) -> anyhow::Result<Self> {
        let items = db.open_partition("clients", PartitionCreateOptions::default())?;

        Ok(Self { db: items })
    }

    pub async fn get(&self, pk: &PublicKey) -> Option<Client> {
        let db = self.db.clone();
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
        let db = self.db.clone();

        task::spawn_blocking(move || {
            db.iter().map(|result| match result {
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
        let db = self.db.clone();
        let data = bincode::serde::encode_to_vec(
            &client,
            bincode::config::standard()
        ).expect("serialize client");

        task::spawn_blocking(move || {
            db.insert(*client.peer_pk, &data).expect("save client to db");
        })
            .await
            .unwrap()
    }

    pub async fn delete(&self, pk: &PublicKey) -> anyhow::Result<()> {
        let db = self.db.clone();
        let pk = pk.clone(); // todo fix

        task::spawn_blocking(move || {
            db.remove(pk.as_slice())
                .map_err(anyhow::Error::from)
        })
            .await?
    }
}