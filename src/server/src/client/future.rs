use std::sync::Arc;
use rocksdb::DB;
use tokio::task;
use crate::client::Client;

#[derive(Clone)]
pub struct Clients {
    pub db: Arc<DB>,
}

impl Clients {
    pub fn new(db: DB) -> Self {
        Self { db: Arc::new(db) }
    }

    pub async fn get(&self, username: &[u8]) -> Option<Client> {
        let db = Arc::clone(&self.db);
        let username = username.to_vec();

        task::spawn_blocking(move || {
            let user = db.get(&username).unwrap()?;
            Some(bincode::deserialize(&user).unwrap())
        })
            .await
            .unwrap()
    }

    pub async fn get_all(&self) -> Vec<(String, Client)> {
        let db = Arc::clone(&self.db);

        task::spawn_blocking(move || {
            db.iterator(rocksdb::IteratorMode::Start)
                .map(|result| match result {
                    Ok((key, value)) => (
                        String::from_utf8(key.to_vec()).unwrap(),
                        bincode::deserialize(&value).unwrap(),
                    ),
                    Err(_) => panic!("Failed to read from the database"),
                })
                .collect()
        })
            .await
            .unwrap()
    }

    pub async fn save(&self, username: &[u8], client: Client) {
        let db = Arc::clone(&self.db);
        let username = username.to_vec();
        let client_bytes = bincode::serialize(&client).unwrap();

        task::spawn_blocking(move || {
            db.put(&username, &client_bytes).unwrap();
        })
            .await
            .unwrap()
    }

    pub async fn delete(&self, username: &[u8]) {
        let db = Arc::clone(&self.db);
        let username = username.to_vec();

        task::spawn_blocking(move || {
            db.delete(&username).unwrap();
        })
            .await
            .unwrap()
    }
}