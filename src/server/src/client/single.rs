use rocksdb::DB;
use serde::{Deserialize, Serialize};
use sunbeam::protocol::keys::auth::AuthKey;

#[derive(Serialize, Deserialize)]
pub struct Client {
    pub auth_key: AuthKey
}

pub struct Clients {
    pub db: DB
}

impl Clients {
    pub fn new(db: DB) -> Self {
        Self {
            db
        }
    }

    pub fn get(&self, username: &[u8]) -> Option<Client> {
        let user = self.db.get(username).unwrap()?;
        Some(bincode::deserialize(&user).unwrap())
    }

    pub fn get_all(&self) -> Vec<(String, Client)> {
        self.db.iterator(rocksdb::IteratorMode::Start)
            .map(|result| match result {
                Ok((key, value)) => (
                    String::from_utf8(key.to_vec()).unwrap(),
                    bincode::deserialize(&value).unwrap()
                ),
                Err(_) => panic!("Failed to read from the database")
            }).collect()
    }

    pub fn save(&self, username: &[u8], client: Client) {
        let client_bytes = bincode::serialize(&client).unwrap();
        self.db.put(username, &client_bytes).unwrap();
    }

    pub fn delete(&self, username: &[u8]) {
        self.db.delete(username).unwrap();
    }
}
