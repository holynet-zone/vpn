use rocksdb::DB;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sunbeam::protocol::{
    enc::AuthEnc,
    AUTH_KEY_SIZE
};


#[derive(Serialize, Deserialize)]
pub struct Client {
    #[serde(with = "BigArray")]
    pub auth_key: [u8; AUTH_KEY_SIZE],
    pub enc: AuthEnc
}

pub fn get_client(username: &[u8], user_db: &DB) -> Option<Client> {
    let user = user_db.get(username).unwrap()?;
    Some(bincode::deserialize(&user).unwrap())
}

pub fn get_clients(user_db: &DB) -> Vec<(String, Client)> {
    user_db.iterator(rocksdb::IteratorMode::Start)
        .map(|result| match result {
            Ok((key, value)) => (
                String::from_utf8(key.to_vec()).unwrap(), 
                bincode::deserialize(&value).unwrap()
            ),
            Err(_) => panic!("Failed to read from the database")
        }).collect()
}

pub fn save_client(username: &[u8], client: Client, user_db: &DB) -> Option<Client> {
    let client_bytes = bincode::serialize(&client).unwrap();
    user_db.put(username, &client_bytes).unwrap();
    Some(client)
}

pub fn delete_client(username: &[u8], user_db: &DB) -> Option<Client> {
    let client = get_client(username, user_db)?;
    user_db.delete(username).unwrap();
    Some(client)
}
