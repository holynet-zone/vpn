use serde::{Deserialize, Serialize};
use sunbeam::protocol::keys::auth::AuthKey;
pub mod future;
pub mod single;


#[derive(Serialize, Deserialize)]
pub struct Client {
    pub auth_key: AuthKey,
}
