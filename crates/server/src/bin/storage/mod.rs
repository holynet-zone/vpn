use fjall::{Keyspace, Config};

use std::path::Path;

mod clients;

pub use clients::{
    Client,
    Clients
};

pub fn database(path: &Path) -> anyhow::Result<Keyspace> {
    Ok(Config::new(path).open()?)
}