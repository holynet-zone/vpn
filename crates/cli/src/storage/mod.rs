mod clients;

pub use clients::{Client, Clients};

use fjall::{Config, Keyspace};
use std::path::Path;

pub fn database(path: &Path) -> anyhow::Result<Keyspace> {
    Ok(Config::new(path).open()?)
}
