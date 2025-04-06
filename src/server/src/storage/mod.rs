use std::path::Path;
use std::process;
use rocksdb::DB;
use serde::{Deserialize, Serialize};
use tracing::error;

mod clients;

pub use clients::{
    Clients,
    Client
};

pub fn database(path: &Path) -> anyhow::Result<DB> {
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(true);
    DB::open(&opts, path).map_err(|error| {
        anyhow::anyhow!("failed to open database: {}", error)
    })
}