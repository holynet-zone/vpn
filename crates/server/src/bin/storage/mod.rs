use rocksdb::DB;
use std::path::Path;

mod clients;

pub use clients::{
    Client,
    Clients
};

pub fn database(path: &Path) -> anyhow::Result<DB> {
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(true);
    DB::open(&opts, path).map_err(|error| {
        anyhow::anyhow!("failed to open database: {}", error)
    })
}