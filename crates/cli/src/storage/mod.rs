mod clients;
mod nodes;

pub use clients::{Client, Clients};
pub use nodes::Nodes;

use fjall::{Config, Database};
use std::path::Path;

pub fn database(path: &Path) -> anyhow::Result<Database> {
    Ok(Database::open(Config::new(path))?)
}
