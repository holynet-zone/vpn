use anyhow::anyhow;
use crate::storage::{database, Clients};
use clap::Parser;
use server::config::Config;
use shared::keys::handshake::PublicKey;
use shared::success_ok;

#[derive(Debug, Parser)]
pub struct RemoveCmd {
    /// public key
    #[arg()]
    pk: String,
}

impl RemoveCmd {
    pub async fn exec(self, config: Config) -> anyhow::Result<()> {
        let pk = PublicKey::try_from(self.pk.as_str()).map_err(|error| {
            anyhow::anyhow!("parse public key: {}", error)
        })?;

        let clients = Clients::new(database(&config.general.storage)?)?;
        match clients.get(&pk).await {
            Some(_) => {
                clients.delete(&pk).await?;
                success_ok!("Success", "client {:8} removed", pk);
                Ok(())
            },
            None => {
                Err(anyhow!("client {:8} not found", pk))
            }
        }
    }
}