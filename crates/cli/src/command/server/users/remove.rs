use crate::config::Config;
use crate::storage::{database, Clients};
use crate::success_ok;
use anyhow::anyhow;
use clap::Args;
use holynet_sdk::crypto::PublicKey;

#[derive(Debug, Args)]
pub struct RemoveCmd {
    /// Public key (base64)
    #[arg()]
    pk: String,
}

impl RemoveCmd {
    pub async fn exec(self, config: Config) -> anyhow::Result<()> {
        let pk = PublicKey::try_from(self.pk.as_str())
            .map_err(|e| anyhow::anyhow!("parse public key: {}", e))?;

        let clients = Clients::new(database(&config.general.storage)?)?;
        match clients.get(&pk).await {
            Some(_) => {
                clients.delete(&pk).await?;
                success_ok!("Removed", "client {:.8}", pk);
                Ok(())
            }
            None => Err(anyhow!("client {:.8} not found", pk)),
        }
    }
}
