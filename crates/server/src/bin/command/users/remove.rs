use crate::storage::{database, Clients};
use clap::Parser;
use server::config::Config;
use shared::keys::handshake::PublicKey;
use crate::success_ok;

#[derive(Debug, Parser)]
pub struct RemoveCmd {
    /// public key (hex)
    #[arg(short, long)]
    pk: String,
}

impl RemoveCmd {
    pub async fn exec(self, config: Config) -> anyhow::Result<()> {
        let pk = PublicKey::try_from(self.pk.as_str()).map_err(|error| {
            anyhow::anyhow!("failed to parse public key: {}", error)
        })?;

        let clients = Clients::new(database(&config.general.storage)?)?;
        clients.delete(&pk).await?;
        success_ok!("Client has been successfully removed");
        Ok(())
    }
}