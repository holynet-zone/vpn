use crate::config::Config;
use crate::storage::{Clients, database};
use crate::success_ok;
use anyhow::anyhow;
use clap::Args;
use holynet_sdk::identity::AccountPublicKey;

#[derive(Debug, Args)]
pub struct RemoveCmd {
    /// Account public key (base64)
    #[arg()]
    account: String,
}

impl RemoveCmd {
    pub async fn exec(self, config: Config) -> anyhow::Result<()> {
        let account = AccountPublicKey::try_from(self.account.as_str())
            .map_err(|e| anyhow::anyhow!("parse account public key: {}", e))?;

        let clients = Clients::new(database(&config.general.storage)?)?;
        match clients.get(&account).await {
            Some(_) => {
                clients.delete(&account).await?;
                success_ok!("Removed", "account {:.8}", account);
                Ok(())
            }
            None => Err(anyhow!("account {:.8} not found", account)),
        }
    }
}
