use crate::config::Config;
use crate::storage::{Clients, database};
use crate::style::format_opaque_bytes;
use crate::success_ok;
use clap::Args;
use derive_more::Display;
use holynet_sdk::crypto::SecretKey;
use holynet_sdk::identity::AccountPublicKey;
use inquire::Select;

#[derive(Clone, Display)]
#[display("{:.8}\t{}", account.to_string(), created_at)]
pub struct UserRow {
    pub account: AccountPublicKey,
    pub device_index: u32,
    pub psk: SecretKey,
    pub created_at: String,
}

#[derive(Debug, Args)]
pub struct ListCmd;

impl ListCmd {
    pub async fn exec(self, config: Config) -> anyhow::Result<()> {
        let clients = Clients::new(database(&config.general.storage)?)?;
        let mut users: Vec<_> = clients
            .get_all()
            .await
            .into_iter()
            .map(|client| UserRow {
                account: client.account_pub,
                device_index: client.device_index,
                psk: client.psk,
                created_at: client.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            })
            .collect();
        users.sort_by_key(|u| u.created_at.clone());

        let selected = Select::new("Select user", users).prompt()?;

        println!();
        success_ok!("Account", selected.account);
        success_ok!("DeviceIndex", selected.device_index);
        success_ok!("SharedKey", format_opaque_bytes(selected.psk.as_slice()));
        success_ok!("CreatedAt", selected.created_at);
        println!();

        Ok(())
    }
}
