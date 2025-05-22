use crate::storage::{database, Clients};
use clap::Parser;
use derive_more::Display;
use inquire::Select;
use server::config::Config;
use shared::keys::handshake::{PublicKey, SecretKey};
use crate::style::format_opaque_bytes;
use crate::success_ok;

#[derive(Clone, Display)]
#[display("{:.8}\t{}", pk.to_string(), created_at)]
pub struct UserRow {
    pub pk: PublicKey,
    pub psk: SecretKey,
    pub created_at: String,
}

#[derive(Debug, Parser)]
pub struct ListCmd;

impl ListCmd {
    pub async fn exec(self, config: Config) -> anyhow::Result<()> {
        let clients = Clients::new(database(&config.general.storage)?)?;
        let mut users: Vec<_> = clients.get_all().await.into_iter().map(|client| {
            UserRow {
                pk: client.peer_pk,
                psk: client.psk,
                created_at: client.created_at.format("%Y-%m-%d %H:%M:%S").to_string()
            }
        }).collect();
        users.sort_by_key(|user| user.created_at.clone());
        let selected_row = Select::new("Select user", users).prompt()?;

        println!();
        success_ok!("PubKey", selected_row.pk);
        success_ok!("SharedKey", format_opaque_bytes(selected_row.psk.as_slice()));
        success_ok!("CreatedAt", selected_row.created_at);
        println!();
        
        Ok(())
    }
}