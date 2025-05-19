use crate::storage::{database, Clients};
use clap::Parser;
use derive_more::Display;
use server::config::Config;

#[derive(Clone, Display)]
#[display("{}\tcreated at {}", pk, created_at)]
pub struct UserRow {
    pub pk: String,
    pub created_at: String,
}

#[derive(Debug, Parser)]
pub struct ListCmd;

impl ListCmd {
    pub async fn exec(self, config: Config) -> anyhow::Result<()> {
        let clients = Clients::new(database(&config.general.storage)?)?;
        let users: Vec<_> = clients.get_all().await.iter().map(|client| {
            UserRow {
                pk: client.peer_pk.to_string(),
                created_at: client.created_at.to_rfc2822()
            }
        }).collect();

        if users.is_empty() {
            return Err(anyhow::anyhow!("no users found"));
        }

        for user in users {
            println!("{}", user);
        }
        Ok(())
    }
}