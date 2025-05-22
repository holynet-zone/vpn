mod add;
mod remove;
mod list;

use clap::Subcommand;
use server::config::Config;
use crate::command::users::add::AddCmd;
use crate::command::users::list::ListCmd;
use crate::command::users::remove::RemoveCmd;
use crate::success_err;

#[derive(Debug, Subcommand)]
pub enum UsersCmd {
    /// Add a new user
    Add(AddCmd),
    /// List all users
    List(ListCmd),
    /// Remove a user
    Remove(RemoveCmd),
}

impl UsersCmd {
    pub async fn exec(self, config: Config) {
        if let Err(error) = match self {
            UsersCmd::Add(cmd) => cmd.exec(config).await,
            UsersCmd::List(cmd) => cmd.exec(config).await,
            UsersCmd::Remove(cmd) => cmd.exec(config).await
        } {
            success_err!("{}\n", error);
            std::process::exit(1);
        }
    }
}