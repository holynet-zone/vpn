mod add;
mod list;
mod remove;

use crate::config::Config;
use crate::success_err;
use add::AddCmd;
use clap::Subcommand;
use list::ListCmd;
use remove::RemoveCmd;

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
        if let Err(e) = match self {
            UsersCmd::Add(cmd) => cmd.exec(config).await,
            UsersCmd::List(cmd) => cmd.exec(config).await,
            UsersCmd::Remove(cmd) => cmd.exec(config).await,
        } {
            success_err!("{}", e);
            std::process::exit(1);
        }
    }
}
