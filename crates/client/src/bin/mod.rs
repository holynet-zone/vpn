mod opt;
mod command;
mod style;

use crate::command::Commands;
use clap::Parser;

const LOG_DIR: &str = "logs";
const LOG_PREFIX: &str = "client.log";

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let opt = opt::Opt::parse();
    opt.init_logging();

    match opt.cmd {
        Commands::Connect(cmd) => cmd.exec().await,
    }
}
