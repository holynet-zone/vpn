mod opt;
mod command;
mod style;

use crate::command::Commands;
use clap::Parser;
use shared::success_err;

const LOG_DIR: &str = "logs";
const LOG_PREFIX: &str = "client.log";

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let opt = opt::Opt::parse();
    let _guard = match opt.init_logging() {
        Ok(guard) => guard,
        Err(err) => {
            success_err!("{}\n", err);
            std::process::exit(1);
        }
    };
    // console_subscriber::init();

    match opt.cmd {
        Commands::Connect(cmd) => cmd.exec().await,
    }
}
