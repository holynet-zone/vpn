mod style;
mod storage;
mod command;
mod opt;

use style::render_config;

use crate::command::Commands;
use crate::opt::Opt;
use clap::Parser;
use shared::success_err;

const CONFIG_PATH_ENV: &str = "HOLYNET_CONFIG";
const LOG_DIR: &str = "logs";
const LOG_PREFIX: &str = "server.log";

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let opt = Opt::parse();
    let _guard = match opt.init_logging() {
        Ok(guard) => guard,
        Err(err) => {
            success_err!("{}\n", err);
            std::process::exit(1);
        }
    };

    inquire::set_global_render_config(render_config());
    let config = match opt.load_config(true) {
        Ok(config) => config,
        Err(err) => {
            success_err!("load config: {}\n", err);
            std::process::exit(1);
        }
    };

    match opt.cmd {
        Commands::Start(cmd) => cmd.exec(config).await,
        Commands::Users(cmd) => cmd.exec(config).await,
        Commands::Monitor => unimplemented!("Monitor command is not implemented"),
        Commands::Logs => unimplemented!("Logs command is not implemented"),
    }
}
