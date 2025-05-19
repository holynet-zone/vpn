mod style;
mod storage;
mod command;
mod opt;

use style::render_config;

use crate::command::Commands;
use crate::opt::Opt;
use clap::Parser;

const CONFIG_PATH_ENV: &str = "HOLYNET_VPN_SERVER_CONFIG";
const LOG_DIR: &str = "logs";
const LOG_PREFIX: &str = "server.log";

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let mut opt = Opt::parse();
    let _guard = opt.init_logging()?;

    inquire::set_global_render_config(render_config());
    let config = opt.load_config(true)?;

    match opt.cmd {
        Commands::Start(cmd) => cmd.exec(config).await,
        Commands::Users(cmd) => cmd.exec(config).await,
        Commands::Monitor => unimplemented!("Monitor command is not implemented"),
        Commands::Logs => unimplemented!("Logs command is not implemented"),
    } 
    
    Ok(())
}
