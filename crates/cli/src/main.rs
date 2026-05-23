mod command;
mod config;
mod network;
mod opt;
mod storage;
mod style;

use clap::Parser;
use command::Commands;
use command::server::ServerCommands;
use opt::Opt;

const LOG_DIR: &str = "logs";
const LOG_PREFIX: &str = "holynet.log";

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let opt = Opt::parse();
    let _guard = match opt.init_logging() {
        Ok(g) => g,
        Err(e) => {
            success_err!("{}", e);
            std::process::exit(1);
        }
    };

    inquire::set_global_render_config(style::render_config());

    match opt.cmd {
        Commands::Connect(cmd) => cmd.exec().await,
        Commands::Server(server_cmd) => {
            let config = match server_cmd.config.exists() {
                true => match config::Config::load(&server_cmd.config) {
                    Ok(c) => c,
                    Err(e) => {
                        success_err!("load config: {}", e);
                        std::process::exit(1);
                    }
                },
                false => {
                    let default_config = config::Config::default();
                    if let Err(e) = default_config.save_as(&server_cmd.config) {
                        success_err!("create default config: {}", e);
                        std::process::exit(1);
                    }
                    default_config
                }
            };

            match server_cmd.cmd {
                ServerCommands::Start(cmd) => cmd.exec(config).await,
                ServerCommands::Users(cmd) => cmd.exec(config).await,
            }
        }
    }
}
