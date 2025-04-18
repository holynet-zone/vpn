mod schema;
mod style;
mod actions;
mod storage;

use style::render_config;

use tracing_subscriber::{filter, fmt, layer::SubscriberExt, reload, util::SubscriberInitExt};

use clap::Parser;

const CONFIG_PATH_ENV: &str = "CONFIG_PATH";
const LOG_DIR: &str = "logs";
const LOG_PREFIX: &str = "server.log";

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = schema::Cli::parse();
    inquire::set_global_render_config(render_config());

    let file_appender = tracing_appender::rolling::daily(LOG_DIR, LOG_PREFIX);
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    let filter = filter::LevelFilter::INFO;
    let (filter, reload_handle) = reload::Layer::new(filter);
    tracing_subscriber::registry()
        .with(filter)
        .with(
            fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false),
        )
        .with(fmt::layer().with_ansi(true))
        .init();

    cli.debug.then(|| reload_handle.modify(|filter| *filter = filter::LevelFilter::DEBUG));
    match cli.command {
        schema::Commands::Start {
            host,
            port,
            iface
        } => actions::start(
            host,
            port,
            iface,
            cli.config
        ).await,
        schema::Commands::Users { commands } => match commands {
            schema::UsersCommands::Add {
                host,
                port,
                sk,
                psk,
            } => actions::add(
                cli.config,
                host,
                port,
                sk,
                psk
            ).await,
            schema::UsersCommands::Remove { pk } => actions::remove(
                cli.config,
                pk
            ).await,
            schema::UsersCommands::List => actions::list(cli.config).await,
        },
        schema::Commands::Monitor => unimplemented!("Monitor command is not implemented"),
        schema::Commands::Logs => unimplemented!("Logs command is not implemented"),
    }
}
