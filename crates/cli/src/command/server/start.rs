use crate::config::Config;
use crate::storage::{database, Clients};
use crate::success_err;
use crate::success_warn;
use clap::Args;
use holynet_sdk::gateway::transport::udp::UdpTransport;
use holynet_sdk::runtime::server::ServerBuilder;
use std::net::SocketAddr;
use std::time::Duration;
use std::{process, thread};
use tracing::error;

#[derive(Debug, Args)]
pub struct StartCmd {
    /// Host to listen on (overrides config)
    #[arg(short, long)]
    host: Option<String>,
    /// Port to listen on (overrides config)
    #[arg(short, long)]
    port: Option<u16>,
    /// TUN interface name (overrides config)
    #[arg(short, long, alias = "interface")]
    iface: Option<String>,
}

impl StartCmd {
    pub async fn exec(self, mut config: Config) {
        if let Some(host) = self.host { config.general.host = host; }
        if let Some(port) = self.port { config.general.port = port; }
        if let Some(iface) = self.iface { config.interface.name = iface; }

        if let Err(e) = config.save() {
            success_warn!("cant update configuration: {}", e);
        }

        let clients = match database(&config.general.storage) {
            Ok(db) => match Clients::new(db) {
                Ok(store) => store,
                Err(e) => {
                    success_err!("failed to create client storage: {}", e);
                    process::exit(1);
                }
            },
            Err(e) => {
                success_err!("load storage: {}", e);
                process::exit(1);
            }
        };

        let known_clients: Vec<_> = clients
            .get_all()
            .await
            .into_iter()
            .map(|cl| (cl.peer_pk, cl.psk))
            .collect();

        let addr: SocketAddr = match format!("{}:{}", config.general.host, config.general.port).parse() {
            Ok(a) => a,
            Err(e) => {
                success_err!("invalid server address: {}", e);
                process::exit(1);
            }
        };

        let runtime = config.runtime.unwrap_or_default();
        let workers = if runtime.workers == 0 {
            std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
        } else {
            runtime.workers
        };

        let transports = match UdpTransport::new_pool(addr, runtime.so_rcvbuf, runtime.so_sndbuf, workers) {
            Ok(t) => t,
            Err(e) => {
                success_err!("create transport: {}", e);
                process::exit(1);
            }
        };

        let session_timeout = runtime.session.as_ref().map(|s| Duration::from_secs(s.timeout as u64));
        let cleanup_interval = runtime
            .session
            .as_ref()
            .map(|s| Duration::from_secs(s.cleanup_interval as u64))
            .unwrap_or(Duration::from_secs(60));

        let builder = ServerBuilder::new()
            .transports(transports.into_iter().map(|t| std::sync::Arc::new(t) as std::sync::Arc<dyn holynet_sdk::gateway::transport::Transport>).collect())
            .secret_key(config.general.secret_key)
            .known_clients(known_clients)
            .tun_name(config.interface.name)
            .tun_mtu(config.interface.mtu)
            .tun_ip(config.interface.address, config.interface.prefix)
            .session_timeout(session_timeout)
            .session_cleanup_interval(cleanup_interval)
            .out_transport_buf(runtime.out_udp_buf)
            .out_tun_buf(runtime.out_tun_buf)
            .handshake_buf(runtime.handshake_buf)
            .data_transport_buf(runtime.data_udp_buf)
            .data_tun_buf(runtime.data_tun_buf);

        let server = match builder.build() {
            Ok(s) => s,
            Err(e) => {
                success_err!("build server: {}", e);
                process::exit(1);
            }
        };

        ctrlc::set_handler(move || {
            println!("Ctrl-C received, stopping...");
            thread::sleep(Duration::from_secs(1));
            process::exit(0);
        })
        .expect("error setting Ctrl-C handler");

        match server.run().await {
            Ok(_) => unreachable!(),
            Err(e) => {
                error!("{}", e);
            }
        }
    }
}
