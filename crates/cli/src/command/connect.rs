use crate::config::connection::{ConnectionConfig, InterfaceConfig, RuntimeConfig};
use crate::network::{RouteState, add_route};
use crate::success_err;
use clap::Args;
use holynet_sdk::gateway::network::TunNetwork;
use holynet_sdk::gateway::transport::udp::UdpTransport;
use holynet_sdk::protocol::handshake::HandshakeResponderPayload;
use holynet_sdk::runtime::client::ClientBuilder;
use holynet_sdk::runtime::cred::Cred;
use holynet_sdk::runtime::error::RuntimeError;
use holynet_sdk::runtime::state::RuntimeState;
use holynet_sdk::tun;
use ipnetwork::IpNetwork;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{process, thread};
use tokio::sync::watch;
use tracing::{debug, error, info};
use tun_rs::AsyncDevice;

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct ConnectCmd {
    /// Connection config file path, or base64-encoded key
    #[arg(value_name = "CONNECTION")]
    connection: Option<String>,
    /// Config file path
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Base64-encoded connection key
    #[arg(short, long, value_name = "KEY")]
    key: Option<String>,
}

impl ConnectCmd {
    pub async fn exec(self) {
        let (mut config, path) = match self.connection {
            Some(ref conn) => match ConnectionConfig::from_base64(conn) {
                Ok(cfg) => (cfg, None),
                Err(_) => match ConnectionConfig::load(&PathBuf::from(conn)) {
                    Ok(cfg) => (cfg, Some(conn.clone())),
                    Err(e) => {
                        success_err!("parse connection: {}", e);
                        process::exit(1);
                    }
                },
            },
            None => match self.key {
                Some(key) => match ConnectionConfig::from_base64(&key) {
                    Ok(cfg) => (cfg, None),
                    Err(e) => {
                        success_err!("parse config key: {}", e);
                        process::exit(1);
                    }
                },
                None => match self.config {
                    Some(ref p) => match ConnectionConfig::load(p) {
                        Ok(cfg) => (cfg, Some(p.to_string_lossy().to_string())),
                        Err(e) => {
                            success_err!("load config: {}", e);
                            process::exit(1);
                        }
                    },
                    None => unreachable!(),
                },
            },
        };

        if config.runtime.is_none() {
            config.runtime = Some(RuntimeConfig::default());
        }
        if config.interface.is_none() {
            config.interface = Some(InterfaceConfig::default());
        }

        if let Some(ref p) = path
            && let Err(e) = config.save(p.as_ref())
        {
            success_err!("save config: {}", e);
            process::exit(1);
        }

        let server_addr = match config.general.host.parse::<IpAddr>() {
            Ok(ip) => SocketAddr::new(ip, config.general.port),
            Err(_) => {
                success_err!("invalid host address: {}", config.general.host);
                process::exit(1);
            }
        };

        let iface = config.interface.unwrap_or_default();
        let runtime = config.runtime.unwrap_or_default();

        let tun = match tun::setup(&iface.name, iface.mtu, false).await {
            Ok(t) => Arc::new(t),
            Err(e) => {
                success_err!("setup tun: {}", e);
                process::exit(1);
            }
        };

        let tun_name = match tun.name() {
            Ok(n) => n,
            Err(e) => {
                success_err!("get tun name: {}", e);
                process::exit(1);
            }
        };

        let routes = match RouteState::new(server_addr.ip(), tun_name).build() {
            Ok(r) => Arc::new(r),
            Err(e) => {
                success_err!("setup routes: {}", e);
                process::exit(1);
            }
        };

        let transport = match UdpTransport::new(server_addr, runtime.so_rcvbuf, runtime.so_sndbuf) {
            Ok(t) => t,
            Err(e) => {
                success_err!("create transport: {}", e);
                process::exit(1);
            }
        };

        let network = TunNetwork(tun.clone());

        let cred = Cred {
            sk: config.credentials.private_key,
            psk: config.credentials.pre_shared_key,
            spk: config.credentials.server_public_key,
        };

        let client = match ClientBuilder::new()
            .transport(transport)
            .network(network)
            .alg(config.general.alg)
            .keepalive(runtime.keepalive.map(Duration::from_secs))
            .handshake_timeout(Duration::from_millis(runtime.handshake_timeout))
            .cred(cred)
            .out_transport_buf(runtime.out_udp_buf)
            .out_network_buf(runtime.out_tun_buf)
            .data_transport_buf(runtime.data_udp_buf)
            .data_network_buf(runtime.data_tun_buf)
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                success_err!("build client: {}", e);
                process::exit(1);
            }
        };

        let state_rx = client.subscribe();
        tokio::spawn(tun_service(state_rx, tun.clone()));

        let routes_ctrlc = routes.clone();
        ctrlc::set_handler(move || {
            println!("Ctrl-C received, stopping...");
            routes_ctrlc.restore();
            thread::sleep(Duration::from_secs(1));
            process::exit(0);
        })
        .expect("error setting Ctrl-C handler");

        match client.run().await {
            Ok(_) => unreachable!(),
            Err(RuntimeError::StopSignal) => info!("runtime stopped"),
            Err(e) => {
                routes.restore();
                success_err!("{}", e);
            }
        }
    }
}

async fn tun_service(mut state_rx: watch::Receiver<RuntimeState>, tun: Arc<AsyncDevice>) {
    while state_rx.changed().await.is_ok() {
        let state = state_rx.borrow().clone();
        match state {
            RuntimeState::Connected((payload, _)) => {
                configure_tun(&tun, &payload).await;
            }
            RuntimeState::Error(_) => break,
            _ => {}
        }
    }
}

async fn configure_tun(tun: &AsyncDevice, payload: &HandshakeResponderPayload) {
    match payload.ipaddr {
        IpAddr::V4(addr) => {
            if let Err(e) = tun.set_network_address(addr, 32, None) {
                error!("set tun ipv4 address: {}", e);
                return;
            }
            let tun_name = match tun.name() {
                Ok(n) => n,
                Err(e) => {
                    error!("get tun name: {}", e);
                    return;
                }
            };
            for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
                if let Err(e) = add_route(
                    &IpNetwork::from_str(prefix).unwrap(),
                    None,
                    &tun_name,
                    Some(1),
                ) {
                    error!("add route {}: {}", prefix, e);
                }
            }
        }
        IpAddr::V6(addr) => {
            if let Err(e) = tun.add_address_v6(addr, 128) {
                error!("set tun ipv6 address: {}", e);
            }
        }
    }
    debug!("tun configured with ip {}", payload.ipaddr);
}
