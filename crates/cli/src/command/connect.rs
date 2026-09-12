use crate::config::connection::{ConnectionConfig, InterfaceConfig, RuntimeConfig};
use crate::network::{RouteState, add_route};
use crate::success_err;
use clap::Args;
use holynet_sdk::gateway::network::tun::TunNetwork;
use holynet_sdk::gateway::transport::ClientTransport;
use holynet_sdk::gateway::transport::relay::RelayTransport;
use holynet_sdk::crypto::PublicKey;
use holynet_sdk::gateway::transport::udp::UdpTransport;
use holynet_sdk::protocol::Alg;
use holynet_sdk::runtime::client::ClientBuilder;
use holynet_sdk::runtime::cred::Cred;
use holynet_sdk::runtime::error::RuntimeError;
use holynet_sdk::runtime::state::{RuntimeState, SessionInfo};
use ipnetwork::IpNetwork;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{process, thread};
use tokio::sync::watch;
use tracing::{debug, error, info};

#[derive(Debug, Args)]
pub struct ConnectCmd {
    #[command(flatten)]
    source: ConnectSource,
    /// Force-disable Linux TUN GRO/TSO offload, overriding `interface.offload`
    /// in the config (runtime kill-switch for buggy NICs).
    #[arg(long)]
    no_offload: bool,
    /// Reach the target node through a relay node at this `host:port`. The dialed
    /// address becomes the relay; the end-to-end session is still with the target
    /// node (the config's server public key), which the relay never decrypts.
    #[arg(long, value_name = "HOST:PORT")]
    via: Option<String>,
    /// Intermediate relay pubkey(s) to chain before the target (multi-hop).
    /// `--via R1 --hop R2pk` gives client->R1->R2->target. Each relay must know
    /// the next hop in its registry. Currently at most one `--hop` (3-hop total).
    #[arg(long, value_name = "PUBKEY", requires = "via")]
    hop: Vec<String>,
}

/// Mutually-exclusive connection source: exactly one must be provided.
#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct ConnectSource {
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
        let (mut config, path) = match self.source.connection {
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
            None => match self.source.key {
                Some(key) => match ConnectionConfig::from_base64(&key) {
                    Ok(cfg) => (cfg, None),
                    Err(e) => {
                        success_err!("parse config key: {}", e);
                        process::exit(1);
                    }
                },
                None => match self.source.config {
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

        let mut iface = config.interface.unwrap_or_default();
        let runtime = config.runtime.unwrap_or_default();

        // Runtime kill-switch: applied after the config save above so it never
        // persists to disk, and only ever disables — never enables — offload.
        if self.no_offload {
            iface.offload = false;
        }

        let tun = match TunNetwork::new(&iface.name, iface.mtu, false, None, iface.offload).await {
            Ok(t) => t,
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

        // With `--via`, the client dials the relay node instead of the target;
        // the end-to-end session is still with the target (config server pubkey).
        let dial_addr = match &self.via {
            Some(v) => match v.parse::<SocketAddr>() {
                Ok(a) => a,
                Err(e) => {
                    success_err!("invalid --via address {}: {}", v, e);
                    process::exit(1);
                }
            },
            None => server_addr,
        };

        let routes = match RouteState::new(dial_addr.ip(), tun_name).build() {
            Ok(r) => Arc::new(r),
            Err(e) => {
                success_err!("setup routes: {}", e);
                process::exit(1);
            }
        };

        let udp = match UdpTransport::new(dial_addr, runtime.so_rcvbuf, runtime.so_sndbuf) {
            Ok(t) => t,
            Err(e) => {
                success_err!("create transport: {}", e);
                process::exit(1);
            }
        };

        let dest_pk = config.credentials.server_public_key.clone();
        let cred = Cred {
            sk: config.credentials.private_key,
            psk: config.credentials.pre_shared_key,
            spk: config.credentials.server_public_key,
            enrollment: config.credentials.enrollment,
        };

        let tun_arc = Arc::new(tun.clone());
        let alg = config.general.alg;
        let hs_to = Duration::from_millis(runtime.handshake_timeout);

        // Parse intermediate relay hop pubkeys (multi-hop chaining).
        let hop_pks: Vec<PublicKey> = match self
            .hop
            .iter()
            .map(|s| PublicKey::try_from(s.as_str()))
            .collect()
        {
            Ok(v) => v,
            Err(e) => {
                success_err!("parse --hop pubkey: {}", e);
                process::exit(1);
            }
        };

        // Nesting a RelayTransport per hop gives multi-hop for free: each relay
        // forwards opaque bytes, stripping exactly its own layer.
        match (self.via.is_some(), hop_pks.as_slice()) {
            (false, _) => run_client(udp, tun, tun_arc, cred, alg, runtime, routes).await,
            (true, []) => {
                let relay = RelayTransport::new(Arc::new(udp), dest_pk, hs_to);
                run_client(relay, tun, tun_arc, cred, alg, runtime, routes).await;
            }
            (true, [h1]) => {
                let inner = RelayTransport::new(Arc::new(udp), h1.clone(), hs_to);
                let outer = RelayTransport::new(Arc::new(inner), dest_pk, hs_to);
                run_client(outer, tun, tun_arc, cred, alg, runtime, routes).await;
            }
            (true, _) => {
                success_err!("at most one --hop (3-hop) is currently supported");
                process::exit(1);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_client<T: ClientTransport + 'static>(
    transport: T,
    tun: TunNetwork,
    tun_arc: Arc<TunNetwork>,
    cred: Cred,
    alg: Alg,
    runtime: RuntimeConfig,
    routes: Arc<RouteState>,
) {
    let client = match ClientBuilder::new(transport, tun)
        .alg(alg)
        .keepalive(runtime.keepalive.map(Duration::from_secs))
        .handshake_timeout(Duration::from_millis(runtime.handshake_timeout))
        .cred(cred)
        .encrypt_workers(crate::config::resolve_pool_workers(runtime.encrypt_workers))
        .decrypt_workers(crate::config::resolve_pool_workers(runtime.decrypt_workers))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            success_err!("build client: {}", e);
            process::exit(1);
        }
    };

    let state_rx = client.subscribe();
    tokio::spawn(tun_service(state_rx, tun_arc));

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

async fn tun_service(mut state_rx: watch::Receiver<RuntimeState>, tun: Arc<TunNetwork>) {
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

async fn configure_tun(tun: &TunNetwork, payload: &SessionInfo) {
    let prefix = match payload.ipaddr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if let Err(e) = tun.configure_ip(payload.ipaddr, prefix) {
        error!("configure tun ip {}: {}", payload.ipaddr, e);
        return;
    }
    if payload.ipaddr.is_ipv4() {
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
    debug!("tun configured with ip {}", payload.ipaddr);
}
