use crate::config::connection::{ConnectionConfig, InterfaceConfig, RuntimeConfig};
use crate::network::{RouteState, add_route};
use crate::success_err;
use clap::Args;
use holynet_sdk::crypto::PublicKey;
use holynet_sdk::gateway::network::tun::TunNetwork;
use holynet_sdk::gateway::transport::ClientTransport;
use holynet_sdk::gateway::transport::relay::RelayTransport;
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
    /// One or more connection sources (config file path or base64 key). Give
    /// several to join multiple non-overlapping networks at once (multi-network):
    /// each routes only its own subnet through its tunnel.
    #[arg(value_name = "CONNECTION", num_args = 1..)]
    connection: Vec<String>,
    /// Single-connection config file path (alternative to a positional CONNECTION).
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Single-connection base64 key (alternative to a positional CONNECTION).
    #[arg(short, long, value_name = "KEY")]
    key: Option<String>,
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

/// Load a connection config from a source string: try base64 first, then a file
/// path. Returns the config and the path (for save-back) when it was a file.
fn load_source(src: &str) -> anyhow::Result<(ConnectionConfig, Option<String>)> {
    match ConnectionConfig::from_base64(src) {
        Ok(cfg) => Ok((cfg, None)),
        Err(_) => ConnectionConfig::load(&PathBuf::from(src))
            .map(|cfg| (cfg, Some(src.to_string())))
            .map_err(|e| anyhow::anyhow!("parse connection {}: {}", src, e)),
    }
}

impl ConnectCmd {
    pub async fn exec(self) {
        // Gather sources: positional list, or the single --config / --key flag.
        let mut sources: Vec<String> = self.connection.clone();
        if sources.is_empty() {
            if let Some(k) = &self.key {
                sources.push(k.clone());
            } else if let Some(c) = &self.config {
                sources.push(c.to_string_lossy().to_string());
            }
        }
        if sources.is_empty() {
            success_err!("no connection given (pass a config/key, or several for multi-network)");
            process::exit(1);
        }

        // Multiple sources => join several non-overlapping networks at once.
        if sources.len() > 1 {
            if self.via.is_some() || !self.hop.is_empty() {
                success_err!("--via/--hop is not supported with multiple networks");
                process::exit(1);
            }
            multi_network(&sources, self.no_offload).await;
            return;
        }

        let (mut config, path) = match load_source(&sources[0]) {
            Ok(v) => v,
            Err(e) => {
                success_err!("{}", e);
                process::exit(1);
            }
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
    tokio::spawn(tun_service(state_rx, tun_arc, RouteMode::Default));

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

/// Join several non-overlapping networks at once: one tunnel per source, each
/// routing only its own subnet. Requires every config to carry `general.network`.
async fn multi_network(sources: &[String], no_offload: bool) {
    let mut all_routes: Vec<Arc<RouteState>> = Vec::new();
    let mut set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

    for src in sources {
        let mut config = match load_source(src) {
            Ok((c, _)) => c,
            Err(e) => {
                success_err!("{}", e);
                process::exit(1);
            }
        };
        let Some(net) = config.general.network.clone() else {
            success_err!("multi-network needs a network subnet in each config (missing in {src})");
            process::exit(1);
        };
        let server_addr = match config.general.host.parse::<IpAddr>() {
            Ok(ip) => SocketAddr::new(ip, config.general.port),
            Err(_) => {
                success_err!("invalid host address: {}", config.general.host);
                process::exit(1);
            }
        };

        let mut iface = config.interface.take().unwrap_or_default();
        if no_offload {
            iface.offload = false;
        }
        let runtime = config.runtime.take().unwrap_or_default();

        // Sequential setup so each TUN gets a distinct auto-picked name.
        let tun = match TunNetwork::new(&iface.name, iface.mtu, false, None, iface.offload).await {
            Ok(t) => t,
            Err(e) => {
                success_err!("setup tun ({}): {}", src, e);
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
                success_err!("setup routes ({}): {}", src, e);
                process::exit(1);
            }
        };
        all_routes.push(routes.clone());

        let transport = match UdpTransport::new(server_addr, runtime.so_rcvbuf, runtime.so_sndbuf) {
            Ok(t) => t,
            Err(e) => {
                success_err!("create transport ({}): {}", src, e);
                process::exit(1);
            }
        };
        let cred = Cred {
            sk: config.credentials.private_key,
            psk: config.credentials.pre_shared_key,
            spk: config.credentials.server_public_key,
            enrollment: config.credentials.enrollment,
        };
        let alg = config.general.alg;
        let tun_arc = Arc::new(tun.clone());
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
                success_err!("build client ({}): {}", src, e);
                process::exit(1);
            }
        };
        let state_rx = client.subscribe();
        tokio::spawn(tun_service(
            state_rx,
            tun_arc,
            RouteMode::Subnet(net.subnet, net.prefix),
        ));
        info!("network {}/{} via {}", net.subnet, net.prefix, server_addr);
        set.spawn(async move {
            match client.run().await {
                Ok(_) => unreachable!(),
                Err(RuntimeError::StopSignal) => info!("runtime stopped"),
                Err(e) => success_err!("network error: {}", e),
            }
        });
    }

    // One Ctrl-C handler restores every network's routes.
    let cleanup = all_routes.clone();
    ctrlc::set_handler(move || {
        println!("Ctrl-C received, stopping...");
        for r in &cleanup {
            r.restore();
        }
        thread::sleep(Duration::from_secs(1));
        process::exit(0);
    })
    .expect("error setting Ctrl-C handler");

    while set.join_next().await.is_some() {}
    for r in &all_routes {
        r.restore();
    }
}

/// How a tunnel claims routes once its address is leased.
#[derive(Clone, Copy)]
enum RouteMode {
    /// Full-tunnel: default route (0.0.0.0/1 + 128.0.0.0/1). Single-network VPN.
    Default,
    /// Split: route only this network's subnet through the tunnel (multi-network).
    Subnet(IpAddr, u8),
}

async fn tun_service(
    mut state_rx: watch::Receiver<RuntimeState>,
    tun: Arc<TunNetwork>,
    route: RouteMode,
) {
    while state_rx.changed().await.is_ok() {
        let state = state_rx.borrow().clone();
        match state {
            RuntimeState::Connected((payload, _)) => {
                configure_tun(&tun, &payload, route).await;
            }
            RuntimeState::Error(_) => break,
            _ => {}
        }
    }
}

async fn configure_tun(tun: &TunNetwork, payload: &SessionInfo, route: RouteMode) {
    let prefix = match payload.ipaddr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if let Err(e) = tun.configure_ip(payload.ipaddr, prefix) {
        error!("configure tun ip {}: {}", payload.ipaddr, e);
        return;
    }
    let tun_name = match tun.name() {
        Ok(n) => n,
        Err(e) => {
            error!("get tun name: {}", e);
            return;
        }
    };
    let routes: Vec<IpNetwork> = match route {
        RouteMode::Default if payload.ipaddr.is_ipv4() => vec![
            IpNetwork::from_str("0.0.0.0/1").unwrap(),
            IpNetwork::from_str("128.0.0.0/1").unwrap(),
        ],
        RouteMode::Default => vec![],
        RouteMode::Subnet(net, plen) => match IpNetwork::new(net, plen) {
            Ok(n) => vec![n],
            Err(e) => {
                error!("invalid network route {}/{}: {}", net, plen, e);
                vec![]
            }
        },
    };
    for net in routes {
        if let Err(e) = add_route(&net, None, &tun_name, Some(1)) {
            error!("add route {}: {}", net, e);
        }
    }
    debug!(
        "tun configured with ip {} ({} routes)",
        payload.ipaddr,
        route_label(route)
    );
}

fn route_label(route: RouteMode) -> String {
    match route {
        RouteMode::Default => "default".to_string(),
        RouteMode::Subnet(net, plen) => format!("{net}/{plen}"),
    }
}
