use crate::config::connection::ConnectionConfig;
use crate::success_err;
use crate::success_ok;
use clap::Args;
use holynet_sdk::gateway::transport::udp::UdpTransport;
use holynet_sdk::runtime::client::{fetch_topology, plan_route, probe_nodes};
use holynet_sdk::runtime::cred::Cred;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use std::time::Duration;

/// Compute and print the lowest-latency multi-hop path to the connection's target
/// node, using the node registry, the gossiped inter-node routing overlay, and
/// this client's own probes. Prints the equivalent `connect --via/--hop` args.
#[derive(Debug, Args)]
pub struct RouteCmd {
    /// Connection config file path, or base64-encoded connection key
    #[arg(value_name = "CONNECTION")]
    connection: String,
    /// Entry node to fetch the topology from (host:port). Defaults to the
    /// connection's own server. Must be directly reachable and know your account.
    #[arg(long, value_name = "HOST:PORT")]
    entry: Option<String>,
}

impl RouteCmd {
    pub async fn exec(self) {
        let config = match ConnectionConfig::from_base64(&self.connection) {
            Ok(cfg) => cfg,
            Err(_) => match ConnectionConfig::load(&PathBuf::from(&self.connection)) {
                Ok(cfg) => cfg,
                Err(e) => {
                    success_err!("parse connection: {}", e);
                    process::exit(1);
                }
            },
        };

        let entry_addr = match &self.entry {
            Some(v) => match v.parse::<SocketAddr>() {
                Ok(a) => a,
                Err(e) => {
                    success_err!("invalid --entry address {}: {}", v, e);
                    process::exit(1);
                }
            },
            None => match config.general.host.parse::<IpAddr>() {
                Ok(ip) => SocketAddr::new(ip, config.general.port),
                Err(_) => {
                    success_err!("invalid host address: {}", config.general.host);
                    process::exit(1);
                }
            },
        };

        let runtime = config.runtime.clone().unwrap_or_default();
        let transport = match UdpTransport::new(entry_addr, runtime.so_rcvbuf, runtime.so_sndbuf) {
            Ok(t) => Arc::new(t),
            Err(e) => {
                success_err!("create transport: {}", e);
                process::exit(1);
            }
        };

        let target = config.credentials.server_public_key.clone();
        let cred = Cred {
            sk: config.credentials.private_key,
            psk: config.credentials.pre_shared_key,
            spk: config.credentials.server_public_key,
            enrollment: config.credentials.enrollment,
        };

        let (nodes, edges) = match fetch_topology(
            transport,
            &cred,
            &config.general.alg,
            Duration::from_millis(3000),
        )
        .await
        {
            Ok(t) => t,
            Err(e) => {
                success_err!("fetch topology: {}", e);
                process::exit(1);
            }
        };
        if nodes.is_empty() {
            success_ok!("Route", "registry is empty");
            return;
        }

        // First-hop weights only the client can measure (its own vantage point).
        let probed = probe_nodes(nodes.clone(), Duration::from_millis(1500)).await;
        let client_rtts: Vec<_> = probed
            .into_iter()
            .filter_map(|(node, rtt)| rtt.map(|d| (node.node_pk, d.as_micros().min(u32::MAX as u128) as u32)))
            .collect();

        let path = match plan_route(&nodes, &edges, &client_rtts, &target) {
            Some(p) => p,
            None => {
                success_err!("no route to target from this vantage point");
                process::exit(1);
            }
        };

        let label_of = |pk: &_| {
            nodes
                .iter()
                .find(|n| &n.node_pk == pk)
                .map(|n| if n.label.is_empty() { "-".to_string() } else { n.label.clone() })
                .unwrap_or_else(|| "?".to_string())
        };

        println!();
        if path.len() == 1 {
            success_ok!("Route", "direct to {} (no relay is faster)", label_of(&path[0]));
            println!();
            return;
        }

        let hops: Vec<String> = path.iter().map(|pk| label_of(pk)).collect();
        success_ok!("Route", "{}", hops.join(" -> "));

        // First hop is dialed (--via its endpoint); the rest are --hop <pubkey>,
        // except the final target which the connection already targets.
        let entry_node = nodes.iter().find(|n| n.node_pk == path[0]);
        if let Some(entry) = entry_node {
            let mid = &path[1..path.len() - 1];
            let hop_args: String = mid.iter().map(|pk| format!(" --hop {}", pk)).collect();
            success_ok!(
                "Connect",
                "connect <connection> --via {}{}",
                entry.endpoint,
                hop_args
            );
        }
        println!();
    }
}
