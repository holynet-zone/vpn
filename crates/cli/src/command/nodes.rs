use crate::config::connection::ConnectionConfig;
use crate::success_err;
use crate::success_ok;
use clap::Args;
use holynet_sdk::gateway::transport::udp::UdpTransport;
use holynet_sdk::runtime::client::fetch_node_list;
use holynet_sdk::runtime::cred::Cred;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Args)]
pub struct NodesCmd {
    /// Connection config file path, or base64-encoded connection key
    #[arg(value_name = "CONNECTION")]
    connection: String,
}

impl NodesCmd {
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

        let server_addr = match config.general.host.parse::<IpAddr>() {
            Ok(ip) => SocketAddr::new(ip, config.general.port),
            Err(_) => {
                success_err!("invalid host address: {}", config.general.host);
                process::exit(1);
            }
        };

        let runtime = config.runtime.clone().unwrap_or_default();
        let transport = match UdpTransport::new(server_addr, runtime.so_rcvbuf, runtime.so_sndbuf) {
            Ok(t) => Arc::new(t),
            Err(e) => {
                success_err!("create transport: {}", e);
                process::exit(1);
            }
        };

        let cred = Cred {
            sk: config.credentials.private_key,
            psk: config.credentials.pre_shared_key,
            spk: config.credentials.server_public_key,
            enrollment: config.credentials.enrollment,
        };

        let nodes = match fetch_node_list(
            transport,
            &cred,
            &config.general.alg,
            Duration::from_millis(3000),
        )
        .await
        {
            Ok(nodes) => nodes,
            Err(e) => {
                success_err!("fetch node list: {}", e);
                process::exit(1);
            }
        };

        if nodes.is_empty() {
            success_ok!("Nodes", "registry is empty");
            return;
        }
        println!();
        for node in nodes {
            let label = if node.label.is_empty() {
                "-".to_string()
            } else {
                node.label
            };
            success_ok!(
                "Node",
                "{}  {}  {}/{}  {:.8}",
                label,
                node.endpoint,
                node.subnet,
                node.prefix,
                node.node_pk.to_string()
            );
        }
        println!();
    }
}
