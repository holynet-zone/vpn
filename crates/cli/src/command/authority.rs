use crate::style::format_opaque_bytes;
use crate::{success_err, success_ok};
use clap::{Args, Subcommand};
use holynet_sdk::crypto::PublicKey;
use holynet_sdk::identity::AccountKey;
use holynet_sdk::protocol::NodeEntry;
use holynet_sdk::registry::NodeRecord;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process;

#[derive(Debug, Subcommand)]
pub enum AuthorityCmd {
    /// Generate a network authority key (keep the private file safe)
    Init(InitCmd),
    /// Sign a node record for distribution to nodes
    Sign(SignCmd),
}

impl AuthorityCmd {
    pub async fn exec(self) {
        match self {
            AuthorityCmd::Init(cmd) => cmd.exec(),
            AuthorityCmd::Sign(cmd) => cmd.exec(),
        }
    }
}

#[derive(Debug, Args)]
pub struct InitCmd {
    /// Where to write the authority private key
    #[arg(long, default_value = "authority.key")]
    out: PathBuf,
}

impl InitCmd {
    fn exec(self) {
        if self.out.exists() {
            success_err!("refusing to overwrite existing {}", self.out.display());
            process::exit(1);
        }
        let key = AccountKey::generate();
        if let Err(e) = std::fs::write(&self.out, key.to_string()) {
            success_err!("write authority key: {}", e);
            process::exit(1);
        }
        println!();
        success_ok!("Authority", key.public());
        success_ok!(
            "PrivateKey",
            "{} ({})",
            self.out.display(),
            format_opaque_bytes(key.as_bytes())
        );
        success_ok!(
            "Config",
            "put the Authority public key into each node's config general.authority"
        );
        println!();
    }
}

#[derive(Debug, Args)]
pub struct SignCmd {
    /// Node's public key (base64), from `holynet server pubkey`
    #[arg(long)]
    node_pk: String,
    /// Reachable UDP endpoint clients dial, host:port
    #[arg(long)]
    endpoint: String,
    /// Base address of the subnet the node owns
    #[arg(long)]
    subnet: IpAddr,
    /// Prefix length of the owned subnet
    #[arg(long)]
    prefix: u8,
    /// Human label (continent / site)
    #[arg(long, default_value = "")]
    label: String,
    /// Emit a revocation tombstone instead of an active record
    #[arg(long)]
    revoke: bool,
    /// LWW version; higher supersedes. Defaults to current unix millis
    #[arg(long)]
    version: Option<u64>,
    /// Authority private key file
    #[arg(long, default_value = "authority.key")]
    key: PathBuf,
}

impl SignCmd {
    fn exec(self) {
        let authority = match std::fs::read_to_string(&self.key) {
            Ok(s) => match AccountKey::try_from(s.as_str()) {
                Ok(k) => k,
                Err(e) => {
                    success_err!("parse authority key: {}", e);
                    process::exit(1);
                }
            },
            Err(e) => {
                success_err!("read authority key {}: {}", self.key.display(), e);
                process::exit(1);
            }
        };

        let node_pk = match PublicKey::try_from(self.node_pk.as_str()) {
            Ok(pk) => pk,
            Err(e) => {
                success_err!("parse node pubkey: {}", e);
                process::exit(1);
            }
        };
        let endpoint = match self.endpoint.parse::<SocketAddr>() {
            Ok(a) => a,
            Err(e) => {
                success_err!("parse endpoint {}: {}", self.endpoint, e);
                process::exit(1);
            }
        };

        let entry = NodeEntry {
            node_pk,
            endpoint,
            subnet: self.subnet,
            prefix: self.prefix,
            label: self.label,
        };
        let version = self.version.unwrap_or_else(now_millis);
        let record = NodeRecord::sign(&authority, entry, version, self.revoke);

        println!();
        success_ok!(
            "Node",
            "{:.8}  {}",
            record.node_pk().to_string(),
            record.entry.endpoint
        );
        success_ok!("Version", version);
        if self.revoke {
            success_ok!("Revoke", "tombstone record");
        }
        success_ok!("Record", "{}", record.to_base64());
        success_ok!(
            "Import",
            "on the node: holynet server nodes import <Record>"
        );
        println!();
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
