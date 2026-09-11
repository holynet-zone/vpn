use crate::config::Config;
use crate::storage::{Nodes, database};
use crate::{success_err, success_ok};
use anyhow::anyhow;
use clap::{Args, Subcommand};
use holynet_sdk::registry::NodeRecord;

#[derive(Debug, Subcommand)]
pub enum NodesCmd {
    /// Import an authority-signed node record (base64) into the registry
    Import(ImportCmd),
    /// List stored node records
    List(ListCmd),
}

impl NodesCmd {
    pub async fn exec(self, config: Config) {
        if let Err(e) = match self {
            NodesCmd::Import(cmd) => cmd.exec(config).await,
            NodesCmd::List(cmd) => cmd.exec(config).await,
        } {
            success_err!("{}", e);
            std::process::exit(1);
        }
    }
}

#[derive(Debug, Args)]
pub struct ImportCmd {
    /// Base64 node record from `holynet authority sign`
    #[arg(value_name = "RECORD")]
    record: String,
}

impl ImportCmd {
    async fn exec(self, config: Config) -> anyhow::Result<()> {
        let trusted = config
            .general
            .authority
            .ok_or_else(|| anyhow!("no authority configured (set general.authority)"))?;

        let record =
            NodeRecord::from_base64(&self.record).map_err(|e| anyhow!("parse record: {}", e))?;

        if record.authority != trusted {
            return Err(anyhow!(
                "record authority does not match configured authority"
            ));
        }
        if !record.verify() {
            return Err(anyhow!("record signature is invalid"));
        }

        let nodes = Nodes::new(database(&config.general.storage)?)?;
        nodes.save(record.clone()).await;

        let kind = if record.revoked {
            "revocation"
        } else {
            "record"
        };
        success_ok!(
            "Imported",
            "{} {:.8} {} v{}",
            kind,
            record.node_pk().to_string(),
            record.entry.endpoint,
            record.version
        );
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct ListCmd;

impl ListCmd {
    async fn exec(self, config: Config) -> anyhow::Result<()> {
        let nodes = Nodes::new(database(&config.general.storage)?)?;
        let records = nodes.get_all().await;
        if records.is_empty() {
            success_ok!("Nodes", "registry is empty");
            return Ok(());
        }
        println!();
        for r in records {
            let label = if r.entry.label.is_empty() {
                "-".to_string()
            } else {
                r.entry.label.clone()
            };
            let state = if r.revoked { "revoked" } else { "active" };
            success_ok!(
                "Node",
                "{}  {}  {}/{}  v{}  {}  {:.8}",
                label,
                r.entry.endpoint,
                r.entry.subnet,
                r.entry.prefix,
                r.version,
                state,
                r.node_pk().to_string()
            );
        }
        println!();
        Ok(())
    }
}
