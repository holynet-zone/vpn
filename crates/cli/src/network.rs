use anyhow::format_err;
use ipnetwork::{IpNetwork, NetworkSize};
use std::fmt::Write;
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;
use tracing::{debug, info, warn};

pub struct RouteState {
    dev: String,
    default_gateway: Option<IpAddr>,
    exclude: Vec<IpNetwork>,
}

impl RouteState {
    pub fn new(remote: IpAddr, dev: String) -> Self {
        Self {
            dev,
            default_gateway: None,
            exclude: vec![IpNetwork::from(remote)],
        }
    }

    pub fn build(mut self) -> anyhow::Result<RouteState> {
        let (default_gateway, default_dev_name) = default_device()
            .map_err(|e| format_err!("failed to get default device: {}", e))?;
        self.default_gateway = Some(default_gateway);
        debug!("default gateway: {} from dev {}", default_gateway, default_dev_name);

        add_route(&IpNetwork::from_str("0.0.0.0/1")?, None, &self.dev, Some(1))?;
        add_route(&IpNetwork::from_str("128.0.0.0/1")?, None, &self.dev, Some(1))?;

        for addr in self.exclude.iter() {
            add_route(addr, Some(default_gateway), &default_dev_name, None)?;
        }

        Ok(self)
    }

    pub fn restore(&self) {
        for addr in self.exclude.iter() {
            let gw = self.default_gateway.expect("default_gateway not set");
            if let Err(e) = delete_route(addr, &gw) {
                warn!("failed to restore route {} via {}: {}", addr, gw, e);
            }
        }
    }
}

pub fn delete_route(route: &IpNetwork, via: &IpAddr) -> anyhow::Result<()> {
    info!("deleting route: {} via {}", route, via);
    let (formatted, _) = match route.size() {
        NetworkSize::V4(32) | NetworkSize::V6(128) => (route.ip().to_string(), false),
        _ => (route.to_string(), true),
    };

    if cfg!(target_os = "linux") {
        let check = Command::new("ip").args(["route", "show", &formatted]).output()?;
        if check.stdout.is_empty() {
            warn!("route already deleted");
            return Ok(());
        }
        let status = Command::new("ip")
            .args(["route", "del", &formatted, "via", &via.to_string()])
            .status()?;
        if !status.success() {
            warn!("cant delete route: {}", status);
        }
    } else {
        unimplemented!("Unsupported OS");
    }
    Ok(())
}

pub fn add_route(
    route: &IpNetwork,
    via: Option<IpAddr>,
    dev: &str,
    metric: Option<usize>,
) -> anyhow::Result<()> {
    let mut log = format!("adding route: {} ", route);
    if let Some(v) = via { write!(log, "via {} ", v)?; }
    write!(log, "dev {} ", dev)?;
    if let Some(m) = metric { write!(log, "metric {}", m)?; }
    info!("{}", log);

    let (formatted, _) = match route.size() {
        NetworkSize::V4(32) | NetworkSize::V6(128) => (route.ip().to_string(), false),
        _ => (route.to_string(), true),
    };

    if cfg!(target_os = "linux") {
        let check = Command::new("ip").args(["route", "show", &formatted]).output()?;
        if !check.stdout.is_empty() {
            warn!("route already exists");
            return Ok(());
        }
        let mut cmd = Command::new("ip");
        cmd.args(["route", "add", &formatted]);
        if let Some(v) = via { cmd.args(["via", &v.to_string()]); }
        cmd.args(["dev", dev]);
        if let Some(m) = metric { cmd.args(["metric", &m.to_string()]); }
        let status = cmd.status()?;
        if !status.success() {
            return Err(anyhow::anyhow!("failed to add route: {}", status));
        }
    } else {
        unimplemented!("Unsupported OS");
    }
    Ok(())
}

pub fn default_device() -> anyhow::Result<(IpAddr, String)> {
    let output = Command::new("bash")
        .args(["-c", "ip -4 route list 0/0"])
        .output()?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(String::from_utf8(output.stderr)?));
    }

    let out = String::from_utf8(output.stdout)?;
    for line in out.lines() {
        if line.contains("default") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                let ip: IpAddr = parts[2].parse()?;
                return Ok((ip, parts[4].to_string()));
            }
        }
    }
    Err(anyhow::anyhow!("Failed to parse default route"))
}
