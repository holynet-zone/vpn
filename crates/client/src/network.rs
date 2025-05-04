use std::net::{IpAddr};
use tracing::{info, warn};
use std::process::Command;
use anyhow::format_err;
use std::fmt::Write;
use std::str::FromStr;

pub struct RouteState {
    dev: String,
    default_gateway: Option<IpAddr>,
    exclude: Vec<IpNetwork>,
}
use ipnetwork::{IpNetwork, NetworkSize};

impl RouteState {
    pub fn new(remote: IpAddr, dev: String) -> Self {
        Self {
            dev,
            default_gateway: None,
            exclude: vec![IpNetwork::from(remote)]
        }
    }

    pub fn exclude(mut self, addr: IpNetwork) {
        self.exclude.push(addr);
    }

    pub fn build(mut self) -> anyhow::Result<RouteState> {
        let (default_gateway, default_dev_name) = default_device().map_err(|e| 
            format_err!("failed to get default device: {}", e)
        )?;
        self.default_gateway = Some(default_gateway);
        info!("default gateway: {} from dev {}", default_gateway, default_dev_name);
        add_route(
            &IpNetwork::from_str("0.0.0.0/1")?,
            None,
            &self.dev,
            Some(1),
        )?;
        add_route(
            &IpNetwork::from_str("128.0.0.0/1")?,
            None,
            &self.dev,
            Some(1),
        )?;
        
        for addr in self.exclude.iter() {
            add_route(
                addr,
                Some(default_gateway),
                &default_dev_name,
                None
            )?;
        }
        
        Ok(self)
    }

    pub fn restore(&mut self) {
        for addr in self.exclude.iter() {
            match delete_route(
                addr,
                &self.default_gateway.expect(
                    "default gateway not set, cannot restore route (are you sure you called build?)"
                ),
            ) {
                Ok(_) => {},
                Err(e) => warn!("failed to restore route: {} via {}: {}", addr, self.default_gateway.unwrap(), e),
            }
        }
    }
}

// impl Drop for DefaultGateway {
//     fn drop(&mut self) {
//         self.restore();
//     }
// }

pub fn delete_route(route: &IpNetwork, via: &IpAddr,) -> anyhow::Result<()> {
    info!("deleting route: {} via {}", route, via);
    
    let (formated_route, _) = match route.size() {
        NetworkSize::V4(32) | NetworkSize::V6(128) => (route.ip().to_string(), false),
        _ => (route.to_string(), true),
    };

    let status = if cfg!(target_os = "linux") {
        let check = Command::new("ip")
            .arg("route")
            .arg("show")
            .arg(formated_route.clone())
            .output()?;

        if check.stdout.is_empty() {
            warn!("route already deleted");
            return Ok(());
        }

        Command::new("ip")
            .arg("route")
            .arg("del")
            .arg(formated_route)
            .arg("via")
            .arg(via.to_string())
            .status()?
    } else {
        unimplemented!("Unsupported OS");
    };
    if !status.success() {
        warn!("cant delete route: {}", status);
    }
    Ok(())
}


fn add_route(route: &IpNetwork, via: Option<IpAddr>, dev: &str, metric: Option<usize>) -> anyhow::Result<()> {
    let mut buffer = format!("adding route: {} ", route);
    if let Some(via) = via {
        write!(buffer, "via {} ", via)?;
    }
    write!(buffer, "dev {} ", dev)?;
    if let Some(metric) = metric {
        write!(buffer, "metric {}", metric)?;
    }
    info!("{}", buffer);

    let (formated_route, _) = match route.size() {
        NetworkSize::V4(32) | NetworkSize::V6(128) => (route.ip().to_string(), false),
        _ => (route.to_string(), true),
    };

    let status = if cfg!(target_os = "linux") {
        let check = Command::new("ip")
            .arg("route")
            .arg("show")
            .arg(formated_route.clone())
            .output()?;

        if !check.stdout.is_empty() {
            warn!("route already exists");
            return Ok(());
        }

        let mut cmd = Command::new("ip");

        cmd.arg("route").arg("add").arg(formated_route);

        if let Some(via) = via {
            cmd.arg("via").arg(via.to_string());
        };

        cmd.arg("dev").arg(dev);

        if let Some(metric) = metric {
            cmd.arg("metric").arg(metric.to_string());
        };

        cmd.status()?
    // } else if cfg!(target_os = "macos") {
    //
    //     Command::new("route")
    //         .arg("-n")
    //         .arg("add")
    //         .arg(if is_net { "-net" } else { "-host" })
    //         .arg(formated_route)
    //         .arg(gateway)
    //         .status()?
    } else {
        unimplemented!("Unsupported OS");
    };
    if !status.success() {
        Err(anyhow::anyhow!("failed to add route: {}", status))
    } else {
        Ok(())
    }
}

pub fn default_device() -> anyhow::Result<(IpAddr, String)> {
    let cmd = if cfg!(target_os = "linux") {
        "ip -4 route list 0/0"
    } else if cfg!(target_os = "macos") {
        "route -n get default"
    } else {
        unimplemented!("Unsupported OS");
    };

    let output = Command::new("bash").arg("-c").arg(cmd).output()?;

    if output.status.success() {
        let output_str = String::from_utf8(output.stdout)?;
        
        if cfg!(target_os = "linux") {
            for line in output_str.lines() {
                if line.contains("default") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let ip: IpAddr = parts[2].parse()?;
                        let interface = parts[4].to_string();
                        return Ok((ip, interface));
                    }
                }
            }
        }

        // if cfg!(target_os = "macos") {
        //     for line in output_str.lines() {
        //         if line.contains("gateway") {
        //             let parts: Vec<&str> = line.split_whitespace().collect();
        //             if parts.len() >= 2 {
        //                 let ip: IpAddr = parts[1].parse()?;
        //                 return Ok((ip, String::from("unknown")));
        //             }
        //         }
        //     }
        // }

        Err(anyhow::anyhow!("Failed to parse output"))
    } else {
        Err(anyhow::anyhow!(String::from_utf8(output.stderr)?))
    }
}

// pub fn set_dns(dns: &str) -> Result<String, String> {
//     let cmd = format!("echo nameserver {} > /etc/resolv.conf", dns);
//     let output = Command::new("bash").arg("-c").arg(cmd).output().unwrap();
//     if output.status.success() {
//         Ok(String::from_utf8(output.stdout).unwrap())
//     } else {
//         Err(String::from_utf8(output.stderr).unwrap())
//     }
// }
