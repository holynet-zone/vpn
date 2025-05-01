use std::net::{IpAddr};
use tracing::{info, warn};
use std::process::Command;
use crate::runtime::error::RuntimeError;

pub enum RouteType {
    Net,
    Host,
}

pub struct DefaultGateway {
    origin: IpAddr,
    remote: IpAddr,
    default: bool,
}

impl DefaultGateway {
    pub fn create(new_gateway: &IpAddr, remote: &IpAddr, default: bool) -> Result<DefaultGateway, RuntimeError> {
        let origin = default_gateway()
            .map_err(|e| RuntimeError::Network(format!("getting default gateway: {}", e)))?;
        info!("original default gateway: {}.", origin);
        add_route(RouteType::Host, &remote.to_string(), &origin.to_string())
            .map_err(|error| RuntimeError::Network(format!(
                "failed to add route: {} -> {}: {}",
                remote, 
                origin, 
                error
            )))?;
        
        if default {
            delete_route(RouteType::Net, "default");
            add_route(RouteType::Net, "default", &new_gateway.to_string())
                .map_err(|error| RuntimeError::Network(format!(
                    "failed to add new default route: {} (new) -> {} (old): {}",
                    new_gateway, 
                    origin, 
                    error
                )))?;
        }
        
        Ok(DefaultGateway {
            origin,
            remote: *remote,
            default,
        })
    }

    pub fn restore(&mut self) {
        if self.default {
            delete_route(RouteType::Net, "default");
            if let Err(e) = add_route(RouteType::Net, "default", &self.origin.to_string()) {
                warn!("failed to restore default route: {}", e);
            } else {
                info!("restored default route: {}.", self.origin);
            }
        }
        delete_route(RouteType::Host, &self.remote.to_string());
    }
}

// impl Drop for DefaultGateway {
//     fn drop(&mut self) {
//         self.restore();
//     }
// }

pub fn delete_route(route_type: RouteType, route: &str) {
    let mode = match route_type {
        RouteType::Net => "-net",
        RouteType::Host => "-host",
    };
    info!("deleting route: {} {}.", mode, route);
    let status = if cfg!(target_os = "linux") {
        Command::new("ip")
            .arg("route")
            .arg("del")
            .arg(route)
            .status()
            .unwrap()
    } else if cfg!(target_os = "macos") {
        Command::new("route")
            .arg("-n")
            .arg("delete")
            .arg(mode)
            .arg(route)
            .status()
            .unwrap()
    } else {
        unimplemented!("Unsupported OS");
    };
    if !status.success() {
        warn!("failed to delete route: {}", status);
    }
}

pub fn add_route(route_type: RouteType, route: &str, gateway: &str) -> anyhow::Result<()> {
    let mode = match route_type {
        RouteType::Net => "-net",
        RouteType::Host => "-host",
    };
    info!("adding route: {} {} gateway {}.", mode, route, gateway);
    let status = if cfg!(target_os = "linux") {
        let check = Command::new("ip")
            .arg("route")
            .arg("show")
            .arg(route)
            .output()?;

        if !check.stdout.is_empty() {
            warn!("route already exists");
            return Ok(());
        }

        Command::new("ip")
            .arg("route")
            .arg("add")
            .arg(route)
            .arg("via")
            .arg(gateway)
            .status()?
    } else if cfg!(target_os = "macos") {
        Command::new("route")
            .arg("-n")
            .arg("add")
            .arg(mode)
            .arg(route)
            .arg(gateway)
            .status()?
    } else {
        unimplemented!("Unsupported OS");
    };
    if !status.success() {
        Err(anyhow::anyhow!("failed to add route: {}", status))
    } else {
        Ok(())
    }
}

pub fn default_gateway() -> anyhow::Result<IpAddr> {
    let cmd = if cfg!(target_os = "linux") {
        "ip -4 route list 0/0 | awk '{print $3}'"
    } else if cfg!(target_os = "macos") {
        "route -n get default | grep gateway | awk '{print $2}'"
    } else {
        unimplemented!("Unsupported OS");
    };
    let output = Command::new("bash").arg("-c").arg(cmd).output()?;
    if output.status.success() {
        Ok(String::from_utf8(output.stdout)?.trim_end().parse()?)
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
