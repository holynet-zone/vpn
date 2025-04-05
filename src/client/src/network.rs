use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use log::{info, warn};
use std::process::Command;
use pnet::datalink;

pub fn enable_ipv4_forwarding() -> Result<(), String> {
    let sysctl_arg = if cfg!(target_os = "linux") {
        "net.ipv4.ip_forward=1"
    } else if cfg!(target_os = "macos") {
        "net.inet.ip.forwarding=1"
    } else {
        unimplemented!()
    };
    info!("Enabling IPv4 Forwarding.");
    let status = Command::new("sysctl")
        .arg("-w")
        .arg(sysctl_arg)
        .status()
        .unwrap();
    if status.success() {
        Ok(())
    } else {
        Err(format!("sysctl: {}", status))
    }
}

pub enum RouteType {
    Net,
    Host,
}

pub struct DefaultGateway {
    origin: String,
    remote: String,
    default: bool,
}

impl DefaultGateway {
    pub fn create(gateway: &IpAddr, remote: &str, default: bool) -> DefaultGateway {
        let origin = get_default_gateway().unwrap();
        info!("Original default gateway: {}.", origin);
        add_route(RouteType::Host, remote, &origin).unwrap();
        if default {
            delete_default_gateway().unwrap();
            set_default_gateway(&gateway.to_string()).unwrap();
        }
        DefaultGateway {
            origin: origin,
            remote: String::from(remote),
            default: default,
        }
    }

    pub fn delete(&mut self) {
        if self.default {
            delete_default_gateway().unwrap();
            set_default_gateway(&self.origin).unwrap();
        }
        delete_route(RouteType::Host, &self.remote).unwrap();
    }
}

impl Drop for DefaultGateway {
    fn drop(&mut self) {
        self.delete();
    }
}

pub fn delete_route(route_type: RouteType, route: &str) -> Result<(), String> {
    let mode = match route_type {
        RouteType::Net => "-net",
        RouteType::Host => "-host",
    };
    info!("Deleting route: {} {}.", mode, route);
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
    if status.success() {
        Ok(())
    } else {
        Err(format!("route: {}", status))
    }
}

pub fn add_route(route_type: RouteType, route: &str, gateway: &str) -> Result<(), String> {
    let mode = match route_type {
        RouteType::Net => "-net",
        RouteType::Host => "-host",
    };
    info!("Adding route: {} {} gateway {}.", mode, route, gateway);
    let status = if cfg!(target_os = "linux") {
        let check = Command::new("ip")
            .arg("route")
            .arg("show")
            .arg(route)
            .output()
            .unwrap();

        if !check.stdout.is_empty() {
            warn!("Route already exists");
            return Ok(());
        }

        Command::new("ip")
            .arg("route")
            .arg("add")
            .arg(route)
            .arg("via")
            .arg(gateway)
            .status()
            .unwrap()
    } else if cfg!(target_os = "macos") {
        Command::new("route")
            .arg("-n")
            .arg("add")
            .arg(mode)
            .arg(route)
            .arg(gateway)
            .status()
            .unwrap()
    } else {
        unimplemented!("Unsupported OS");
    };
    if status.success() {
        Ok(())
    } else {
        Err(format!("route: {}", status))
    }
}

pub fn set_default_gateway(gateway: &str) -> Result<(), String> {
    add_route(RouteType::Net, "default", gateway)
}

pub fn delete_default_gateway() -> Result<(), String> {
    delete_route(RouteType::Net, "default")
}

pub fn get_default_gateway() -> Result<String, String> {
    let cmd = if cfg!(target_os = "linux") {
        "ip -4 route list 0/0 | awk '{print $3}'"
    } else if cfg!(target_os = "macos") {
        "route -n get default | grep gateway | awk '{print $2}'"
    } else {
        unimplemented!()
    };
    let output = Command::new("bash").arg("-c").arg(cmd).output().unwrap();
    if output.status.success() {
        Ok(String::from_utf8(output.stdout)
            .unwrap()
            .trim_end()
            .to_string())
    } else {
        Err(String::from_utf8(output.stderr).unwrap())
    }
}

pub fn get_public_ip() -> Result<String, String> {
    let output = Command::new("curl")
        .arg("ipecho.net/plain")
        .output()
        .unwrap();
    if output.status.success() {
        Ok(String::from_utf8(output.stdout).unwrap())
    } else {
        Err(String::from_utf8(output.stderr).unwrap())
    }
}

fn get_route_gateway(route: &str) -> Result<String, String> {
    let cmd = format!("ip -4 route list {}", route);
    let output = Command::new("bash").arg("-c").arg(cmd).output().unwrap();
    if output.status.success() {
        Ok(String::from_utf8(output.stdout)
            .unwrap()
            .trim_end()
            .to_string())
    } else {
        Err(String::from_utf8(output.stderr).unwrap())
    }
}

pub fn set_dns(dns: &str) -> Result<String, String> {
    let cmd = format!("echo nameserver {} > /etc/resolv.conf", dns);
    let output = Command::new("bash").arg("-c").arg(cmd).output().unwrap();
    if output.status.success() {
        Ok(String::from_utf8(output.stdout).unwrap())
    } else {
        Err(String::from_utf8(output.stderr).unwrap())
    }
}

pub fn find_available_ifname(base_name: &str) -> String {
    let interfaces = datalink::interfaces();

    let existing_names: HashSet<String> = interfaces
        .into_iter()
        .map(|iface| iface.name)
        .collect();

    let mut index = 0;
    loop {
        let candidate = format!("{}{}", base_name, index);
        if !existing_names.contains(&candidate) {
            return candidate;
        }

        index += 1;
    }
}