use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use tracing::info;
use tun::Device;
use serde::Deserialize;
use crate::exceptions::RuntimeExceptions;

pub fn set_ipv4_forwarding(value: bool) -> Result<(), RuntimeExceptions> {
    let sysctl_arg = if cfg!(target_os = "linux") {
        format!("net.ipv4.ip_forward={}", if value { 1 } else { 0 })
    } else if cfg!(target_os = "macos") {
        format!("net.inet.ip.forwarding={}", if value { 1 } else { 0 })
    } else {
        unimplemented!()
    };
    let status = Command::new("sysctl")
        .arg("-w")
        .arg(sysctl_arg)
        .status();
    match status {
        Ok(_) => {
            info!("Ipv4 forwarding is {}", if value { "enabled" } else { "disabled" });
            Ok(())
        },
        Err(error) => Err(RuntimeExceptions::TunError(format!("Failed to set ipv4 forwarding: {}", error)))
    }
}

pub fn setup_tun(name: &str, mtu: &u16, ip: &IpAddr, prefix: &u8) -> Result<Device, RuntimeExceptions> {
    let mut config = tun::Configuration::default();
    config.tun_name(name);
    config.address(ip);
    config.netmask(prefix_to_address(prefix));
    config.mtu(mtu.clone());
    config.up();

    let tun_device = tun::create(&config).map_err(|error| {
        RuntimeExceptions::TunError(format!("Failed to create the TUN device: {}", error))
    })?;
    info!("TUN device {} is up", name);
    Ok(tun_device)
}

pub fn down_tun(name: &str) -> Result<(), RuntimeExceptions> {
    let output = Command::new("sudo")
        .arg("ip")
        .arg("link")
        .arg("delete")
        .arg(name)
        .output()
        .map_err(|error| {
            RuntimeExceptions::TunError(format!("Failed to execute command to delete TUN interface: {}", error))
        })?;
    if output.status.success() {
        info!("TUN interface {} is down", name);
        Ok(())
    } else {
        Err(RuntimeExceptions::TunError(format!("Failed to delete TUN interface: {}", String::from_utf8_lossy(&output.stderr))))
    }
}

#[derive(Debug, Deserialize)]
pub enum TunState {
    Up,
    Down,
    Unknown,
}

#[derive(Deserialize)]
struct TunStatusRaw {
    pub ifname: String,
    pub operstate: TunState,
    pub mtu: usize,
    pub addr_info: Option<AddrInfoRaw>,
}


#[derive(Deserialize)]
struct AddrInfoRaw {
    pub local: String,
    pub prefixlen: u8
}

pub struct TunStatus {
    pub name: String,
    pub state: TunState,
    pub mtu: usize,
    pub ip: String,
    pub netmask: String,
}

pub fn tun_status(name: &str) -> Result<TunStatus, String> {
    let output = Command::new("ip")
        .arg("-j")
        .arg("a")
        .arg("show")
        .arg(name)
        .output()
        .map_err(|error| {
            format!("Failed to execute command to show TUN interface status: {}", error)
        })?;
    if output.status.success() {
        let raw: TunStatusRaw = serde_json::from_slice(&output.stdout).map_err(|error| {
            format!("Failed to parse TUN interface status: {}", error)
        })?;
        Ok(TunStatus {
            name: raw.ifname,
            state: raw.operstate,
            mtu: raw.mtu,
            ip: raw.addr_info.as_ref().map_or("none".to_string(), |addr| addr.local.clone()),
            netmask: raw.addr_info.as_ref().map_or(
                "none".to_string(),
                |addr|prefix_to_address(&addr.prefixlen).to_string()
            )
        })
    } else {
        Err(format!("Failed to show TUN interface status: {}", String::from_utf8_lossy(&output.stderr)))
    }
}


fn prefix_to_address(prefix: &u8) -> Ipv4Addr {
    let mask = (0xffffffffu32 as i32) << (32 - prefix) as i32;
    Ipv4Addr::new(
        (mask >> 24) as u8,
        (mask >> 16) as u8,
        (mask >> 8) as u8,
        mask as u8
    )
}