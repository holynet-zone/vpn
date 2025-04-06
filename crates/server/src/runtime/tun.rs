use std::net::{IpAddr};
use tun_rs::AsyncDevice;
use crate::runtime::error::RuntimeError;

pub async fn setup_tun(name: &str, mtu: &u16, ip: &IpAddr, prefix: &u8) -> Result<AsyncDevice, RuntimeError> {
    let mut config = tun_rs::Configuration::default();
    config.name(name);
    config.address_with_prefix(ip, *prefix);
    config.mtu(mtu.clone());
    config.up();
    let dev = tun_rs::create_as_async(&config).map_err(|error| {  // todo: requires async runtime
        RuntimeError::Tun(format!("failed to create the TUN device: {}", error))
    })?;

    // ignore the head 4bytes packet information for calling `recv` and `send` on macOS
    #[cfg(target_os = "macos")]
    dev.set_ignore_packet_info(true);
    
    Ok(dev)
}

// pub fn down_tun(name: &str) -> Result<(), RuntimeError> {
//     let output = Command::new("sudo")
//         .arg("ip")
//         .arg("link")
//         .arg("delete")
//         .arg(name)
//         .output()
//         .map_err(|error| {
//             RuntimeError::Tun(format!("failed to execute command to delete TUN interface: {}", error))
//         })?;
//     if output.status.success() {
//         info!("TUN interface {} is down", name);
//         Ok(())
//     } else {
//         Err(RuntimeError::Tun(format!("failed to delete TUN interface: {}", String::from_utf8_lossy(&output.stderr))))
//     }
// }
// 
// #[derive(Debug, Deserialize)]
// pub enum TunState {
//     Up,
//     Down,
//     Unknown,
// }
// 
// #[derive(Deserialize)]
// struct TunStatusRaw {
//     pub ifname: String,
//     pub operstate: TunState,
//     pub mtu: usize,
//     pub addr_info: Option<AddrInfoRaw>,
// }
// 
// 
// #[derive(Deserialize)]
// struct AddrInfoRaw {
//     pub local: String,
//     pub prefixlen: u8
// }
// 
// pub struct TunStatus {
//     pub name: String,
//     pub state: TunState,
//     pub mtu: usize,
//     pub ip: String,
//     pub netmask: String,
// }
// 
// pub fn tun_status(name: &str) -> Result<TunStatus, String> {
//     let output = Command::new("ip")
//         .arg("-j")
//         .arg("a")
//         .arg("show")
//         .arg(name)
//         .output()
//         .map_err(|error| {
//             format!("Failed to execute command to show TUN interface status: {}", error)
//         })?;
//     if output.status.success() {
//         let raw: TunStatusRaw = serde_json::from_slice(&output.stdout).map_err(|error| {
//             format!("Failed to parse TUN interface status: {}", error)
//         })?;
//         Ok(TunStatus {
//             name: raw.ifname,
//             state: raw.operstate,
//             mtu: raw.mtu,
//             ip: raw.addr_info.as_ref().map_or("none".to_string(), |addr| addr.local.clone()),
//             netmask: raw.addr_info.as_ref().map_or(
//                 "none".to_string(),
//                 |addr|prefix_to_address(&addr.prefixlen).to_string()
//             )
//         })
//     } else {
//         Err(format!("Failed to show TUN interface status: {}", String::from_utf8_lossy(&output.stderr)))
//     }
// }
// 
// 
// fn prefix_to_address(prefix: &u8) -> Ipv4Addr {
//     let mask = (0xffffffffu32 as i32) << (32 - prefix) as i32;
//     Ipv4Addr::new(
//         (mask >> 24) as u8,
//         (mask >> 16) as u8,
//         (mask >> 8) as u8,
//         mask as u8
//     )
// }