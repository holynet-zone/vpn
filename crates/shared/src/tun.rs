use std::io;
use std::net::IpAddr;
use tun_rs::AsyncDevice;

pub async fn setup_tun<S: Into<String>>(name: S, mtu: u16, ip: IpAddr, prefix: u8) -> io::Result<AsyncDevice> {
    let mut config = tun_rs::DeviceBuilder::default()
        .name(name)
        .mtu(mtu)
        .enable(true);

    // ignore the head 4bytes packet information for calling `recv` and `send` on macOS
    if cfg!(target_os = "macos") {
        config = config.packet_information(false);
    }

    match ip {
        IpAddr::V4(addr) => config.ipv4(addr, prefix, None),
        IpAddr::V6(addr) => config.ipv6(addr, prefix),
    }.build_async()
}
