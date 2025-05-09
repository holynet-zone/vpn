use std::io;
use tun_rs::AsyncDevice;

pub async fn setup_tun<S: Into<String>>(name: S, mtu: u16, multiple: bool) -> io::Result<AsyncDevice> {
    let mut config = tun_rs::DeviceBuilder::default()
        .name(name)
        .mtu(mtu)
        .multi_queue(multiple)
        .tx_queue_len(10000)
        .enable(true);

    // ignore the head 4bytes packet information for calling `recv` and `send` on macOS
    if cfg!(target_os = "macos") {
        config = config.packet_information(false);
    }

    config.build_async()
}
