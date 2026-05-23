use std::io;
use tun_rs::AsyncDevice;

pub async fn setup<S: Into<String>>(name: S, mtu: u16, multi_queue: bool) -> io::Result<AsyncDevice> {
    let mut config = tun_rs::DeviceBuilder::default()
        .name(name)
        .mtu(mtu)
        .multi_queue(multi_queue)
        .tx_queue_len(10000)
        .enable(true);

    if cfg!(target_os = "macos") {
        config = config.packet_information(false);
    }

    config.build_async()
}
