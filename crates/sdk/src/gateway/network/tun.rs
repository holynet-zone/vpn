use crate::gateway::network::{GroState, Network, NetworkReceiver, NetworkSender};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tun_rs::AsyncDevice;

#[derive(Clone)]
pub struct TunNetwork {
    device: Arc<AsyncDevice>,
    mtu: u16,
    offload: bool,
}

impl TunNetwork {
    pub async fn new<S: Into<String>>(
        name: S,
        mtu: u16,
        multi_queue: bool,
        ip: Option<(IpAddr, u8)>,
        offload: bool,
    ) -> io::Result<Self> {
        // tun-rs silently falls back to per-packet if the kernel rejects
        // TUNSETOFFLOAD, so a buggy NIC degrades gracefully on its own.
        let mut config = tun_rs::DeviceBuilder::default()
            .name(name)
            .mtu(mtu)
            .multi_queue(multi_queue)
            .offload(offload)
            .tx_queue_len(10000)
            .enable(true);

        if cfg!(target_os = "macos") {
            config = config.packet_information(false);
        }

        let device = config.build_async()?;

        if let Some((addr, prefix)) = ip {
            match addr {
                IpAddr::V4(v4) => device.set_network_address(v4, prefix, None)?,
                IpAddr::V6(v6) => device.add_address_v6(v6, prefix)?,
            }
        }

        Ok(Self {
            device: Arc::new(device),
            mtu,
            offload,
        })
    }

    pub fn configure_ip(&self, ip: IpAddr, prefix: u8) -> io::Result<()> {
        match ip {
            IpAddr::V4(v4) => self.device.set_network_address(v4, prefix, None),
            IpAddr::V6(v6) => self.device.add_address_v6(v6, prefix),
        }
    }

    pub fn name(&self) -> io::Result<String> {
        self.device.name()
    }
}

impl NetworkSender for TunNetwork {
    async fn send_to(&self, data: &[u8], _addr: &SocketAddr) -> io::Result<usize> {
        self.device.send(data).await
    }

    async fn send(&self, data: &[u8]) -> io::Result<usize> {
        self.device.send(data).await
    }
}

impl NetworkReceiver for TunNetwork {
    async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let n = self.device.recv(buffer).await?;
        Ok((n, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
    }

    async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        self.device.recv(buffer).await
    }
}

impl Network for TunNetwork {
    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn offload_enabled(&self) -> bool {
        self.offload
    }

    /// Batched read via tun-rs `recv_multiple` (GRO split on Linux).
    #[cfg(target_os = "linux")]
    async fn recv_multiple(
        &self,
        orig: &mut [u8],
        bufs: &mut [Vec<u8>],
        sizes: &mut [usize],
        offset: usize,
    ) -> io::Result<usize> {
        self.device.recv_multiple(orig, bufs, sizes, offset).await
    }

    /// Batched write via tun-rs `send_multiple` (GRO merge on Linux).
    #[cfg(target_os = "linux")]
    async fn send_multiple(
        &self,
        gro: &mut GroState,
        bufs: &mut [Vec<u8>],
        offset: usize,
    ) -> io::Result<usize> {
        self.device.send_multiple(&mut gro.0, bufs, offset).await
    }
}
