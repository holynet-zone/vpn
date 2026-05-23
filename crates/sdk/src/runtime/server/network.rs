use std::net::IpAddr;
use std::sync::Arc;

use etherparse::SlicedPacket;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tracing::error;
use tun_rs::AsyncDevice;

use super::session::HolyIp;

/// Returns the **destination** IP of the given IP packet.
/// Used to route TUN packets to the correct VPN session (the destination is the client's HolyIp).
pub fn parse_destination(packet: &[u8]) -> anyhow::Result<IpAddr> {
    match SlicedPacket::from_ip(packet) {
        Ok(sliced) => match sliced.net {
            Some(net) => match net {
                etherparse::InternetSlice::Ipv4(ipv4) => {
                    Ok(ipv4.header().destination_addr().into())
                }
                etherparse::InternetSlice::Ipv6(_) => {
                    Err(anyhow::anyhow!("IPv6 is not supported"))
                }
                etherparse::InternetSlice::Arp(_) => {
                    Err(anyhow::anyhow!("ARP is not supported"))
                }
            },
            None => Err(anyhow::anyhow!("missing network layer")),
        },
        Err(error) => Err(anyhow::Error::from(error)),
    }
}

pub async fn tun_sender(
    mut stop: watch::Receiver<bool>,
    tun: Arc<AsyncDevice>,
    mut out_tun_rx: mpsc::Receiver<Vec<u8>>,
) {
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            result = out_tun_rx.recv() => match result {
                Some(data) => {
                    if let Err(e) = tun.send(&data).await {
                        error!("failed to send data to tun: {}", e);
                    }
                }
                None => break,
            }
        }
    }
}

pub async fn tun_listener(
    mut stop: watch::Receiver<bool>,
    tun: Arc<AsyncDevice>,
    data_tun_tx: mpsc::Sender<(Vec<u8>, HolyIp)>,
) {
    let mut buffer = [0u8; 65536];
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            result = tun.recv(&mut buffer) => match result {
                Ok(len) => match parse_destination(&buffer[..len]) {
                    Ok(ip) => {
                        if let Err(e) = data_tun_tx.send((buffer[..len].to_vec(), ip)).await {
                            error!("failed to forward tun packet: {}", e);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("failed to parse tun packet: {}", e);
                    }
                },
                Err(e) => {
                    error!("tun recv error: {}", e);
                }
            }
        }
    }
}
