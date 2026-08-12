//! Merged network-read + encrypt + UDP-send task (server side).
//!
//! ## Batched, zero-allocation hot path
//!
//! ```text
//! network.recv_multiple → up to TUN_BATCH_SIZE IP packets from one 64 KiB
//!                         GSO super-frame (TUN GRO split, one syscall)
//!   for each packet:
//!     → write_ip_packet_plain  — PLAIN_BUF (thread-local), Copy 1
//!     → noise write_message    — AEAD encrypt into encode_buf (stack), Copy 2
//!     → transport.send_to      — direct UDP write, no intermediate buffers
//! ```
//!
//! A single bulk TCP stream produces one destination client per batch, so the
//! 1-entry session cache turns the per-packet DashMap lookup into a pointer
//! compare.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::sync::watch;
use tracing::{debug, error, warn};

use super::session::{HolyIp, Session, Sessions};
use crate::gateway::network::{Network, TUN_BATCH_SIZE};
use crate::gateway::transport::Transport;
use crate::runtime::crypto::encode_data_server_packet;

/// Extract the destination IP address from a raw IP packet without parsing
/// all layers. Only IPv4 is supported; IPv6 returns an error.
///
/// IPv4 layout: version nibble at byte 0, destination addr at bytes 16–19.
/// Minimum valid IPv4 header is 20 bytes.
#[inline]
pub(super) fn parse_destination(packet: &[u8]) -> anyhow::Result<IpAddr> {
    let version = packet.first().map(|b| b >> 4);
    match version {
        Some(4) => {
            if packet.len() < 20 {
                return Err(anyhow::anyhow!(
                    "IPv4 packet too short: {} bytes",
                    packet.len()
                ));
            }
            Ok(Ipv4Addr::from([packet[16], packet[17], packet[18], packet[19]]).into())
        }
        Some(6) => Err(anyhow::anyhow!("IPv6 is not supported")),
        Some(v) => Err(anyhow::anyhow!("unknown IP version: {}", v)),
        None => Err(anyhow::anyhow!("empty packet")),
    }
}

fn ip_to_holy(ip: IpAddr) -> HolyIp {
    match ip {
        IpAddr::V4(v4) => HolyIp::V4(v4),
        IpAddr::V6(v6) => HolyIp::V6(v6),
    }
}

/// Combined network-read → encrypt → UDP-send task.
///
/// Reads raw IP packets from the network, looks up the destination session,
/// encrypts the payload, encodes the `Packet`, and sends it directly via the
/// transport. No intermediate channels or heap allocations in steady state.
pub(super) async fn encrypt_forward<T: Transport, N: Network>(
    mut stop: watch::Receiver<bool>,
    network: Arc<N>,
    transport: Arc<T>,
    sessions: Sessions,
) {
    // Batched TUN read buffers (reused each iteration — zero alloc in steady state).
    let mut orig = vec![0u8; 10 + 65535]; // raw GSO super-frame + virtio hdr
    let seg = network.mtu() as usize + 128;
    let mut bufs: Vec<Vec<u8>> = (0..TUN_BATCH_SIZE).map(|_| vec![0u8; seg]).collect();
    let mut sizes = vec![0usize; TUN_BATCH_SIZE];
    let mut encode_buf = [0u8; 65600];
    // Per-task 1-entry destination cache: batch of a bulk stream shares one client.
    let mut cached: Option<(HolyIp, Arc<Session>)> = None;

    loop {
        tokio::select! {
            _ = stop.changed() => break,
            result = network.recv_multiple(&mut orig, &mut bufs, &mut sizes, 0) => match result {
                Err(e) => error!("network recv error: {}", e),
                Ok(count) => {
                    for i in 0..count {
                        let pkt = &bufs[i][..sizes[i]];
                        let ip = match parse_destination(pkt) {
                            Err(e) => {
                                warn!("failed to parse network packet destination: {}", e);
                                continue;
                            }
                            Ok(ip) => ip,
                        };
                        let holy_ip = ip_to_holy(ip);
                        let session = match &cached {
                            Some((cip, s)) if *cip == holy_ip => s.clone(),
                            _ => {
                                let Some(s) = sessions.get_by_holy_ip(&holy_ip) else {
                                    warn!("[{}] no session for network packet destination", ip);
                                    continue;
                                };
                                cached = Some((holy_ip, s.clone()));
                                s
                            }
                        };
                        let send_nonce = session.send_nonce.fetch_add(1, Ordering::Relaxed);
                        match encode_data_server_packet(pkt, &session.state, send_nonce, &mut encode_buf) {
                            Err(e) => warn!("[{}] encrypt failed (sid {}): {}", ip, session.id, e),
                            Ok(n) => {
                                let addr = session.sock_addr();
                                if let Err(e) = transport.send_to(&encode_buf[..n], &addr).await {
                                    error!("[{}] UDP send failed: {}", addr, e);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    debug!("encrypt_forward stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet(dst: [u8; 4]) -> Vec<u8> {
        // Minimal IPv4 header: 20 bytes. Version=4, IHL=5.
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45; // version=4, IHL=5
        pkt[16..20].copy_from_slice(&dst);
        pkt
    }

    #[test]
    fn test_ipv4_dst_parsed() {
        let pkt = ipv4_packet([10, 0, 0, 1]);
        let ip = parse_destination(&pkt).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_ipv4_dst_with_payload() {
        let mut pkt = ipv4_packet([192, 168, 1, 100]);
        pkt.extend_from_slice(&[0u8; 100]); // simulate payload
        let ip = parse_destination(&pkt).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
    }

    #[test]
    fn test_ipv4_too_short_errors() {
        let pkt = vec![0x45u8; 19]; // version=4, but only 19 bytes
        assert!(parse_destination(&pkt).is_err());
    }

    #[test]
    fn test_ipv6_returns_error() {
        let mut pkt = vec![0u8; 40]; // IPv6 header is 40 bytes
        pkt[0] = 0x60; // version=6
        assert!(parse_destination(&pkt).is_err());
    }

    #[test]
    fn test_empty_packet_errors() {
        assert!(parse_destination(&[]).is_err());
    }

    #[test]
    fn test_unknown_version_errors() {
        let pkt = vec![0x50u8; 20]; // version=5 (reserved)
        assert!(parse_destination(&pkt).is_err());
    }
}
