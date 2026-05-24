//! Merged TUN-read + encrypt + UDP-send task (server side).
//!
//! Replaces the former `tun_listener` + `data_tun_executor` + `transport_sender` chain.
//!
//! ## Zero-allocation hot path
//!
//! ```text
//! TUN recv → stack buffer
//!   → BufPool::copy_to_bytes  — no alloc after warmup
//!   → noise_encrypt            — CIPHER_POOL, no alloc after warmup
//!   → encode_into_slice        — stack encode_buf, no alloc
//!   → transport.send_to        — direct UDP write
//! ```

use std::net::IpAddr;
use std::sync::Arc;

use etherparse::SlicedPacket;
use tokio::sync::watch;
use tracing::{debug, error, warn};
use tun_rs::AsyncDevice;

use super::session::{HolyIp, Sessions};
use crate::gateway::transport::Transport;
use crate::protocol::{DataServerBody, Packet};
use crate::runtime::buf_pool::BufPool;
use crate::runtime::crypto::noise_encrypt;

/// Parse the destination IP from a raw IP packet slice.
pub(super) fn parse_destination(packet: &[u8]) -> anyhow::Result<IpAddr> {
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
        Err(e) => Err(anyhow::Error::from(e)),
    }
}

fn ip_to_holy(ip: IpAddr) -> HolyIp {
    match ip {
        IpAddr::V4(v4) => HolyIp::V4(v4),
        IpAddr::V6(v6) => HolyIp::V6(v6),
    }
}

/// Combined TUN-read → encrypt → UDP-send task.
///
/// Reads raw IP packets from the TUN device, looks up the destination session,
/// encrypts the payload, encodes the `Packet`, and sends it directly via the
/// transport. No intermediate channels or heap allocations in steady state.
pub(super) async fn tun_encrypt_forward(
    mut stop: watch::Receiver<bool>,
    tun: Arc<AsyncDevice>,
    transport: Arc<dyn Transport>,
    sessions: Sessions,
) {
    let mut tun_buf = [0u8; 65536];
    let mut encode_buf = [0u8; 65600];
    let mut pool = BufPool::new(65536);

    loop {
        tokio::select! {
            _ = stop.changed() => break,
            result = tun.recv(&mut tun_buf) => match result {
                Err(e) => error!("TUN recv error: {}", e),
                Ok(len) => {
                    match parse_destination(&tun_buf[..len]) {
                        Err(e) => warn!("failed to parse TUN packet destination: {}", e),
                        Ok(ip) => {
                            let holy_ip = ip_to_holy(ip);
                            let Some(session) = sessions.get_by_holy_ip(&holy_ip) else {
                                warn!("[{}] no session for TUN packet destination", ip);
                                continue;
                            };
                            // Copy TUN data into pool buffer (no alloc after warmup)
                            let packet_bytes = pool.copy_to_bytes(&tun_buf[..len]);
                            match noise_encrypt(&DataServerBody::Packet(packet_bytes), &session.state) {
                                Err(e) => warn!("[{}] encrypt failed (sid {}): {}", ip, session.id, e),
                                Ok(encrypted) => {
                                    let pkt = Packet::DataServer(encrypted);
                                    match bincode::encode_into_slice(
                                        &pkt,
                                        &mut encode_buf,
                                        bincode::config::standard(),
                                    ) {
                                        Err(e) => error!("packet encode failed: {}", e),
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
            }
        }
    }
    debug!("tun_encrypt_forward stopped");
}
