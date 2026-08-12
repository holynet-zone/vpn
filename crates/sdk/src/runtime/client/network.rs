//! Merged network-read + encrypt + UDP-send task (client side).
//!
//! ## Batched, zero-allocation hot path
//!
//! ```text
//! network.recv_multiple → up to TUN_BATCH_SIZE IP packets from one 64 KiB
//!                         GSO super-frame (TUN GRO split, one syscall)
//!   for each packet:
//!     → write_ip_packet_plain  — PLAIN_BUF (thread-local), Copy 1
//!     → noise write_message    — AEAD encrypt into encode_buf (stack), Copy 2
//!     → transport.send         — direct UDP write, no intermediate buffers
//! ```

use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::sync::watch;
use tracing::warn;

use crate::gateway::{
    network::{Network, TUN_BATCH_SIZE},
    transport::ClientTransport,
};
use crate::protocol::SessionId;
use crate::runtime::client::AWAIT_STATE_DELAY;
use crate::runtime::crypto::encode_data_client_packet;
use crate::runtime::error::RuntimeError;
use crate::runtime::state::{ClientSession, RuntimeState};

pub(super) async fn encrypt_forward<T: ClientTransport, N: Network>(
    state_tx: watch::Sender<RuntimeState>,
    network: Arc<N>,
    transport: Arc<T>,
) {
    let mut state_rx = state_tx.subscribe();
    // Batched TUN read buffers (reused each iteration — zero alloc in steady state).
    let mut orig = vec![0u8; 10 + 65535];
    let seg = network.mtu() as usize + 128;
    let mut bufs: Vec<Vec<u8>> = (0..TUN_BATCH_SIZE).map(|_| vec![0u8; seg]).collect();
    let mut sizes = vec![0usize; TUN_BATCH_SIZE];
    let mut encode_buf = [0u8; 65600];
    let mut state_wait_timer = tokio::time::interval(AWAIT_STATE_DELAY);

    let mut is_connected = false;
    let mut sid = SessionId::default();
    let mut transport_state: Option<ClientSession> = None;

    'main: loop {
        // Pause reading until connected to avoid encrypting with stale state.
        if !is_connected {
            match state_rx.has_changed() {
                Ok(false) => {
                    state_wait_timer.tick().await;
                    continue;
                }
                Err(_) => break,
                Ok(true) => {}
            }
        }

        tokio::select! {
            _ = state_rx.changed() => {
                match state_rx.borrow().deref() {
                    RuntimeState::Error(_) => break,
                    RuntimeState::Connecting => {
                        is_connected = false;
                        transport_state = None;
                    }
                    RuntimeState::Connected((payload, session)) => {
                        sid = payload.sid;
                        transport_state = Some(session.clone());
                        is_connected = true;
                    }
                    _ => {}
                }
            }
            result = network.recv_multiple(&mut orig, &mut bufs, &mut sizes, 0) => match result {
                Err(e) => {
                    let state = RuntimeState::Error(RuntimeError::IO(
                        format!("failed to receive from network: {}", e)
                    ));
                    if state_tx.send(state).is_err() { break; }
                }
                Ok(count) => {
                    let Some(ref session) = transport_state else {
                        warn!("received network packet before connected state, dropping");
                        continue;
                    };
                    for i in 0..count {
                        let pkt = &bufs[i][..sizes[i]];
                        if pkt.is_empty() {
                            continue;
                        }
                        let nonce = session.send_nonce.fetch_add(1, Ordering::Relaxed);
                        match encode_data_client_packet(pkt, sid, &session.noise, nonce, &mut encode_buf) {
                            Err(e) => {
                                if state_tx.send(RuntimeState::Error(
                                    RuntimeError::Unexpected(format!("failed to encrypt data: {}", e))
                                )).is_err() { break 'main; }
                            }
                            Ok(total) => {
                                if let Err(e) = transport.send(&encode_buf[..total]).await {
                                    warn!("transport send error, reconnecting: {}", e);
                                    if state_tx.send(RuntimeState::Connecting).is_err() { break 'main; }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
