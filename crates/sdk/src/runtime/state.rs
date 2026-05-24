use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use snow::StatelessTransportState;

use crate::protocol::HandshakeResponderPayload;
use crate::runtime::error::RuntimeError;
use crate::runtime::replay::ReplayWindow;

/// Per-session state shared by all client tasks (network, recv, keepalive).
///
/// Wrapping nonce counters in `Arc` lets the three tasks share the same
/// counters without cloning underlying state on every watch channel read.
#[derive(Clone, Debug)]
pub struct ClientSession {
    pub(crate) noise: Arc<StatelessTransportState>,
    /// Monotonically increasing counter used as the Noise nonce for outgoing packets.
    pub(crate) send_nonce: Arc<AtomicU64>,
    /// Anti-replay sliding window for incoming packets from the server.
    pub(crate) recv_window: Arc<Mutex<ReplayWindow>>,
}

impl ClientSession {
    pub(crate) fn new(noise: StatelessTransportState) -> Self {
        Self {
            noise: Arc::new(noise),
            send_nonce: Arc::new(AtomicU64::new(0)),
            recv_window: Arc::new(Mutex::new(ReplayWindow::new())),
        }
    }
}

#[derive(Debug, Clone)]
pub enum RuntimeState {
    Connecting,
    Connected((HandshakeResponderPayload, ClientSession)),
    Error(RuntimeError),
    Listening,
}
