use std::sync::Arc;
use snow::StatelessTransportState;
use shared::protocol::HandshakeResponderPayload;
use crate::runtime::error::RuntimeError;

#[derive(Debug, Clone)]
pub enum RuntimeState {
    Connecting,
    Connected((HandshakeResponderPayload, Arc<StatelessTransportState>)),
    Error(RuntimeError)
}