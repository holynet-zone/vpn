use std::sync::Arc;
use snow::StatelessTransportState;
use crate::protocol::HandshakeResponderPayload;
use crate::error::RuntimeError;

#[derive(Debug, Clone)]
pub enum RuntimeState {
    Connecting,
    Connected((HandshakeResponderPayload, Arc<StatelessTransportState>)),
    Error(RuntimeError),
    Listening,
}