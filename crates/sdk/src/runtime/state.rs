use crate::protocol::HandshakeResponderPayload;
use crate::runtime::error::RuntimeError;
use snow::StatelessTransportState;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum RuntimeState {
    Connecting,
    Connected((HandshakeResponderPayload, Arc<StatelessTransportState>)),
    Error(RuntimeError),
    Listening,
}
