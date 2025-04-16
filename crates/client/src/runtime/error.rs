use thiserror::Error;


#[derive(Error, Debug, Clone)]
pub enum RuntimeError {
    #[error("IO: {0}")]
    IO(String),
    #[error("Tun: {0}")]
    Tun(String),
    #[error("Handshake: {0}")]
    Handshake(String),
    #[error("Disconnect: {0}")]
    Disconnect(String),
    #[error("Unexpected: {0}")]
    Unexpected(String),
    #[error("StopSignal")]
    StopSignal
}

impl From<std::io::Error> for RuntimeError {
    fn from(err: std::io::Error) -> Self {
        RuntimeError::IO(err.to_string())
    }
}

impl From<snow::Error> for RuntimeError {
    fn from(err: snow::Error) -> Self {
        RuntimeError::Handshake(format!("snow error: {}", err))
    }
}

impl From<anyhow::Error> for RuntimeError {
    fn from(err: anyhow::Error) -> Self {
        RuntimeError::Unexpected(err.to_string())
    }
}

impl<T> From<tokio::sync::broadcast::error::SendError<T>> for RuntimeError  {
    fn from(err: tokio::sync::broadcast::error::SendError<T>) -> Self {
        RuntimeError::IO(format!("broadcast send: {}", err))
    }
}
