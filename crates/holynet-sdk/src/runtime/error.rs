use std::fmt;

pub enum BuildError {
    MissingRequiredField(&'static str),
}

#[derive(Debug, Clone)]
pub enum RuntimeError {
    IO(String),
    Handshake(String),
    Unexpected(String),
    StopSignal,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuntimeError::IO(s) => write!(f, "IO error: {}", s),
            RuntimeError::Handshake(s) => write!(f, "handshake error: {}", s),
            RuntimeError::Unexpected(s) => write!(f, "unexpected error: {}", s),
            RuntimeError::StopSignal => write!(f, "stop signal received"),
        }
    }
}

impl From<std::io::Error> for RuntimeError {
    fn from(err: std::io::Error) -> Self {
        RuntimeError::IO(err.to_string())
    }
}

impl From<snow::Error> for RuntimeError {
    fn from(err: snow::Error) -> Self {
        RuntimeError::Handshake(format!("snow error: {err}"))
    }
}

impl<T> From<tokio::sync::broadcast::error::SendError<T>> for RuntimeError {
    fn from(err: tokio::sync::broadcast::error::SendError<T>) -> Self {
        RuntimeError::IO(format!("broadcast send: {err}"))
    }
}
