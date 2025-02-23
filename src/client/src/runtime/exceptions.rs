use thiserror::Error;


#[derive(Error, Debug, Clone)]
pub enum RuntimeError {
    #[error("TunError: {0}")]
    TunError(String),
    #[error("IOError: {0}")]
    IOError(String),
    #[error("InvalidCredentials: {0}")]
    InvalidCredentials(String),
    #[error("MaxConnectedDevices: {0}")]
    MaxConnectedDevices(String),
    #[error("ServerOverloaded")]
    ServerOverloaded,
    #[error("SessionExpired: {0}")]
    SessionExpired(String),
    #[error("ServerShutdown")]
    ServerShutdown,
    #[error("UnexpectedError: {0}")]
    UnexpectedError(String),
    #[error("TimeoutError: {0}")]
    TimeoutError(String),
    #[error("StopSignal")]
    StopSignal,
}

impl From<std::io::Error> for RuntimeError {
    fn from(err: std::io::Error) -> Self {
        RuntimeError::IOError(err.to_string())
    }
}
