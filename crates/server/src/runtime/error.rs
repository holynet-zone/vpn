use thiserror::Error;


#[derive(Error, Debug, Clone)]
pub enum RuntimeError {
    #[error("Tun: {0}")]
    Tun(String),
    #[error("IO: {0}")]
    IO(String),
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
