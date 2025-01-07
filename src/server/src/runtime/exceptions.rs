use thiserror::Error;


#[derive(Error, Debug)]
pub enum RuntimeError {
    #[error("TunError: {0}")]
    TunError(String),
    #[error("IOError: {0}")]
    IOError(String),
    #[error("UnexpectedError: {0}")]
    UnexpectedError(String),
    #[error("StopSignal")]
    StopSignal,
}

impl From<std::io::Error> for RuntimeError {
    fn from(err: std::io::Error) -> Self {
        RuntimeError::IOError(err.to_string())
    }
}
