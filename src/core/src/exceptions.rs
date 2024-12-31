use thiserror::Error;


#[derive(Error, Debug)]
pub enum CoreExceptions {
    #[error("TunError: {0}")]
    TunError(String),
    #[error("BadPacketRequest: {0}")]
    BadPacketRequest(String),
    #[error("IOError: {0}")]
    IOError(String),
}

impl From<std::io::Error> for CoreExceptions {
    fn from(err: std::io::Error) -> Self {
        CoreExceptions::IOError(err.to_string())
    }
}
