use thiserror::Error;


#[derive(Error, Debug)]
pub enum RuntimeExceptions {
    #[error("TunError: {0}")]
    TunError(String),
    #[error("IOError: {0}")]
    IOError(String),
}

impl From<std::io::Error> for RuntimeExceptions {
    fn from(err: std::io::Error) -> Self {
        RuntimeExceptions::IOError(err.to_string())
    }
}
