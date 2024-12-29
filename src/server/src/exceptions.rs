

pub enum ServerExceptions {
    TunError(String),
    BadPacketRequest(String),
    IOError(String),
}
