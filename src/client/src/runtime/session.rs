use sunbeam::protocol::{
    keys::session::SessionKey,
    enc::EncAlg,
    SessionId
};

#[derive(Clone)]
pub struct Session {
    pub id: SessionId,
    pub key: SessionKey,
    pub enc: EncAlg,
}
