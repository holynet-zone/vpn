use sunbeam::protocol::{
    keys::session::SessionKey,
    enc::EncAlg,
    SessionId
};


pub struct Session {
    pub id: SessionId,
    pub key: SessionKey,
    pub enc: EncAlg,
}
