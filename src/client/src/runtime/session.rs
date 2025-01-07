use sunbeam::protocol::{
    SESSION_KEY_SIZE,
    enc::BodyEnc,
    SessionId
};

pub struct Session {
    pub id: SessionId,
    pub key: [u8; SESSION_KEY_SIZE],
    pub enc: BodyEnc,
}
