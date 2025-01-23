use super::Key;

const SESSION_KEY_SIZE: usize = 32;

pub type SessionKey = Key<SESSION_KEY_SIZE>;
