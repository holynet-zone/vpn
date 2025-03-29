

#[derive(Clone)]
pub struct Credential {
    pub private_key: [u8; 32],
    pub pre_shared_key: [u8; 32],
    pub server_public_key: [u8; 32]
}