



pub(crate) struct Cred {
    // Secret Key
    pub sk: [u8; 32],
    // Pre-Shared Key 
    pub psk: [u8; 32],
    // Server Public Key
    pub spk: [u8; 32],
}