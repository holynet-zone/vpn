use std::str::FromStr;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use snow::{Builder, HandshakeState, StatelessTransportState};
use snow::params::NoiseParams;
use crate::keys::handshake::{PublicKey, SecretKey};
use crate::session::Alg;
use crate::handshake::{
    NOISE_IK_PSK2_25519_AESGCM_BLAKE2S,
    NOISE_IK_PSK2_25519_CHACHAPOLY_BLAKE2S,
    params_from_alg
};


#[derive(Serialize, Deserialize)]
pub struct Handshake {
    pub body: Vec<u8>
}

impl Handshake {
    

    pub fn try_decode(&self, sk: &SecretKey, psk: &SecretKey, client_pk: &PublicKey, alg: &Alg) -> anyhow::Result<(HandshakeBody, HandshakeState)> {
        let mut responder = Builder::new(match alg {
            Alg::ChaCha20Poly1305 => NOISE_IK_PSK2_25519_CHACHAPOLY_BLAKE2S.clone(),
            Alg::Aes256 => NOISE_IK_PSK2_25519_AESGCM_BLAKE2S.clone()
        })
            .local_private_key(sk.as_slice())
            .remote_public_key(client_pk.as_slice())
            .psk(2, psk.as_slice())
            .build_responder()?;


        let mut buffer = [0u8; 65536];
        let len = responder.read_message(&self.body, &mut buffer)?;
        Ok((bincode::deserialize(&buffer[..len])?, responder))
    }
}


// This type is used by the user when he wants to connect to the server.
// Note that the `sid` field of the `ClientPacket` type
// must be set to `0`, otherwise the server will ignore the request
//
// The size of this type is 1 byte
// #[derive(Serialize, Deserialize)]
// pub struct HandshakeBody {
//     // Note that the type of the `guard` field is `EncAlg`, and in the user configuration
//     // file it is `AuthEnc` - this is not done to confuse you
//     //
//     // The point is that the `AuthEnc` type cannot be changed on the user side, because
//     // then the user password would have to be reissued on the server side
//     //
//     // The `guard` field of the `EncAlg` type in this context means the encryption type
//     // that the server will use for further communication with the client once
//     // the connection is successfully established and the payload flow begins.
//     // It does not mean the encryption type for authentication!
//     //
//     // The size of this type is 1 byte
//     // enc: Alg
// }
