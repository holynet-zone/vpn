use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize)]
pub struct Handshake {
    pub body: Vec<u8>
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
//     // that the server will use for further communication with the storage once
//     // the connection is successfully established and the payload flow begins.
//     // It does not mean the encryption type for authentication!
//     //
//     // The size of this type is 1 byte
//     // enc: Alg
// }
