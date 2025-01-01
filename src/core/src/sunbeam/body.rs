use crate::sunbeam::enc::BodyEnc;
use crate::sunbeam::SESSION_KEY_SIZE;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::net::IpAddr;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum ClientBody {
    /// Represents a structure of useful data,
    /// in particular an ip packet taken from a user tun
    /// 
    /// The size of this type is variable. To store the length of a vector, the u16 type is used, 
    /// the size of which is 2 bytes => the size of this vector is 2 bytes + x - the number 
    /// of elements in the vector
    Data(Vec<u8>),
    /// This type contains a timestamp from the beginning of the UNIX epoch in milliseconds - the time the package was created
    ///
    /// This is important to calculate both (Round-Trip Time) *RTT* and (One-Way Delay) *OWD*  
    ///   
    /// The size of this type is 16 bytes
    KeepAlive(u128),
    /// This type is used by the user when he wants to connect to the server. 
    /// Note that the `sid` field of the `ClientPacket` type
    /// must be set to `0`, otherwise the server will ignore the request
    /// 
    /// The size of this type is 1 byte
    /// 
    Connection {
        /// Note that the type of the `enc` field is `BodyEnc`, and in the user configuration 
        /// file it is `AuthEnc` - this is not done to confuse you
        /// 
        /// The point is that the `AuthEnc` type cannot be changed on the user side, because 
        /// then the user password would have to be reissued on the server side
        /// 
        /// The `enc` field of the `BodyEnc` type in this context means the encryption type 
        /// that the server will use for further communication with the client once 
        /// the connection is successfully established and the payload flow begins. 
        /// It does not mean the encryption type for authentication!
        /// 
        /// The size of this type is 1 byte
        enc: BodyEnc
    },
}

#[derive(Serialize, Deserialize)]
pub enum ConnectionState {
    /// If the user data is correct, and it is possible to allocate a user session,
    /// then the connection is considered successful - the server returns useful
    /// data for configuration
    /// 
    /// The size of this type:  
    /// * If holynet ipv4 and dns ipv4: 5 + 1 + 4 + 128 + 5 = 143 bytes
    /// * If holynet ipv6 and dns ipv4: 17 + 1 + 4 + 128 + 5 = 155 bytes
    /// * If holynet ipv4 and dns ipv6: 5 + 1 + 4 + 128 + 17 = 155 bytes
    /// * If holynet ipv6 and dns ipv6: 17 + 1 + 4 + 128 + 17 = 167 bytes
    Connected {
        /// This field contains the IP address of the user VPN interface
        ///
        /// The size of this type is from (1+4) to (1+16) bytes.
        /// Maximum size is 17 bytes
        ip: IpAddr,
        /// This field contains the prefix of the user VPN interface
        ///
        /// The size of this type is 1 byte
        prefix: u8,
        /// This field contains the numeric session identifier. 
        /// There can be (4,294,967,295 - 1) active devices connected to one server at the same time. 
        /// Note that `sid` with value `0` is reserved and is used only during authentication! 
        /// The client cannot get `sid` with value `0`!
        ///
        /// The size of this type is 4 bytes
        sid: u32,
        /// This field contains the encryption key that the client should use for 
        /// this session and the selected encryption algorithm (`BodyEnc`)
        #[serde(with = "BigArray")]
        key: [u8; SESSION_KEY_SIZE],
        /// This field contains the MTU of the user VPN interface
        ///
        /// The size of this type is from (1+4) bytes to (1+16) bytes
        dns: IpAddr,
    },
    /// The server administrator can limit the number of devices from which one can connect using
    /// one cred. By default, this is 10 devices - it is set at the stage of creating a client
    MaxConnectedDevices,
    /// If the username or password is incorrect, the connection is refused
    InvalidCredentials
}

#[derive(Serialize, Deserialize)]
pub enum ServerBody {
    /// Represents a structure of useful data,
    /// in particular an ip packet taken from a server tun
    /// 
    /// The size of this type is variable. To store the length of a vector, the u16 type is used, 
    /// the size of which is 2 bytes => the size of this vector is 2 bytes + x - the number 
    /// of elements in the vector
    Data(Vec<u8>),
    /// This type contains two important fields: server_ts and client_ts - meaning the timestamp
    /// since the UNIX epoch in milliseconds!
    ///
    /// This is important to calculate both (Round-Trip Time) *RTT* and (One-Way Delay) *OWD*
    /// 
    /// The size of this type is 32 bytes
    KeepAlive { server_ts: u128, client_ts: u128 },
    /// This type represents a response to a connection request.
    /// Please note that if the structure of the request was violated (for example,
    /// instead of the expected uid = 0, another identifier was specified),
    /// the server will not expect a connection request, and upon receiving such a body,
    /// it will simply ignore it
    /// 
    /// The size of this type is 1- bytes
    Connection(ConnectionState)
}
