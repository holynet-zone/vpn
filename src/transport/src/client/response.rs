use super::packet::DataBody;

pub enum Response {
    Data(DataBody),
    Close, // Disconnect without sending a response
    None
}