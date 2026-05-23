use bincode::{error::{DecodeError, EncodeError}, BorrowDecode, Decode, Encode};
use std::ops::Deref;
use bincode::de::BorrowDecoder;
use serde::{Deserialize, Serialize};


#[derive(Debug, PartialEq)]
pub struct VecU16<T>(pub Vec<T>);

impl<T> Deref for VecU16<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> From<Vec<T>> for VecU16<T> {
    fn from(vec: Vec<T>) -> Self {
        VecU16(vec)
    }
}

impl<T: Encode> Encode for VecU16<T> {
    fn encode<E: bincode::enc::Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        let len = self.0.len();
        if len > u16::MAX as usize {
            return Err(EncodeError::Other("length exceeds u16::MAX"));
        }
        (len as u16).encode(encoder)?;
        for item in &self.0 {
            item.encode(encoder)?;
        }
        Ok(())
    }
}

impl<Context, T: Decode<Context>> Decode<Context> for VecU16<T> {
    fn decode<D: bincode::de::Decoder<Context = Context>>(decoder: &mut D) -> Result<Self, DecodeError> {
        let len = u16::decode(decoder)? as usize;
        let mut vec = Vec::with_capacity(len);
        for _ in 0..len {
            vec.push(T::decode(decoder)?);
        }
        Ok(VecU16(vec))
    }
}

impl<'de, Context, T> BorrowDecode<'de, Context> for VecU16<T>
where
    T: BorrowDecode<'de, Context>
{
    fn borrow_decode<D>(decoder: &mut D) -> Result<Self, DecodeError> 
    where
        D: bincode::de::Decoder<Context = Context> + BorrowDecoder<'de>
    {
        let len = u16::decode(decoder)? as usize;
        let mut vec = Vec::with_capacity(len);
        for _ in 0..len {
            vec.push(T::borrow_decode(decoder)?);
        }
        Ok(VecU16(vec))
    }
}

impl<T: Serialize + bincode::Encode> Serialize for VecU16<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.0.len() > u16::MAX as usize {
            return Err(serde::ser::Error::custom("length exceeds u16::MAX"));
        }
        
        let mut buffer = [0u8; 65536];
        match bincode::encode_into_slice(
            &self.0,
            &mut buffer,
            bincode::config::standard()
        ) {
            Ok(n) => serializer.serialize_bytes(&buffer[..n]),
            Err(err) => Err(serde::ser::Error::custom(err))
        }
    }
}

impl<'de, T> Deserialize<'de> for VecU16<T>
where
    T: Deserialize<'de> + bincode::Decode<()>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {

        let bytes = <&[u8]>::deserialize(deserializer)?;

        let (vec, _) = bincode::decode_from_slice(
            bytes,
            bincode::config::standard()
        ).map_err(serde::de::Error::custom)?;
        
        Ok(VecU16(vec))
    }
}