//! Bincode 2.x VarintEncoding decode.
//!
//! Bincode standard() config encodes unsigned integers as:
//!   0..=250      → 1 byte (the value itself)
//!   251..=65535  → [0xFB, lo, hi]          (2 bytes LE u16)
//!   65536..=2^32 → [0xFC, b0,b1,b2,b3]    (4 bytes LE u32)
//!   > 2^32       → [0xFD, b0..b7]          (8 bytes LE u64)
//!   > 2^64       → [0xFE, b0..b15]         (16 bytes LE u128)
//!
//! All functions return `(value, remaining_slice)` or `None` on truncation.

#[inline]
pub(crate) fn read_u32(buf: &[u8]) -> Option<(u32, &[u8])> {
    let (&tag, rest) = buf.split_first()?;
    match tag {
        0..=250 => Some((tag as u32, rest)),
        251 => {
            let (b, rest) = rest.split_at_checked(2)?;
            Some((u16::from_le_bytes(b.try_into().unwrap()) as u32, rest))
        }
        252 => {
            let (b, rest) = rest.split_at_checked(4)?;
            Some((u32::from_le_bytes(b.try_into().unwrap()), rest))
        }
        _ => None,
    }
}

#[inline]
pub(crate) fn read_u16(buf: &[u8]) -> Option<(u16, &[u8])> {
    let (&tag, rest) = buf.split_first()?;
    match tag {
        0..=250 => Some((tag as u16, rest)),
        251 => {
            let (b, rest) = rest.split_at_checked(2)?;
            Some((u16::from_le_bytes(b.try_into().unwrap()), rest))
        }
        _ => None,
    }
}

/// Decode a varint-encoded usize/u64 (used by bincode serde for byte-sequence lengths).
#[inline]
pub(crate) fn read_usize(buf: &[u8]) -> Option<(usize, &[u8])> {
    let (&tag, rest) = buf.split_first()?;
    match tag {
        0..=250 => Some((tag as usize, rest)),
        251 => {
            let (b, rest) = rest.split_at_checked(2)?;
            Some((u16::from_le_bytes(b.try_into().unwrap()) as usize, rest))
        }
        252 => {
            let (b, rest) = rest.split_at_checked(4)?;
            Some((u32::from_le_bytes(b.try_into().unwrap()) as usize, rest))
        }
        253 => {
            let (b, rest) = rest.split_at_checked(8)?;
            Some((u64::from_le_bytes(b.try_into().unwrap()) as usize, rest))
        }
        _ => None,
    }
}

#[inline]
pub(crate) fn read_u128(buf: &[u8]) -> Option<(u128, &[u8])> {
    let (&tag, rest) = buf.split_first()?;
    match tag {
        0..=250 => Some((tag as u128, rest)),
        251 => {
            let (b, rest) = rest.split_at_checked(2)?;
            Some((u16::from_le_bytes(b.try_into().unwrap()) as u128, rest))
        }
        252 => {
            let (b, rest) = rest.split_at_checked(4)?;
            Some((u32::from_le_bytes(b.try_into().unwrap()) as u128, rest))
        }
        253 => {
            let (b, rest) = rest.split_at_checked(8)?;
            Some((u64::from_le_bytes(b.try_into().unwrap()) as u128, rest))
        }
        254 => {
            let (b, rest) = rest.split_at_checked(16)?;
            Some((u128::from_le_bytes(b.try_into().unwrap()), rest))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify round-trip: encode via bincode, then decode via our varint fns.
    fn enc_u32(v: u32) -> Vec<u8> {
        bincode::encode_to_vec(v, bincode::config::standard()).unwrap()
    }
    fn enc_u16(v: u16) -> Vec<u8> {
        bincode::encode_to_vec(v, bincode::config::standard()).unwrap()
    }
    fn enc_u128(v: u128) -> Vec<u8> {
        bincode::encode_to_vec(v, bincode::config::standard()).unwrap()
    }
    fn enc_usize(v: usize) -> Vec<u8> {
        bincode::encode_to_vec(v, bincode::config::standard()).unwrap()
    }

    #[test]
    fn test_u32_small() {
        for v in [0u32, 1, 42, 250] {
            let enc = enc_u32(v);
            let (dec, rest) = read_u32(&enc).unwrap();
            assert_eq!(dec, v, "v={v}");
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn test_u32_u16_range() {
        for v in [251u32, 1000, 1400, 65535] {
            let enc = enc_u32(v);
            let (dec, rest) = read_u32(&enc).unwrap();
            assert_eq!(dec, v, "v={v}");
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn test_u32_large() {
        for v in [65536u32, 100_000, u32::MAX] {
            let enc = enc_u32(v);
            let (dec, rest) = read_u32(&enc).unwrap();
            assert_eq!(dec, v, "v={v}");
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn test_u16_small() {
        for v in [0u16, 1, 250, 1400, u16::MAX] {
            let enc = enc_u16(v);
            let (dec, rest) = read_u16(&enc).unwrap();
            assert_eq!(dec, v, "v={v}");
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn test_u128_small() {
        for v in [0u128, 42, 250] {
            let enc = enc_u128(v);
            let (dec, rest) = read_u128(&enc).unwrap();
            assert_eq!(dec, v, "v={v}");
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn test_u128_large() {
        for v in [1_000_000u128, 5_000_000_000, u64::MAX as u128, u128::MAX] {
            let enc = enc_u128(v);
            let (dec, rest) = read_u128(&enc).unwrap();
            assert_eq!(dec, v, "v={v}");
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn test_usize_1400() {
        let enc = enc_usize(1400);
        let (dec, rest) = read_usize(&enc).unwrap();
        assert_eq!(dec, 1400);
        assert!(rest.is_empty());
    }

    #[test]
    fn test_trailing_bytes_ignored() {
        let mut enc = enc_u32(42);
        enc.extend_from_slice(&[0xFF, 0xFF]);
        let (dec, rest) = read_u32(&enc).unwrap();
        assert_eq!(dec, 42);
        assert_eq!(rest, &[0xFF, 0xFF]);
    }
}
