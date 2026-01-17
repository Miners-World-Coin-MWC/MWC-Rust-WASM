use hex;

pub fn hex_to_bytes(s: &str) -> Vec<u8> {
    hex::decode(s).expect("invalid hex")
}

pub fn bytes_to_hex(b: &[u8]) -> String {
    hex::encode(b)
}

pub fn u32_le(n: u32) -> [u8; 4] {
    n.to_le_bytes()
}

pub fn u64_le(n: u64) -> [u8; 8] {
    n.to_le_bytes()
}

/// Bitcoin-style VarInt
pub fn varint(n: usize) -> Vec<u8> {
    match n {
        0..=0xfc => vec![n as u8],
        0xfd..=0xffff => {
            let mut v = vec![0xfd];
            v.extend((n as u16).to_le_bytes());
            v
        }
        0x10000..=0xffff_ffff => {
            let mut v = vec![0xfe];
            v.extend((n as u32).to_le_bytes());
            v
        }
        _ => {
            let mut v = vec![0xff];
            v.extend((n as u64).to_le_bytes());
            v
        }
    }
}
