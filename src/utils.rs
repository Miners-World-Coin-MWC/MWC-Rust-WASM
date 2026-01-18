use base64;
use hex::*;

// --------------------
// Hex helpers
// --------------------

pub fn hex_to_bytes(s: &str) -> Vec<u8> {
    hex::decode(s).expect("invalid hex")
}

pub fn bytes_to_hex(b: &[u8]) -> String {
    hex::encode(b)
}

// --------------------
// Base64 helpers (PSBT)
// --------------------

pub fn base64_to_bytes(s: &str) -> Vec<u8> {
    base64::decode(s).expect("invalid base64")
}

pub fn bytes_to_base64(b: &[u8]) -> String {
    base64::encode(b)
}

// --------------------
// Endian helpers
// --------------------

pub fn u32_le(n: u32) -> [u8; 4] {
    n.to_le_bytes()
}

pub fn u64_le(n: u64) -> [u8; 8] {
    n.to_le_bytes()
}

// --------------------
// Bitcoin-style VarInt
// --------------------

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

// --------------------
// Transaction / PSBT detection
// --------------------

// PSBT magic bytes: 0x70736274 = "psbt"
pub fn is_psbt_bytes(data: &[u8]) -> bool {
    data.len() > 4 && data[0..4] == [0x70, 0x73, 0x62, 0x74]
}

// Accepts hex OR base64, returns raw bytes
pub fn parse_tx_or_psbt(input: &str) -> Vec<u8> {
    // Try hex first
    if let Ok(bytes) = hex::decode(input) {
        return bytes;
    }

    // Fallback to base64 (PSBT)
    base64::decode(input).expect("invalid hex or base64 input")
}

// High-level discriminator
pub fn classify_tx(input: &str) -> TxInputType {
    let bytes = parse_tx_or_psbt(input);

    if is_psbt_bytes(&bytes) {
        TxInputType::Psbt
    } else {
        TxInputType::RawTransaction
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxInputType {
    RawTransaction,
    Psbt,
}
