use sha2::{Sha256, Digest};
use ripemd::Ripemd160;

pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

pub fn double_sha256(data: &[u8]) -> Vec<u8> {
    sha256(&sha256(data))
}

pub fn hash160(data: &[u8]) -> Vec<u8> {
    let sha = sha256(data);
    Ripemd160::digest(&sha).to_vec()
}

pub fn checksum(data: &[u8]) -> Vec<u8> {
    double_sha256(data)[0..4].to_vec()
}
