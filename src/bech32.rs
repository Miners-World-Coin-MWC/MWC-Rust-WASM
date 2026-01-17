use bech32::{self, ToBase32, Variant};

pub fn encode_segwit(hrp: &str, witver: u8, witprog: &[u8]) -> String {
    bech32::encode(hrp, std::iter::once(witver).chain(witprog.to_base32()), Variant::Bech32)
        .expect("bech32 encoding failed")
}

pub fn decode_segwit(addr: &str) -> Option<(String, u8, Vec<u8>)> {
    let (hrp, data, _) = bech32::decode(addr).ok()?;
    let (witver, witprog) = data.split_first()?;
    Some((hrp, *witver, Vec::from(bech32::FromBase32::from_base32(witprog).ok()?)))
}
