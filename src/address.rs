use crate::network::Network;
use bech32::{self, ToBase32, Variant};
use bs58;
use secp256k1::PublicKey;

/// Convert public key to legacy P2PKH address
pub fn pubkey_to_address(pubkey: &PublicKey, network: Network) -> String {
    let hash160 = crate::crypto::hash160(&pubkey.serialize());

    let mut payload = Vec::with_capacity(25);
    payload.push(network.p2pkh_prefix());
    payload.extend(&hash160);

    let checksum = crate::crypto::checksum(&payload);
    payload.extend(&checksum);

    bs58::encode(payload).into_string()
}

/// Validate Base58 P2PKH / P2SH address (NOT bech32)
pub fn validate_address(addr: &str, network: Network) -> bool {
    let decoded = match bs58::decode(addr).into_vec() {
        Ok(v) => v,
        Err(_) => return false,
    };

    // version (1) + hash160 (20) + checksum (4)
    if decoded.len() != 25 {
        return false;
    }

    let prefix = decoded[0];
    if prefix != network.p2pkh_prefix() && prefix != network.p2sh_prefix() {
        return false;
    }

    let checksum = &decoded[21..25];
    let expected = crate::crypto::checksum(&decoded[0..21]);

    checksum == expected
}

/// Convert address (P2PKH / P2SH / Bech32 v0) to scriptPubKey
pub fn address_to_scriptpubkey(addr: &str, network: Network) -> Vec<u8> {
    if addr.starts_with(network.bech32_hrp()) {
        return p2wpkh_script_from_bech32(addr);
    }

    let decoded = bs58::decode(addr).expect("invalid base58 address");
    let prefix = decoded[0];
    let hash160 = &decoded[1..21];

    match prefix {
        p if p == network.p2pkh_prefix() => p2pkh_script(hash160),
        p if p == network.p2sh_prefix() => p2sh_script(hash160),
        _ => panic!("invalid address prefix"),
    }
}

/// Convert public key to Bech32 P2WPKH address
pub fn pubkey_to_bech32(pubkey: &PublicKey, hrp: &str) -> String {
    let hash160 = crate::crypto::hash160(&pubkey.serialize());

    // witness version 0 + program
    let mut data = vec![bech32::u5::try_from_u8(0).unwrap()];
    data.extend(hash160.to_base32());

    bech32::encode(hrp, data, Variant::Bech32).unwrap()
}

/// --------------------
/// Script builders
/// --------------------

fn p2pkh_script(hash160: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.extend([
        0x76, // OP_DUP
        0xa9, // OP_HASH160
        0x14, // push 20 bytes
    ]);
    script.extend(hash160);
    script.extend([
        0x88, // OP_EQUALVERIFY
        0xac, // OP_CHECKSIG
    ]);
    script
}

fn p2sh_script(hash160: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(23);
    script.push(0xa9); // OP_HASH160
    script.push(0x14);
    script.extend(hash160);
    script.push(0x87); // OP_EQUAL
    script
}

/// Decode Bech32 P2WPKH address into scriptPubKey
fn p2wpkh_script_from_bech32(addr: &str) -> Vec<u8> {
    let (_hrp, data, _) = bech32::decode(addr).expect("invalid bech32");

    let version = data[0].to_u8();
    assert!(version == 0, "unsupported witness version");

    let program: Vec<u8> = Vec::<u8>::from_base32(&data[1..]).expect("invalid witness program");

    assert!(program.len() == 20, "invalid P2WPKH length");

    let mut script = Vec::with_capacity(22);
    script.push(0x00); // OP_0
    script.push(0x14); // push 20 bytes
    script.extend(program);
    script
}
