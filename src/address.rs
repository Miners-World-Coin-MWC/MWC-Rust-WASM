use secp256k1::PublicKey;
use bs58;

const P2PKH_PREFIX: u8 = 0x14; // 20 — MWC PUBKEY_ADDRESS

pub fn pubkey_to_address(pubkey: &PublicKey) -> String {
    let hash160 = crate::crypto::hash160(&pubkey.serialize());

    let mut payload = Vec::with_capacity(25);
    payload.push(P2PKH_PREFIX);
    payload.extend(&hash160);

    let checksum = crate::crypto::checksum(&payload);
    payload.extend(&checksum);

    bs58::encode(payload).into_string()
}

pub fn pubkey_to_scriptpubkey(pubkey: &PublicKey) -> Vec<u8> {
    let hash160 = crate::crypto::hash160(&pubkey.serialize());
    p2pkh_script(&hash160)
}

pub fn address_to_scriptpubkey(addr: &str) -> Vec<u8> {
    let decoded = bs58::decode(addr)
        .into_vec()
        .expect("invalid base58 address");

    // [prefix][20-byte hash][4-byte checksum]
    assert!(decoded.len() == 25, "invalid address length");
    assert!(decoded[0] == P2PKH_PREFIX, "invalid address prefix");

    let hash160 = &decoded[1..21];
    p2pkh_script(hash160)
}

fn p2pkh_script(hash160: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // push 20 bytes
    script.extend(hash160);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script
}
