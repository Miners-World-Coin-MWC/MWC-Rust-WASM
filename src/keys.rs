use secp256k1::{Secp256k1, SecretKey, PublicKey};
use rand::rngs::OsRng;
use bs58;

const WIF_PREFIX: u8 = 0x7B; // 123 — MWC SECRET_KEY

pub struct KeyPair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

pub fn generate_wif() -> String {
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let (secret, _) = secp.generate_keypair(&mut rng);

    // WIF payload:
    // [1-byte prefix][32-byte privkey][1-byte compression flag]
    let mut payload = Vec::with_capacity(34);
    payload.push(WIF_PREFIX);
    payload.extend(secret.secret_bytes());
    payload.push(0x01); // compressed public key

    // checksum = first 4 bytes of double SHA256
    let checksum = crate::crypto::checksum(&payload);
    payload.extend(&checksum);

    bs58::encode(payload).into_string()
}

pub fn wif_to_privkey(wif: &str) -> SecretKey {
    let data = bs58::decode(wif)
        .into_vec()
        .expect("invalid base58 WIF");

    // Basic sanity checks
    assert!(data.len() == 38, "invalid WIF length");
    assert!(data[0] == WIF_PREFIX, "invalid WIF prefix");
    assert!(data[33] == 0x01, "WIF not compressed");

    SecretKey::from_slice(&data[1..33]).expect("invalid private key")
}

pub fn privkey_to_pubkey(secret: &SecretKey) -> PublicKey {
    let secp = Secp256k1::new();
    PublicKey::from_secret_key(&secp, secret)
}
