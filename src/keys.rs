use crate::{crypto, network::Network};
use bs58;
use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

// Generate a new compressed WIF private key
pub fn generate_wif(network: Network) -> String {
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let (secret, _) = secp.generate_keypair(&mut rng);

    let mut payload = Vec::with_capacity(38);
    payload.push(network.wif_prefix());
    payload.extend(secret.secret_bytes());
    payload.push(0x01); // compressed key marker

    let checksum = crypto::checksum(&payload);
    payload.extend(&checksum);

    bs58::encode(payload).into_string()
}

// Decode WIF into SecretKey
pub fn wif_to_privkey(wif: &str, network: Network) -> SecretKey {
    let data = bs58::decode(wif).into_vec().expect("invalid WIF");

    // 1 (prefix) + 32 (key) + 1 (compressed) + 4 (checksum)
    assert!(data.len() == 38, "invalid WIF length");
    assert!(data[0] == network.wif_prefix(), "wrong network");
    assert!(data[33] == 0x01, "key not compressed");

    // Verify checksum
    let checksum = crypto::checksum(&data[..34]);
    assert_eq!(&data[34..], &checksum, "invalid WIF checksum");

    SecretKey::from_slice(&data[1..33]).expect("invalid private key")
}

// Derive compressed public key from private key
pub fn privkey_to_pubkey(secret: &SecretKey) -> PublicKey {
    let secp = Secp256k1::new();
    PublicKey::from_secret_key(&secp, secret)
}
