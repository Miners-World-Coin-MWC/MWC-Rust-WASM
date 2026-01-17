use secp256k1::{Secp256k1, SecretKey, PublicKey};
use rand::rngs::OsRng;
use bs58;
use crate::{crypto, network::Network};

pub fn generate_wif(network: Network) -> String {
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let (secret, _) = secp.generate_keypair(&mut rng);

    let mut payload = Vec::with_capacity(34);
    payload.push(network.wif_prefix());
    payload.extend(secret.secret_bytes());
    payload.push(0x01); // compressed

    let checksum = crypto::checksum(&payload);
    payload.extend(&checksum);

    bs58::encode(payload).into_string()
}

pub fn wif_to_privkey(wif: &str, network: Network) -> SecretKey {
    let data = bs58::decode(wif)
        .into_vec()
        .expect("invalid WIF");

    assert!(data.len() == 38, "invalid WIF length");
    assert!(data[0] == network.wif_prefix(), "wrong network");
    assert!(data[33] == 0x01, "key not compressed");

    SecretKey::from_slice(&data[1..33]).expect("invalid private key")
}

pub fn privkey_to_pubkey(secret: &SecretKey) -> PublicKey {
    let secp = Secp256k1::new();
    PublicKey::from_secret_key(&secp, secret)
}
