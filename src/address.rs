use secp256k1::PublicKey;
use bs58;
use crate::network::Network;

pub fn pubkey_to_address(pubkey: &PublicKey, network: Network) -> String {
    let hash160 = crate::crypto::hash160(&pubkey.serialize());

    let mut payload = Vec::new();
    payload.push(network.p2pkh_prefix());
    payload.extend(&hash160);

    let checksum = crate::crypto::checksum(&payload);
    payload.extend(&checksum);

    bs58::encode(payload).into_string()
}

pub fn validate_address(addr: &str, network: Network) -> bool {
    let decoded = match bs58::decode(addr).into_vec() {
        Ok(v) => v,
        Err(_) => return false,
    };

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

pub fn address_to_scriptpubkey(addr: &str, network: Network) -> Vec<u8> {
    let decoded = bs58::decode(addr).into_vec().unwrap();
    let prefix = decoded[0];
    let hash160 = &decoded[1..21];

    match prefix {
        p if p == network.p2pkh_prefix() => p2pkh_script(hash160),
        p if p == network.p2sh_prefix() => p2sh_script(hash160),
        _ => panic!("invalid address prefix"),
    }
}

fn p2pkh_script(hash160: &[u8]) -> Vec<u8> {
    vec![
        0x76, 0xa9, 0x14,
        hash160[0],hash160[1],hash160[2],hash160[3],hash160[4],
        hash160[5],hash160[6],hash160[7],hash160[8],hash160[9],
        hash160[10],hash160[11],hash160[12],hash160[13],hash160[14],
        hash160[15],hash160[16],hash160[17],hash160[18],hash160[19],
        0x88, 0xac,
    ]
}

fn p2sh_script(hash160: &[u8]) -> Vec<u8> {
    let mut script = Vec::new();
    script.push(0xa9); // OP_HASH160
    script.push(0x14);
    script.extend(hash160);
    script.push(0x87); // OP_EQUAL
    script
}
