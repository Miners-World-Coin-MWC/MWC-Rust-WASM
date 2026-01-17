use serde::Deserialize;
use secp256k1::{Secp256k1, Message, PublicKey};
use crate::{crypto, utils, keys, address, network::Network};
use bech32::{self, ToBase32};

#[derive(Deserialize)]
pub struct UTXO {
    pub txid: String,
    pub vout: u32,
    pub scriptPubKey: String, // hex
    pub amount: u64,
    pub is_segwit: bool,      // optional hint; can be auto-detected
}

// ---- helpers ----

fn p2wpkh_script(hash160: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(22);
    v.push(0x00); // OP_0
    v.push(0x14); // push 20 bytes
    v.extend(hash160);
    v
}

// Detect input type from scriptPubKey
pub fn detect_input_type(script_pubkey: &[u8]) -> &'static str {
    match script_pubkey {
        [0x00, 0x14, ..] => "p2wpkh", // v0 witness
        [0xa9, 0x14, ..] => "p2sh",
        [0x76, 0xa9, 0x14, ..] => "p2pkh",
        _ => "unknown",
    }
}

pub fn create_and_sign(
    utxos_json: &str,
    to_address: &str,
    amount: u64,
    fee: u64,
    wif: &str,
    mainnet: bool,
) -> String {
    let network = if mainnet { Network::Mainnet } else { Network::Testnet };
    let secp = Secp256k1::new();

    let utxos: Vec<UTXO> = serde_json::from_str(utxos_json)
        .expect("invalid UTXO JSON");

    let total_in: u64 = utxos.iter().map(|u| u.amount).sum();
    assert!(total_in >= amount + fee, "insufficient funds");

    let change = total_in - amount - fee;
    let privkey = keys::wif_to_privkey(wif, network);
    let pubkey = keys::privkey_to_pubkey(&privkey);

    // -------- outputs --------
    let mut outputs = Vec::new();
    let mut output_count = 0;

    let to_script = if to_address.starts_with(network.bech32_hrp()) {
        let (_hrp, data, _) = bech32::decode(to_address).expect("invalid bech32");
        let (ver, prog) = data.split_first().expect("invalid witness");
        assert!(ver.to_u8() == 0);
        let prog = Vec::from_base32(prog).expect("invalid bech32 data");
        p2wpkh_script(&prog)
    } else {
        address::address_to_scriptpubkey(to_address, network)
    };

    outputs.extend(utils::u64_le(amount));
    outputs.extend(utils::varint(to_script.len()));
    outputs.extend(to_script);
    output_count += 1;

    // change output (legacy P2PKH)
    if change > 0 {
        let change_script = address::pubkey_to_scriptpubkey(&pubkey, network);
        outputs.extend(utils::u64_le(change));
        outputs.extend(utils::varint(change_script.len()));
        outputs.extend(change_script);
        output_count += 1;
    }

    // -------- transaction header --------
    let has_segwit = utxos.iter().any(|u| u.is_segwit || detect_input_type(&utils::hex_to_bytes(&u.scriptPubKey)) == "p2wpkh");
    let mut tx = Vec::new();
    tx.extend(utils::u32_le(1)); // version

    if has_segwit {
        tx.push(0x00); // marker
        tx.push(0x01); // flag
    }

    tx.extend(utils::varint(utxos.len()));

    let mut witness: Vec<Vec<Vec<u8>>> = vec![vec![]; utxos.len()];

    // -------- inputs --------
    for (i, utxo) in utxos.iter().enumerate() {
        let script_bytes = utils::hex_to_bytes(&utxo.scriptPubKey);
        let input_type = detect_input_type(&script_bytes);

        tx.extend(utils::hex_to_bytes(&utxo.txid).into_iter().rev());
        tx.extend(utils::u32_le(utxo.vout));

        if input_type == "p2wpkh" {
            tx.push(0x00); // empty scriptSig
            tx.extend(utils::u32_le(0xffffffff));

            // BIP143 sighash
            let mut hash_prevouts = Vec::new();
            let mut hash_sequence = Vec::new();
            for u in &utxos {
                hash_prevouts.extend(utils::hex_to_bytes(&u.txid).into_iter().rev());
                hash_prevouts.extend(utils::u32_le(u.vout));
                hash_sequence.extend(utils::u32_le(0xffffffff));
            }

            let hash_prevouts = crypto::double_sha256(&hash_prevouts);
            let hash_sequence = crypto::double_sha256(&hash_sequence);

            let pubkey_hash = &script_bytes[2..22];
            let script_code = address::p2pkh_script(pubkey_hash);

            let mut sighash = Vec::new();
            sighash.extend(utils::u32_le(1));
            sighash.extend(&hash_prevouts);
            sighash.extend(&hash_sequence);
            sighash.extend(utils::hex_to_bytes(&utxo.txid).into_iter().rev());
            sighash.extend(utils::u32_le(utxo.vout));
            sighash.extend(utils::varint(script_code.len()));
            sighash.extend(script_code);
            sighash.extend(utils::u64_le(utxo.amount));
            sighash.extend(utils::u32_le(0xffffffff));
            sighash.extend(utils::varint(output_count));
            sighash.extend(&outputs);
            sighash.extend(utils::u32_le(0));
            sighash.extend(utils::u32_le(1));

            let hash = crypto::double_sha256(&sighash);
            let msg = Message::from_slice(&hash).unwrap();
            let sig = secp.sign_ecdsa(&msg, &privkey);

            let mut sig_der = sig.serialize_der().to_vec();
            sig_der.push(0x01);

            witness[i] = vec![sig_der, pubkey.serialize().to_vec()];
        } else {
            // legacy P2PKH
            tx.push(0x00);
            tx.extend(utils::u32_le(0xffffffff));
        }
    }

    // -------- outputs --------
    tx.extend(utils::varint(output_count));
    tx.extend(&outputs);

    // -------- witness --------
    if has_segwit {
        for w in witness {
            tx.extend(utils::varint(w.len()));
            for item in w {
                tx.extend(utils::varint(item.len()));
                tx.extend(item);
            }
        }
    }

    tx.extend(utils::u32_le(0)); // locktime

    utils::bytes_to_hex(&tx)
}

// -------- helper: build PSBT skeleton --------
pub fn create_psbt_skeleton(utxos_json: &str, to_address: &str, amount: u64, fee: u64, mainnet: bool) -> Vec<u8> {
    let network = if mainnet { Network::Mainnet } else { Network::Testnet };
    let utxos: Vec<UTXO> = serde_json::from_str(utxos_json).unwrap();
    let mut psbt: Vec<u8> = Vec::new();

    // PSBT magic
    psbt.extend(b"psbt\xff");

    // global map placeholder
    // inputs/outputs will be added by external signer
    for _ in &utxos {
        psbt.push(0x00); // dummy input
    }

    let to_script = if to_address.starts_with(network.bech32_hrp()) {
        let (_hrp, data, _) = bech32::decode(to_address).unwrap();
        let (ver, prog) = data.split_first().unwrap();
        let prog = Vec::from_base32(prog).unwrap();
        p2wpkh_script(&prog)
    } else {
        address::address_to_scriptpubkey(to_address, network)
    };

    psbt.push(0x00); // dummy output
    psbt.extend(to_script);

    psbt
}
