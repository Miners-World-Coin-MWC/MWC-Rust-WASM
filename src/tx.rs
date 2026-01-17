use serde::Deserialize;
use secp256k1::{Secp256k1, Message};
use crate::{crypto, utils, keys, address, network::Network};
use bech32::{self, ToBase32};

#[derive(Deserialize)]
pub struct UTXO {
    pub txid: String,
    pub vout: u32,
    pub scriptPubKey: String, // hex
    pub amount: u64,
    pub is_segwit: bool,      // new field for segwit detection
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

    if to_address.starts_with(network.bech32_hrp()) {
        // Bech32 P2WPKH
        let (_hrp, data, _variant) = bech32::decode(to_address).expect("invalid bech32");
        let witness_prog = Vec::from_base32(&data).expect("invalid bech32 data");
        outputs.extend(utils::u64_le(amount));
        outputs.extend(utils::varint(2 + witness_prog.len())); // 0x00 OP_PUSH_LEN <hash>
        outputs.push(0x00); // version 0
        outputs.push(witness_prog.len() as u8);
        outputs.extend(&witness_prog);
    } else {
        let to_script = address::address_to_scriptpubkey(to_address, network);
        outputs.extend(utils::u64_le(amount));
        outputs.extend(utils::varint(to_script.len()));
        outputs.extend(to_script);
    }

    // change output (always legacy P2PKH)
    if change > 0 {
        let change_script = address::pubkey_to_scriptpubkey(&pubkey, network);
        outputs.extend(utils::u64_le(change));
        outputs.extend(utils::varint(change_script.len()));
        outputs.extend(change_script);
    }

    // -------- build & sign inputs --------
    let mut final_tx = Vec::new();
    final_tx.extend(utils::u32_le(1)); // version
    final_tx.extend(utils::varint(utxos.len()));

    for (i, utxo) in utxos.iter().enumerate() {
        let mut sighash_tx = Vec::new();

        if utxo.is_segwit {
            // BIP143 SegWit sighash
            let mut hash_prevouts = Vec::new();
            let mut hash_sequence = Vec::new();
            for u in &utxos {
                hash_prevouts.extend(utils::hex_to_bytes(&u.txid).into_iter().rev());
                hash_prevouts.extend(utils::u32_le(u.vout));
                hash_sequence.extend(utils::u32_le(0xffffffff));
            }
            let hash_prevouts = crypto::double_sha256(&hash_prevouts);
            let hash_sequence = crypto::double_sha256(&hash_sequence);

            sighash_tx.extend(utils::u32_le(1)); // version
            sighash_tx.extend(&hash_prevouts);
            sighash_tx.extend(&hash_sequence);
            sighash_tx.extend(utils::hex_to_bytes(&utxo.txid).into_iter().rev());
            sighash_tx.extend(utils::u32_le(utxo.vout));

            let script_code = utils::hex_to_bytes(&utxo.scriptPubKey);
            sighash_tx.extend(utils::varint(script_code.len()));
            sighash_tx.extend(script_code);

            sighash_tx.extend(utils::u64_le(utxo.amount));
            sighash_tx.extend(utils::u32_le(0xffffffff)); // sequence

            // outputs
            sighash_tx.extend(&outputs);
            sighash_tx.extend(utils::u32_le(0)); // locktime
            sighash_tx.extend(utils::u32_le(1)); // SIGHASH_ALL

            let hash = crypto::double_sha256(&sighash_tx);
            let msg = Message::from_slice(&hash).unwrap();
            let sig = secp.sign_ecdsa(&msg, &privkey);

            let mut sig_der = sig.serialize_der().to_vec();
            sig_der.push(0x01); // SIGHASH_ALL

            let mut script_sig = Vec::new();
            script_sig.push(sig_der.len() as u8);
            script_sig.extend(sig_der);
            script_sig.push(33);
            script_sig.extend(pubkey.serialize());

            // final input
            final_tx.extend(utils::hex_to_bytes(&utxo.txid).into_iter().rev());
            final_tx.extend(utils::u32_le(utxo.vout));
            final_tx.extend(utils::varint(script_sig.len()));
            final_tx.extend(script_sig);
            final_tx.extend(utils::u32_le(0xffffffff));

        } else {
            // legacy signing (unchanged from your previous code)
            sighash_tx.extend(utils::u32_le(1));
            sighash_tx.extend(utils::varint(utxos.len()));
            for (j, other) in utxos.iter().enumerate() {
                sighash_tx.extend(utils::hex_to_bytes(&other.txid).into_iter().rev());
                sighash_tx.extend(utils::u32_le(other.vout));
                if i == j {
                    let prev_script = utils::hex_to_bytes(&other.scriptPubKey);
                    sighash_tx.extend(utils::varint(prev_script.len()));
                    sighash_tx.extend(prev_script);
                } else {
                    sighash_tx.push(0x00);
                }
                sighash_tx.extend(utils::u32_le(0xffffffff));
            }
            sighash_tx.extend(utils::varint(if change > 0 { 2 } else { 1 }));
            sighash_tx.extend(&outputs);
            sighash_tx.extend(utils::u32_le(0));
            sighash_tx.extend(utils::u32_le(1));

            let hash = crypto::double_sha256(&sighash_tx);
            let msg = Message::from_slice(&hash).unwrap();
            let sig = secp.sign_ecdsa(&msg, &privkey);

            let mut sig_der = sig.serialize_der().to_vec();
            sig_der.push(0x01);

            let mut script_sig = Vec::new();
            script_sig.push(sig_der.len() as u8);
            script_sig.extend(sig_der);
            script_sig.push(33);
            script_sig.extend(pubkey.serialize());

            final_tx.extend(utils::hex_to_bytes(&utxo.txid).into_iter().rev());
            final_tx.extend(utils::u32_le(utxo.vout));
            final_tx.extend(utils::varint(script_sig.len()));
            final_tx.extend(script_sig);
            final_tx.extend(utils::u32_le(0xffffffff));
        }
    }

    final_tx.extend(utils::varint(if change > 0 { 2 } else { 1 }));
    final_tx.extend(outputs);
    final_tx.extend(utils::u32_le(0)); // locktime

    utils::bytes_to_hex(&final_tx)
}
