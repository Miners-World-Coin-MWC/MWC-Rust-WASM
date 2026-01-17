use serde::Deserialize;
use secp256k1::{Secp256k1, Message};
use crate::{crypto, utils, keys, address};

#[derive(Deserialize)]
pub struct UTXO {
    pub txid: String,
    pub vout: u32,
    pub scriptPubKey: String, // hex
    pub amount: u64,
}

pub fn create_and_sign(
    utxos_json: &str,
    to_address: &str,
    amount: u64,
    fee: u64,
    wif: &str,
) -> String {
    let utxos: Vec<UTXO> = serde_json::from_str(utxos_json)
        .expect("invalid UTXO JSON");

    let total_in: u64 = utxos.iter().map(|u| u.amount).sum();
    assert!(total_in >= amount + fee, "insufficient funds");

    let change = total_in - amount - fee;

    let privkey = keys::wif_to_privkey(wif);
    let pubkey = keys::privkey_to_pubkey(&privkey);
    let secp = Secp256k1::new();

    // -------- outputs --------
    let mut outputs = Vec::new();

    // main output
    outputs.extend(utils::u64_le(amount));
    let to_script = address::address_to_scriptpubkey(to_address);
    outputs.extend(utils::varint(to_script.len()));
    outputs.extend(to_script);

    // change output
    if change > 0 {
        outputs.extend(utils::u64_le(change));
        let change_script = address::pubkey_to_scriptpubkey(&pubkey);
        outputs.extend(utils::varint(change_script.len()));
        outputs.extend(change_script);
    }

    // -------- build & sign inputs --------
    let mut final_tx = Vec::new();

    // version
    final_tx.extend(utils::u32_le(1));

    // input count
    final_tx.extend(utils::varint(utxos.len()));

    for (i, utxo) in utxos.iter().enumerate() {
        // ---------- sighash tx ----------
        let mut sighash_tx = Vec::new();
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

        sighash_tx.extend(utils::varint(
            if change > 0 { 2 } else { 1 }
        ));
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

        // ---------- final tx input ----------
        final_tx.extend(utils::hex_to_bytes(&utxo.txid).into_iter().rev());
        final_tx.extend(utils::u32_le(utxo.vout));
        final_tx.extend(utils::varint(script_sig.len()));
        final_tx.extend(script_sig);
        final_tx.extend(utils::u32_le(0xffffffff));
    }

    // outputs
    final_tx.extend(utils::varint(
        if change > 0 { 2 } else { 1 }
    ));
    final_tx.extend(outputs);

    // locktime
    final_tx.extend(utils::u32_le(0));

    utils::bytes_to_hex(&final_tx)
}
