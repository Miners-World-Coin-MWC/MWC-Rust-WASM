use serde::Deserialize;
use secp256k1::{Secp256k1, Message};
use crate::{crypto, utils, keys, address, network::Network};
use bech32::{self, ToBase32};

#[derive(Deserialize)]
pub struct UTXO {
    pub txid: String,
    pub vout: u32,
    pub scriptPubKey: String,
    pub amount: u64,
}

/* -------------------- Script detection -------------------- */
#[derive(Clone, Copy, PartialEq, Eq)]
enum InputType {
    P2PKH,
    P2WPKH,
}

fn detect_input_type(script: &[u8]) -> InputType {
    match script {
        [0x00, 0x14, ..] => InputType::P2WPKH,
        [0x76, 0xa9, 0x14, .., 0x88, 0xac] => InputType::P2PKH,
        _ => InputType::P2PKH,
    }
}

fn dust_threshold() -> u64 {
    546
}

/* -------------------- Return struct -------------------- */
pub struct TxResult {
    pub raw_tx_hex: String,
    pub psbt_hex: String,
    pub vbytes: u64,
    pub effective_fee: u64,
}

/* -------------------- Main TX + PSBT builder -------------------- */
pub fn create_tx_and_psbt(
    utxos_json: &str,
    to_address: &str,
    amount: u64,
    fee: u64,
    wif: &str,
    mainnet: bool,
) -> TxResult {
    let network = if mainnet { Network::Mainnet } else { Network::Testnet };
    let secp = Secp256k1::new();
    let utxos: Vec<UTXO> = serde_json::from_str(utxos_json).expect("invalid UTXO JSON");

    let total_in: u64 = utxos.iter().map(|u| u.amount).sum();
    assert!(total_in >= amount + fee, "insufficient funds");

    let mut change = total_in - amount - fee;
    let privkey = keys::wif_to_privkey(wif, network);
    let pubkey = keys::privkey_to_pubkey(&privkey);
    let pubkey_bytes = pubkey.serialize().to_vec();

    let has_segwit = utxos.iter().any(|u| {
        detect_input_type(&utils::hex_to_bytes(&u.scriptPubKey)) == InputType::P2WPKH
    });

    /* ---------------- Outputs + Change ---------------- */
    let mut outputs = Vec::new();
    let mut output_count = 1;

    let to_script = address::address_to_scriptpubkey(to_address, network);
    outputs.extend(utils::u64_le(amount));
    outputs.extend(utils::varint(to_script.len()));
    outputs.extend(to_script);

    let mut effective_fee = fee;
    let change_output_size = 8 + 1 + 25; // approx P2PKH output
    if change < dust_threshold() || change < (change_output_size as u64 * (fee / amount)) {
        println!("Change ({}) below dust threshold or uneconomical, adding to fee", change);
        effective_fee += change;
        change = 0;
    }

    if change >= dust_threshold() {
        let change_address = address::pubkey_to_address(&pubkey, network);
        let change_script = address::address_to_scriptpubkey(&change_address, network);
        outputs.extend(utils::u64_le(change));
        outputs.extend(utils::varint(change_script.len()));
        outputs.extend(change_script);
        output_count += 1;
    }

    /* ---------------- TX header ---------------- */
    let mut tx = Vec::new();
    tx.extend(utils::u32_le(1));
    if has_segwit {
        tx.extend([0x00, 0x01]);
    }
    tx.extend(utils::varint(utxos.len()));

    /* ---------------- Prepare witnesses / PSBT inputs ---------------- */
    let mut witnesses: Vec<Vec<Vec<u8>>> = vec![vec![]; utxos.len()];
    let mut psbt_global = Vec::new();
    let mut psbt_inputs: Vec<Vec<(u8, Vec<u8>)>> = vec![];

    for (i, utxo) in utxos.iter().enumerate() {
        let script = utils::hex_to_bytes(&utxo.scriptPubKey);
        let input_type = detect_input_type(&script);

        // TX input
        tx.extend(utils::hex_to_bytes(&utxo.txid).into_iter().rev());
        tx.extend(utils::u32_le(utxo.vout));

        match input_type {
            InputType::P2WPKH => {
                tx.push(0x00);
                tx.extend(utils::u32_le(0xffffffff));

                let pubkey_hash = &script[2..22];
                let script_code = address::p2pkh_script(pubkey_hash);

                let sighash = crypto::bip143_sighash(&utxos, i, &script_code, utxo.amount, &outputs);
                let sig = secp.sign_ecdsa(&Message::from_slice(&sighash).unwrap(), &privkey);
                let mut sig_der = sig.serialize_der().to_vec();
                sig_der.push(0x01);

                witnesses[i] = vec![sig_der.clone(), pubkey_bytes.clone()];

                // PSBT input pre-sign
                psbt_inputs.push(vec![
                    (0x00, utils::hex_to_bytes(&utxo.txid)),  // Non-witness utxo placeholder
                    (0x01, sig_der),
                    (0x02, pubkey_bytes.clone()),
                ]);
            }
            InputType::P2PKH => {
                let sighash = crypto::legacy_sighash(&utxos, i, &outputs);
                let sig = secp.sign_ecdsa(&Message::from_slice(&sighash).unwrap(), &privkey);
                let mut sig_der = sig.serialize_der().to_vec();
                sig_der.push(0x01);

                let mut script_sig = Vec::new();
                script_sig.extend(utils::varint(sig_der.len()));
                script_sig.extend(sig_der);
                script_sig.extend(utils::varint(pubkey_bytes.len()));
                script_sig.extend(pubkey_bytes.clone());

                tx.extend(utils::varint(script_sig.len()));
                tx.extend(script_sig);
                tx.extend(utils::u32_le(0xffffffff));

                // PSBT input pre-sign
                psbt_inputs.push(vec![
                    (0x01, sig_der),
                    (0x02, pubkey_bytes.clone()),
                ]);
            }
        }
    }

    /* ---------------- Outputs ---------------- */
    tx.extend(utils::varint(output_count));
    tx.extend(&outputs);

    /* ---------------- Witnesses ---------------- */
    if has_segwit {
        for w in witnesses.iter() {
            tx.extend(utils::varint(w.len()));
            for item in w {
                tx.extend(utils::varint(item.len()));
                tx.extend(item);
            }
        }
    }

    tx.extend(utils::u32_le(0)); // locktime

    /* ---------------- vbytes ---------------- */
    let vbytes = (tx.len() + 3) as u64 / 4;

    /* ---------------- PSBT Serialization ---------------- */
    // Minimal BIP-174 PSBT example
    let mut psbt = vec![0x70, 0x73, 0x62, 0x74, 0xff]; // magic bytes
    psbt.extend(vec![0x01, 0x00]); // PSBT version 0

    // Inputs
    for input in psbt_inputs.iter() {
        for (key, val) in input.iter() {
            psbt.push(*key);
            psbt.extend(utils::varint(val.len()));
            psbt.extend(val);
        }
        psbt.push(0x00); // separator
    }

    // Outputs
    for _ in 0..output_count {
        psbt.push(0x00); // placeholder separator for outputs
    }

    TxResult {
        raw_tx_hex: utils::bytes_to_hex(&tx),
        psbt_hex: utils::bytes_to_hex(&psbt),
        vbytes,
        effective_fee,
    }
}
