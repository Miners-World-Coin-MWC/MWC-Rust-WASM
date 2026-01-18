use crate::network::Network;
use wasm_bindgen::prelude::*;

mod address;
mod crypto;
mod fees;
mod keys;
mod network;
mod tx;
mod utils;

#[wasm_bindgen]
pub fn generate_wif(mainnet: bool) -> String {
    keys::generate_wif(if mainnet {
        Network::Mainnet
    } else {
        Network::Testnet
    })
}

#[wasm_bindgen]
pub fn wif_to_address(wif: &str, mainnet: bool) -> String {
    let net = if mainnet {
        Network::Mainnet
    } else {
        Network::Testnet
    };

    let privkey = keys::wif_to_privkey(wif, net);
    let pubkey = keys::privkey_to_pubkey(&privkey);
    address::pubkey_to_address(&pubkey, net)
}

#[wasm_bindgen]
pub fn pubkey_to_bech32_wasm(wif: &str, mainnet: bool) -> String {
    let net = if mainnet {
        Network::Mainnet
    } else {
        Network::Testnet
    };

    let privkey = keys::wif_to_privkey(wif, net);
    let pubkey = keys::privkey_to_pubkey(&privkey);
    address::pubkey_to_bech32(&pubkey, net.bech32_hrp())
}

#[wasm_bindgen]
pub fn validate_address(addr: &str, mainnet: bool) -> bool {
    address::validate_address(
        addr,
        if mainnet {
            Network::Mainnet
        } else {
            Network::Testnet
        },
    )
}

// ----------------------------------------------------------------------
// TRUE WEIGHT / VBYTES FEE ESTIMATION (AUTO-DETECTED)
// ----------------------------------------------------------------------
#[wasm_bindgen]
pub fn estimate_fee_wasm(
    input_scripts_json: &str,
    output_scripts_json: &str,
    sat_per_byte: u64,
) -> u64 {
    let input_scripts: Vec<String> =
        serde_json::from_str(input_scripts_json).expect("invalid input scripts JSON");

    let output_scripts: Vec<String> =
        serde_json::from_str(output_scripts_json).expect("invalid output scripts JSON");

    fees::estimate_fee(&input_scripts, &output_scripts, sat_per_byte)
}

// ----------------------------------------------------------------------
// FEE ESTIMATION DIRECTLY FROM UTXOS JSON
// ----------------------------------------------------------------------
#[wasm_bindgen]
pub fn estimate_fee_from_utxos_wasm(
    utxos_json: &str,
    output_scripts_json: &str,
    sat_per_byte: u64,
) -> u64 {
    let utxos: Vec<tx::UTXO> = serde_json::from_str(utxos_json).expect("invalid UTXO JSON");

    let input_scripts: Vec<String> =
        utxos.iter().map(|u| u.scriptPubKey.clone()).collect();

    let output_scripts: Vec<String> =
        serde_json::from_str(output_scripts_json).expect("invalid output scripts JSON");

    fees::estimate_fee(&input_scripts, &output_scripts, sat_per_byte)
}

#[wasm_bindgen]
pub fn create_signed_tx(
    utxos_json: &str,
    to_address: &str,
    amount: u64,
    fee: u64,
    wif: &str,
    mainnet: bool,
) -> String {
    tx::create_and_sign(utxos_json, to_address, amount, fee, wif, mainnet)
}
