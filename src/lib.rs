use wasm_bindgen::prelude::*;
use crate::network::Network;

mod keys;
mod address;
mod tx;
mod crypto;
mod utils;
mod network;
mod fees;

#[wasm_bindgen]
pub fn generate_wif(mainnet: bool) -> String {
    keys::generate_wif(if mainnet { Network::Mainnet } else { Network::Testnet })
}

#[wasm_bindgen]
pub fn wif_to_address(wif: &str, mainnet: bool) -> String {
    let net = if mainnet { Network::Mainnet } else { Network::Testnet };
    let privkey = keys::wif_to_privkey(wif, net);
    let pubkey = keys::privkey_to_pubkey(&privkey);
    address::pubkey_to_address(&pubkey, net)
}

#[wasm_bindgen]
pub fn pubkey_to_bech32_wasm(wif: &str, mainnet: bool) -> String {
    let net = if mainnet { Network::Mainnet } else { Network::Testnet };
    let privkey = keys::wif_to_privkey(wif, net);
    let pubkey = keys::privkey_to_pubkey(&privkey);

    address::pubkey_to_bech32(&pubkey, net.bech32_hrp())
}

#[wasm_bindgen]
pub fn validate_address(addr: &str, mainnet: bool) -> bool {
    address::validate_address(addr, if mainnet { Network::Mainnet } else { Network::Testnet })
}

/// Legacy fee estimator: by input type
#[wasm_bindgen]
pub fn estimate_fee_wasm(
    inputs: usize,
    outputs: usize,
    sat_per_byte: u64,
    input_type: &str
) -> u64 {
    fees::estimate_fee(inputs, outputs, sat_per_byte, input_type)
}

/// Auto-detect input types from UTXOs JSON and compute true fee (vbytes)
#[wasm_bindgen]
pub fn estimate_fee_from_utxos_wasm(
    utxos_json: &str,
    outputs: usize,
    sat_per_byte: u64
) -> u64 {
    let utxos: Vec<tx::UTXO> = serde_json::from_str(utxos_json).expect("invalid UTXO JSON");

    fees::estimate_fee_from_utxos(&utxos, outputs, sat_per_byte)
}

#[wasm_bindgen]
pub fn create_signed_tx(
    utxos_json: &str,
    to_address: &str,
    amount: u64,
    fee: u64,
    wif: &str,
    mainnet: bool
) -> String {
    tx::create_and_sign(utxos_json, to_address, amount, fee, wif, mainnet)
}
