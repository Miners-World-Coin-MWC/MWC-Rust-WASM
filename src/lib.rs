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

    // Use the new pubkey_to_bech32 function from address.rs
    address::pubkey_to_bech32(&pubkey, net.bech32_hrp())
}

#[wasm_bindgen]
pub fn validate_address(addr: &str, mainnet: bool) -> bool {
    address::validate_address(addr, if mainnet { Network::Mainnet } else { Network::Testnet })
}

/// Estimate fee with input type support: "p2pkh", "p2sh", "p2wpkh"
#[wasm_bindgen]
pub fn estimate_fee_wasm(
    inputs: usize,
    outputs: usize,
    sat_per_byte: u64,
    input_type: &str
) -> u64 {
    fees::estimate_fee(inputs, outputs, sat_per_byte, input_type)
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
