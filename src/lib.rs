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
pub fn validate_address(addr: &str, mainnet: bool) -> bool {
    address::validate_address(addr, if mainnet { Network::Mainnet } else { Network::Testnet })
}

#[wasm_bindgen]
pub fn estimate_fee(inputs: usize, outputs: usize, sat_per_byte: u64) -> u64 {
    fees::estimate_fee(inputs, outputs, sat_per_byte)
}
