use wasm_bindgen::prelude::*;

mod keys;
mod address;
mod tx;
mod crypto;
mod utils;

#[wasm_bindgen]
pub fn generate_wif() -> String {
    keys::generate_wif()
}

#[wasm_bindgen]
pub fn wif_to_address(wif: &str) -> String {
    let privkey = keys::wif_to_privkey(wif);
    let pubkey = keys::privkey_to_pubkey(&privkey);
    address::pubkey_to_address(&pubkey)
}

#[wasm_bindgen]
pub fn create_signed_tx(
    utxos_json: &str,
    to_address: &str,
    amount: u64,
    fee: u64,
    wif: &str,
) -> String {
    tx::create_and_sign(utxos_json, to_address, amount, fee, wif)
}
