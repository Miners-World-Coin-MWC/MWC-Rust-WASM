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

#[wasm_bindgen]
pub fn estimate_fee_from_utxos_wasm(
    utxos_json: &str,
    output_scripts_json: &str,
    sat_per_byte: u64,
) -> u64 {
    let utxos: Vec<tx::UTXO> = serde_json::from_str(utxos_json).expect("invalid UTXO JSON");

    let input_scripts: Vec<String> = utxos.iter().map(|u| u.scriptPubKey.clone()).collect();

    let output_scripts: Vec<String> =
        serde_json::from_str(output_scripts_json).expect("invalid output scripts JSON");

    fees::estimate_fee(&input_scripts, &output_scripts, sat_per_byte)
}

#[wasm_bindgen]
pub struct WasmTxResult {
    raw_tx: String,
    psbt: String,
    vbytes: u64,
    effective_fee: u64,
}

#[wasm_bindgen]
impl WasmTxResult {
    #[wasm_bindgen(getter)]
    pub fn raw_tx(&self) -> String {
        self.raw_tx.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn psbt(&self) -> String {
        self.psbt.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn vbytes(&self) -> u64 {
        self.vbytes
    }

    #[wasm_bindgen(getter)]
    pub fn effective_fee(&self) -> u64 {
        self.effective_fee
    }
}

#[wasm_bindgen]
pub fn create_signed_tx_full(
    utxos_json: &str,
    to_address: &str,
    amount: u64,
    fee: u64,
    wif: &str,
    mainnet: bool,
) -> WasmTxResult {
    let tx_result = tx::create_and_sign(utxos_json, to_address, amount, fee, wif, mainnet);
    WasmTxResult {
        raw_tx: tx_result.raw_tx,
        psbt: tx_result.psbt,
        vbytes: tx_result.vbytes,
        effective_fee: tx_result.effective_fee,
    }
}
