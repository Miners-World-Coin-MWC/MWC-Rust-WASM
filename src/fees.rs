use crate::network::Network;

/// Estimate transaction fee in satoshis
/// `inputs` = number of inputs
/// `outputs` = number of outputs
/// `sat_per_byte` = satoshis per byte
/// `input_type` = "p2pkh", "p2sh", "p2wpkh"
pub fn estimate_fee(inputs: usize, outputs: usize, sat_per_byte: u64, input_type: &str) -> u64 {
    // base tx size: version (4) + locktime (4) + varints for input/output count (~2 each)
    let base_size = 4 + 4 + 2 + 2; // 12 bytes approx

    // input size depends on type
    let input_size = match input_type {
        "p2pkh" => 148,  // legacy
        "p2sh" => 91,    // P2SH-wrapped SegWit (average)
        "p2wpkh" => 68,  // native SegWit input
        _ => 148,        // default to legacy
    };

    // output size depends on type (we assume standard P2PKH/P2SH, Bech32 ~31 bytes)
    let output_size = 34; // tweak if needed for Bech32/P2SH outputs

    let tx_size = base_size + inputs * input_size + outputs * output_size;

    tx_size as u64 * sat_per_byte
}
