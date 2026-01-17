use hex;
use std::collections::HashMap;

/// Supported script types
#[derive(Debug, Clone, Copy)]
pub enum ScriptType {
    P2PKH,
    P2SH,
    P2WPKH,
}

/// Detect input type from scriptPubKey hex
pub fn detect_input_type(script_hex: &str) -> ScriptType {
    let bytes = hex::decode(script_hex).unwrap_or_default();
    match bytes.as_slice() {
        [0x00, 0x14, ..] => ScriptType::P2WPKH,      // native SegWit v0
        [0xa9, 0x14, ..] => ScriptType::P2SH,        // P2SH
        [0x76, 0xa9, 0x14, ..] => ScriptType::P2PKH, // legacy
        _ => ScriptType::P2PKH,
    }
}

/// Detect output type from scriptPubKey hex
pub fn detect_output_type(script_hex: &str) -> ScriptType {
    let bytes = hex::decode(script_hex).unwrap_or_default();
    match bytes.as_slice() {
        [0x00, 0x14, ..] => ScriptType::P2WPKH,
        [0xa9, 0x14, ..] => ScriptType::P2SH,
        [0x76, 0xa9, 0x14, ..] => ScriptType::P2PKH,
        _ => ScriptType::P2PKH,
    }
}

/// Estimate transaction fee in satoshis using **true weight / vbytes**
/// - `input_scripts` = Vec of input scriptPubKeys (hex)
/// - `output_scripts` = Vec of output scriptPubKeys (hex)
/// - `sat_per_byte` = satoshis per virtual byte
pub fn estimate_fee(
    input_scripts: &[String],
    output_scripts: &[String],
    sat_per_byte: u64,
) -> u64 {
    let mut total_weight: usize = 0;

    // ---- inputs ----
    for script in input_scripts {
        match detect_input_type(script) {
            ScriptType::P2PKH => total_weight += 148 * 4,
            ScriptType::P2SH => total_weight += 91 * 4,           // P2SH-wrapped segwit
            ScriptType::P2WPKH => total_weight += 68 * 4 + 107,   // base * 4 + witness
        }
    }

    // ---- outputs ----
    for script in output_scripts {
        match detect_output_type(script) {
            ScriptType::P2PKH => total_weight += 34 * 4,
            ScriptType::P2SH => total_weight += 32 * 4,
            ScriptType::P2WPKH => total_weight += 31 * 4,
        }
    }

    // ---- base tx overhead: version + locktime + varints (~10 vbytes) ----
    total_weight += 10 * 4;

    // ---- convert to vbytes ----
    let vbytes = (total_weight + 3) / 4; // round up
    vbytes as u64 * sat_per_byte
}

/// ----- PSBT Skeleton (v0) -----
/// Returns a basic PSBT map with input/output info. Can be extended for signing.
pub fn psbt_skeleton(
    input_scripts: &[String],
    output_scripts: &[String],
) -> HashMap<String, Vec<String>> {
    let mut psbt: HashMap<String, Vec<String>> = HashMap::new();
    psbt.insert(
        "inputs".to_string(),
        input_scripts.iter().map(|s| s.clone()).collect(),
    );
    psbt.insert(
        "outputs".to_string(),
        output_scripts.iter().map(|s| s.clone()).collect(),
    );
    psbt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_detect_fee() {
        let inputs = vec![
            "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88".to_string(), // P2PKH
            "001489abcdefabbaabbaabbaabbaabbaabbaabbaabba".to_string(),     // P2WPKH
        ];
        let outputs = vec![
            "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88".to_string(), // P2PKH
            "001489abcdefabbaabbaabbaabbaabbaabbaabbaabba".to_string(),     // P2WPKH
        ];
        let fee = estimate_fee(&inputs, &outputs, 50);
        println!("Estimated fee: {} sats", fee);
        assert!(fee > 0);
    }

    #[test]
    fn test_psbt_skeleton() {
        let inputs = vec![
            "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88".to_string(),
        ];
        let outputs = vec![
            "001489abcdefabbaabbaabbaabbaabbaabbaabbaabba".to_string(),
        ];
        let psbt = psbt_skeleton(&inputs, &outputs);
        assert_eq!(psbt["inputs"].len(), 1);
        assert_eq!(psbt["outputs"].len(), 1);
    }
}
