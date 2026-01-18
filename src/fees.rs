use hex;

// Supported script types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptType {
    P2pkh,
    P2shP2wpkh, // wrapped segwit
    P2wpkh,
}

// Detect script type from scriptPubKey hex
pub fn detect_script_type(script_hex: &str) -> ScriptType {
    let bytes = match hex::decode(script_hex) {
        Ok(b) => b,
        Err(_) => return ScriptType::P2pkh, // safe fallback
    };

    match bytes.as_slice() {
        // P2WPKH: OP_0 <20-byte>
        [0x00, 0x14, ..] => ScriptType::P2wpkh,

        // P2SH-P2WPKH: OP_HASH160 <20-byte> OP_EQUAL
        [0xa9, 0x14, .., 0x87] => ScriptType::P2shP2wpkh,

        // P2PKH: OP_DUP OP_HASH160 <20-byte> OP_EQUALVERIFY OP_CHECKSIG
        [0x76, 0xa9, 0x14, .., 0x88, 0xac] => ScriptType::P2pkh,

        _ => ScriptType::P2pkh,
    }
}

// Estimate transaction fee using **true BIP-141 weight units**
//
// Returns **fee in satoshis**
pub fn estimate_fee(
    input_scripts: &[String],
    output_scripts: &[String],
    sat_per_vbyte: u64,
) -> u64 {
    let mut total_weight: usize = 0;

    // ------------------------------------------------------------------
    // INPUTS
    // ------------------------------------------------------------------
    for script in input_scripts {
        match detect_script_type(script) {
            // Legacy P2PKH input
            ScriptType::P2pkh => {
                total_weight += 148 * 4;
            }

            // P2SH-P2WPKH input
            ScriptType::P2shP2wpkh => {
                total_weight += (64 * 4) + 107;
            }

            // Native P2WPKH input
            ScriptType::P2wpkh => {
                total_weight += (41 * 4) + 107;
            }
        }
    }

    // ------------------------------------------------------------------
    // OUTPUTS
    // ------------------------------------------------------------------
    for script in output_scripts {
        match detect_script_type(script) {
            ScriptType::P2pkh => total_weight += 34 * 4,
            ScriptType::P2shP2wpkh => total_weight += 32 * 4,
            ScriptType::P2wpkh => total_weight += 31 * 4,
        }
    }

    // ------------------------------------------------------------------
    // TX OVERHEAD
    // ------------------------------------------------------------------
    total_weight += 10 * 4;

    // Convert weight → vbytes (round up)
    let vbytes = (total_weight + 3) / 4;

    vbytes as u64 * sat_per_vbyte
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_detect_fee() {
        let inputs = vec![
            "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac".to_string(),
            "001489abcdefabbaabbaabbaabbaabbaabbaabbaabba".to_string(),
        ];

        let outputs = vec!["001489abcdefabbaabbaabbaabbaabbaabbaabbaabba".to_string()];

        let fee = estimate_fee(&inputs, &outputs, 50);
        assert!(fee > 0);
    }
}
