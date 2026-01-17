pub fn estimate_fee(inputs: usize, outputs: usize, sat_per_byte: u64) -> u64 {
    let tx_size =
        10 +            // base
        inputs * 148 +  // P2PKH input
        outputs * 34;   // P2PKH output

    tx_size as u64 * sat_per_byte
}
