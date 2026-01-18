use crate::tx::UTXO;
use crate::utils;

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

// --------
// Hashing helpers
// --------

pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

pub fn double_sha256(data: &[u8]) -> Vec<u8> {
    sha256(&sha256(data))
}

pub fn hash160(data: &[u8]) -> Vec<u8> {
    let sha = sha256(data);
    Ripemd160::digest(&sha).to_vec()
}

pub fn checksum(data: &[u8]) -> Vec<u8> {
    double_sha256(data)[0..4].to_vec()
}

// --------
// Sighash implementations
// --------

// Legacy sighash (pre-SegWit)
pub fn legacy_sighash(utxos: &[UTXO], input_index: usize, outputs_serialized: &[u8]) -> Vec<u8> {
    let mut tx = Vec::new();
    tx.extend(utils::u32_le(1)); // version
    tx.extend(utils::varint(utxos.len()));

    for (i, u) in utxos.iter().enumerate() {
        tx.extend(utils::hex_to_bytes(&u.txid).into_iter().rev());
        tx.extend(utils::u32_le(u.vout));

        if i == input_index {
            let script = utils::hex_to_bytes(&u.scriptPubKey);
            tx.extend(utils::varint(script.len()));
            tx.extend(script);
        } else {
            tx.push(0x00);
        }

        tx.extend(utils::u32_le(0xffffffff));
    }

    // outputs
    tx.extend(outputs_serialized);

    tx.extend(utils::u32_le(0)); // locktime
    tx.extend(utils::u32_le(1)); // SIGHASH_ALL

    double_sha256(&tx)
}

// BIP143 SegWit v0 sighash
pub fn bip143_sighash(
    utxos: &[UTXO],
    input_index: usize,
    script_code: &[u8],
    amount: u64,
    outputs_serialized: &[u8],
) -> Vec<u8> {
    let mut hash_prevouts = Vec::new();
    let mut hash_sequence = Vec::new();

    for u in utxos {
        hash_prevouts.extend(utils::hex_to_bytes(&u.txid).into_iter().rev());
        hash_prevouts.extend(utils::u32_le(u.vout));
        hash_sequence.extend(utils::u32_le(0xffffffff));
    }

    let hash_prevouts = double_sha256(&hash_prevouts);
    let hash_sequence = double_sha256(&hash_sequence);

    let utxo = &utxos[input_index];

    let mut sighash = Vec::new();
    sighash.extend(utils::u32_le(1)); // version
    sighash.extend(&hash_prevouts);
    sighash.extend(&hash_sequence);

    // outpoint
    sighash.extend(utils::hex_to_bytes(&utxo.txid).into_iter().rev());
    sighash.extend(utils::u32_le(utxo.vout));

    // scriptCode
    sighash.extend(utils::varint(script_code.len()));
    sighash.extend(script_code);

    // amount
    sighash.extend(utils::u64_le(amount));

    // sequence
    sighash.extend(utils::u32_le(0xffffffff));

    // outputs
    sighash.extend(outputs_serialized);

    // locktime + sighash type
    sighash.extend(utils::u32_le(0)); // locktime
    sighash.extend(utils::u32_le(1)); // SIGHASH_ALL

    double_sha256(&sighash)
}
