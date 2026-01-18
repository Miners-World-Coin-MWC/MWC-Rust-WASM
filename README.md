# Wallet Core – PSBT & Raw Transaction Support

## Overview

This project provides a **UTXO-based wallet core** with **first-class PSBT (BIP-174) support**, designed for both **software and hardware wallet interoperability**.

Key design goals:
- Clean separation between **transaction construction**, **signing**, and **broadcasting**
- Support for **air-gapped / hardware wallet workflows**
- Compatibility with **Bitcoin-style UTXO chains** (SegWit & legacy)
- Deterministic, inspectable, and auditable transactions

The wallet accepts **either raw transaction hex or PSBT hex**, making it flexible for advanced signing flows and external tools.

---

## Features

- ✅ Raw transaction (hex) parsing & handling
- ✅ PSBT parsing, merging, and finalization
- ✅ Pre-sign inputs by default (configurable)
- ✅ Mixed signing support (partial + external)
- ✅ SegWit-aware size & fee handling
- ✅ Hardware-wallet-friendly architecture
- ✅ Clean Rust utility layer (`utils.rs`)

---

## Input Formats

### 1. Raw Transaction Hex

Used when:
- The wallet controls all private keys
- Full signing is done internally
- No external signer is required

Example:
```
0200000001...
```

### 2. PSBT Hex (BIP-174)

Used when:
- Hardware wallets are involved
- Multi-sig or multi-party signing is required
- Offline or air-gapped signing is desired

Example:
```
70736274ff0100...
```

The wallet will:
- Detect PSBT automatically
- Pre-sign inputs it controls
- Leave remaining inputs untouched
- Allow merging and finalization later

---

## Default Signing Behaviour

By default:
- Inputs controlled by the wallet **are pre-signed**
- External or unknown inputs remain unsigned
- Resulting PSBT can be:
  - Exported
  - Merged
  - Finalized
  - Converted to raw tx

This makes the wallet **hardware-wallet safe by default**.

---

## Utility Functions

The wallet uses a small, auditable utility layer:

```rust
pub fn hex_to_bytes(s: &str) -> Vec<u8>
pub fn bytes_to_hex(b: &[u8]) -> String
pub fn u32_le(n: u32) -> [u8; 4]
pub fn u64_le(n: u64) -> [u8; 8]
pub fn varint(n: usize) -> Vec<u8>
```

These are used consistently across:
- Transaction serialization
- PSBT encoding/decoding
- Script and witness building

---

## Hardware Wallet Compatibility

| Hardware Wallet | PSBT Support | SegWit | Notes |
|-----------------|-------------|--------|-------|
| Ledger (Nano S/X) | ✅ Yes | ✅ Yes | Requires Bitcoin app |
| Trezor One | ✅ Yes | ⚠️ Partial | Limited SegWit v1 |
| Trezor Model T | ✅ Yes | ✅ Yes | Full PSBT support |
| Coldcard | ✅ Yes | ✅ Yes | Air-gapped PSBT workflow |
| BitBox02 | ✅ Yes | ✅ Yes | Excellent PSBT UX |
| Keystone | ✅ Yes | ✅ Yes | QR-based signing |
| Passport | ✅ Yes | ✅ Yes | Air-gapped focused |
| Jade | ✅ Yes | ✅ Yes | USB / QR signing |

> Any device supporting **BIP-174 PSBT** will work with this wallet.

---

## Typical Workflows

### Software-Only Wallet
1. Build transaction
2. Sign all inputs
3. Broadcast raw hex

### Hardware Wallet
1. Build PSBT
2. Pre-sign known inputs
3. Export PSBT
4. Sign on hardware wallet
5. Merge + finalize
6. Broadcast

### Multi-Sig
1. Build base PSBT
2. Distribute to signers
3. Merge signatures
4. Finalize & broadcast

---

## Security Notes

- No private keys are required for PSBT parsing
- Signing is isolated per input
- No hidden signing or mutation of external inputs
- Fully deterministic serialization

---

## Status

🚧 **Active Development**  
PSBT support is considered **core infrastructure**, not an add-on.

Upcoming:
- PSBT v2 (BIP-370)
- Descriptor-based wallets
- True vbyte fee calculation
- Advanced coin selection

---

## License

MIT / Apache-2.0 (project dependent)
