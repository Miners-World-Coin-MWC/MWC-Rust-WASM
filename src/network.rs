#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    /// P2PKH Base58 prefix
    pub fn p2pkh_prefix(self) -> u8 {
        match self {
            Network::Mainnet => 0x14, // MWC mainnet P2PKH
            Network::Testnet => 0x53, // MWC testnet P2PKH
        }
    }

    /// P2SH Base58 prefix
    pub fn p2sh_prefix(self) -> u8 {
        match self {
            Network::Mainnet => 0x0A, // MWC mainnet P2SH
            Network::Testnet => 0xC5, // MWC testnet P2SH
        }
    }

    /// WIF private key prefix
    pub fn wif_prefix(self) -> u8 {
        match self {
            Network::Mainnet => 0x7B, // MWC mainnet WIF
            Network::Testnet => 0xF0, // MWC testnet WIF
        }
    }

    /// Bech32 HRP (SegWit v0+)
    pub fn bech32_hrp(self) -> &'static str {
        match self {
            Network::Mainnet => "mwc",
            Network::Testnet => "tmwc",
        }
    }

    /// Return true if HRP matches this network
    pub fn matches_bech32(self, addr: &str) -> bool {
        addr.starts_with(self.bech32_hrp())
    }
}
