#[derive(Clone, Copy)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub fn p2pkh_prefix(self) -> u8 {
        match self {
            Network::Mainnet => 0x14,
            Network::Testnet => 0x53,
        }
    }

    pub fn p2sh_prefix(self) -> u8 {
        match self {
            Network::Mainnet => 0x0A,
            Network::Testnet => 0xC5,
        }
    }

    pub fn wif_prefix(self) -> u8 {
        match self {
            Network::Mainnet => 0x7B,
            Network::Testnet => 0xF0,
        }
    }

    pub fn bech32_hrp(self) -> &'static str {
        match self {
            Network::Mainnet => "mwc",
            Network::Testnet => "tmwc",
        }
    }
}
