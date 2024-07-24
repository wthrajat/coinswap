//! Keychain Enum & related API

use serde::{Deserialize, Serialize};

/// Derivation Path from master to Account no i.e 0' by default.
pub const HARDENED_DERIVATION: &str = "m/84'/1'/0'";

/// Types of keychains
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy, Serialize, Deserialize)]
pub enum Keychain {
    /// External: Derives recipient addresses.
    External,
    /// Internal: Derives change addresses.
    Internal,
    /// Fidelity: Generates keypair for fidelity bonds.
    Fidelity { count: u32 },
    /// SwapCoin: Generates keypair of 2-of-2 multisig in funding transations.
    SwapCoin { count: u32 },
    /// Contract: Generates Keypair for hashlock and timelock transactions.
    Contract { count: u32 },
}

impl Keychain {
    /// Specify the keychain derivation path from [`HARDENDED_DERIVATION`]
    fn index_num(&self) -> u32 {
        match self {
            Self::External => 0,
            Self::Internal => 1,
            Self::Fidelity { .. } => 2,
            Self::SwapCoin { .. } => 3,
            Self::Contract { .. } => 4,
        }
    }

    // returns path of given keychain.
    pub fn path(&self) -> String {
        let keychain_type = match self {
            Keychain::External => String::from("0"),
            Keychain::Internal => String::from("1"),
            Keychain::Fidelity { count } => format!("2/{}", count),
            Keychain::SwapCoin { count } => format!("3/{}", count),
            Keychain::Contract { count } => format!("4/{}", count),
        };

        format!("{}/{}", HARDENED_DERIVATION, keychain_type)
    }
}
