//! All Wallet-related errors.

/// Enum for handling wallet-related errors.
#[derive(Debug)]
pub enum WalletError {
    /// The error type for I/O operations and associated traits
    File(std::io::Error),
    /// Errors that can occur when serializing or deserializing CBOR data.
    Cbor(serde_cbor::Error),
    /// Errors that can occur when interacting with the Bitcoin Core RPC.
    Rpc(bitcoind::bitcoincore_rpc::Error),
    /// Protocol related error.
    Protocol(String),
    /// Errors that can occur when working with BIP32 keys.
    BIP32(bitcoin::bip32::Error),
    /// Errors that can occur when working with BIP39 mnemonics.
    BIP39(bip39::Error),
    /// Errors that can occur when working with contracts.
    Contract(crate::protocol::error::ContractError),
    /// Errors that can occur when working with fidelity.
    Fidelity(crate::wallet::FidelityError),
    /// An error that occurs when converting a `u32` to a lock time variant.
    Locktime(bitcoin::blockdata::locktime::absolute::ConversionError),
    /// Errors that can occur when working with the secp256k1 elliptic curve.
    Secp(bitcoin::secp256k1::Error),
    /// Errors that can occur when working with BDK.
    BDKErrors(crate::wallet::bdk_wallet::error::BDKErrors),
}

/// Implementations for Wallet Errors.
impl From<std::io::Error> for WalletError {
    fn from(value: std::io::Error) -> Self {
        Self::File(value)
    }
}

impl From<serde_cbor::Error> for WalletError {
    fn from(value: serde_cbor::Error) -> Self {
        Self::Cbor(value)
    }
}

impl From<bitcoind::bitcoincore_rpc::Error> for WalletError {
    fn from(value: bitcoind::bitcoincore_rpc::Error) -> Self {
        Self::Rpc(value)
    }
}

impl From<bitcoin::bip32::Error> for WalletError {
    fn from(value: bitcoin::bip32::Error) -> Self {
        Self::BIP32(value)
    }
}

impl From<bip39::Error> for WalletError {
    fn from(value: bip39::Error) -> Self {
        Self::BIP39(value)
    }
}

impl From<crate::protocol::error::ContractError> for WalletError {
    fn from(value: crate::protocol::error::ContractError) -> Self {
        Self::Contract(value)
    }
}

impl From<crate::wallet::FidelityError> for WalletError {
    fn from(value: crate::wallet::FidelityError) -> Self {
        Self::Fidelity(value)
    }
}

impl From<bitcoin::blockdata::locktime::absolute::ConversionError> for WalletError {
    fn from(value: bitcoin::blockdata::locktime::absolute::ConversionError) -> Self {
        Self::Locktime(value)
    }
}

impl From<bitcoin::secp256k1::Error> for WalletError {
    fn from(value: bitcoin::secp256k1::Error) -> Self {
        Self::Secp(value)
    }
}

impl From<crate::wallet::bdk_wallet::error::BDKErrors> for WalletError {
    fn from(value: crate::wallet::bdk_wallet::error::BDKErrors) -> Self {
        Self::BDKErrors(value)
    }
}
