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
    BDKErrors(BDKErrors),
}

/// Enum for handling BDK-related errors.
#[derive(Debug)]
pub enum BDKErrors {
    /// Errors related to the parsing and usage of passed-in descriptor(s).
    Descriptor(bdk_wallet::descriptor::error::Error),
    /// Errors that can happen while extracting and manipulating policies.
    Policy(bdk_wallet::descriptor::policy::PolicyError),
    /// The error type when constructing a fresh [`Wallet`].
    New(bdk_wallet::wallet::NewError),
    /// The error type when loading a [`Wallet`] from a [`ChangeSet`].
    Load(bdk_wallet::wallet::LoadError),
    /// Error type for when we try load a [`Wallet`] from persistence and creating it if non-existent.
    NewLoad(bdk_wallet::wallet::NewOrLoadError),
    /// An error that may occur when applying a block to [`Wallet`].
    ApplyBlock(bdk_wallet::wallet::ApplyBlockError),
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

/// Implementations for BDK Errors.
impl From<bdk_wallet::descriptor::DescriptorError> for WalletError {
    fn from(value: bdk_wallet::descriptor::DescriptorError) -> Self {
        Self::BDKErrors(BDKErrors::Descriptor(value))
    }
}

impl From<bdk_wallet::descriptor::policy::PolicyError> for WalletError {
    fn from(value: bdk_wallet::descriptor::policy::PolicyError) -> Self {
        Self::BDKErrors(BDKErrors::Policy(value))
    }
}

impl From<bdk_wallet::wallet::NewError> for WalletError {
    fn from(value: bdk_wallet::wallet::NewError) -> Self {
        Self::BDKErrors(BDKErrors::New(value))
    }
}

impl From<bdk_wallet::wallet::LoadError> for WalletError {
    fn from(value: bdk_wallet::wallet::LoadError) -> Self {
        Self::BDKErrors(BDKErrors::Load(value))
    }
}

impl From<bdk_wallet::wallet::NewOrLoadError> for WalletError {
    fn from(value: bdk_wallet::wallet::NewOrLoadError) -> Self {
        Self::BDKErrors(BDKErrors::NewLoad(value))
    }
}

impl From<bdk_wallet::wallet::ApplyBlockError> for WalletError {
    fn from(value: bdk_wallet::wallet::ApplyBlockError) -> Self {
        Self::BDKErrors(BDKErrors::ApplyBlock(value))
    }
}
