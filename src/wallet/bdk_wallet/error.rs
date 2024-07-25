//! BDK-related errors.

use bdk_chain::miniscript;

use super::{wallet::ChangeSet, Keychain};

/// Enum for handling BDK-related errors.
#[derive(Debug)]
pub enum BdkError {
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
    /// Error returned from [`KeychainTxOutIndex::insert_descriptor`]
    InsertDescriptorError(bdk_chain::keychain::InsertDescriptorError<Keychain>),
    /// Error related to BDKStore
    BdkStoreError(BdkStoreError),

    /// Error indicating that the specified keychain does not exist.
    KeychainDoesNotExist,
    // Error while generating a new address
    AddressGenerationError(bdk_wallet::bitcoin::address::FromScriptError),

    // Error while parsing key in descriptor
    DescriptorKeyParseError(miniscript::descriptor::DescriptorKeyParseError),
}

/// Enum for handling BDKStore related errors
#[derive(Debug)]
pub enum BdkStoreError {
    FileError(bdk_file_store::FileError),
    AggregateChangesetsError(bdk_file_store::AggregateChangesetsError<ChangeSet>),
    IterError(bdk_file_store::IterError),
    NoChangeSetFound,
}

/// Implementations for BDK Errors.
impl From<bdk_wallet::descriptor::DescriptorError> for BdkError {
    fn from(value: bdk_wallet::descriptor::DescriptorError) -> Self {
        Self::Descriptor(value)
    }
}

impl From<bdk_wallet::descriptor::policy::PolicyError> for BdkError {
    fn from(value: bdk_wallet::descriptor::policy::PolicyError) -> Self {
        Self::Policy(value)
    }
}

impl From<bdk_wallet::wallet::NewError> for BdkError {
    fn from(value: bdk_wallet::wallet::NewError) -> Self {
        Self::New(value)
    }
}

impl From<bdk_wallet::wallet::LoadError> for BdkError {
    fn from(value: bdk_wallet::wallet::LoadError) -> Self {
        Self::Load(value)
    }
}

impl From<bdk_wallet::wallet::NewOrLoadError> for BdkError {
    fn from(value: bdk_wallet::wallet::NewOrLoadError) -> Self {
        Self::NewLoad(value)
    }
}

impl From<bdk_wallet::wallet::ApplyBlockError> for BdkError {
    fn from(value: bdk_wallet::wallet::ApplyBlockError) -> Self {
        Self::ApplyBlock(value)
    }
}

impl From<bdk_chain::keychain::InsertDescriptorError<Keychain>> for BdkError {
    fn from(value: bdk_chain::keychain::InsertDescriptorError<Keychain>) -> Self {
        Self::InsertDescriptorError(value)
    }
}

impl From<miniscript::descriptor::DescriptorKeyParseError> for BdkError {
    fn from(value: miniscript::descriptor::DescriptorKeyParseError) -> Self {
        Self::DescriptorKeyParseError(value)
    }
}

impl From<bdk_wallet::bitcoin::address::FromScriptError> for BdkError {
    fn from(value: bdk_wallet::bitcoin::address::FromScriptError) -> Self {
        Self::AddressGenerationError(value)
    }
}

/// Implementations for BdkStore Errors.
impl From<bdk_file_store::FileError> for BdkStoreError {
    fn from(value: bdk_file_store::FileError) -> Self {
        Self::FileError(value)
    }
}

impl From<bdk_file_store::AggregateChangesetsError<ChangeSet>> for BdkStoreError {
    fn from(value: bdk_file_store::AggregateChangesetsError<ChangeSet>) -> Self {
        Self::AggregateChangesetsError(value)
    }
}

impl From<bdk_file_store::IterError> for BdkStoreError {
    fn from(value: bdk_file_store::IterError) -> Self {
        Self::IterError(value)
    }
}

impl From<BdkStoreError> for BdkError {
    fn from(value: BdkStoreError) -> Self {
        Self::BdkStoreError(value)
    }
}
