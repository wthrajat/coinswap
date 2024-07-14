//! BDK-related errors.

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
