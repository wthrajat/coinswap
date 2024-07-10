//! The Wallet API.

use super::Keychain;
use bdk_chain::{
    bitcoin::{key::Secp256k1, secp256k1::All, Network},
    keychain::KeychainTxOutIndex,
    local_chain::LocalChain,
    CombinedChangeSet, ConfirmationTimeHeightAnchor, IndexedTxGraph,
};
use bdk_wallet::signer::SignersContainer;

use crate::wallet::WalletStore as MetaStore;
use bitcoind::bitcoincore_rpc::Client;
use std::{collections::HashMap, path::PathBuf, sync::Arc};
pub type ChangeSet = CombinedChangeSet<Keychain, ConfirmationTimeHeightAnchor>;

pub struct Wallet {
    signers: HashMap<Keychain, Arc<SignersContainer>>,
    chain: LocalChain,
    indexed_graph: IndexedTxGraph<ConfirmationTimeHeightAnchor, KeychainTxOutIndex<Keychain>>,
    stage: ChangeSet,
    meta_store: MetaStore,
    network: Network,
    secp: Secp256k1<All>,
    rpc: Client,
    wallet_file_path: PathBuf,
}
