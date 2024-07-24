//! The Wallet API.
use super::{
    error::{BdkError, BdkStoreError},
    Keychain,
};
use bdk_chain::{
    bitcoin::{
        bip32::IntoDerivationPath, constants::genesis_block, key::Secp256k1, secp256k1::All,
        Address, Network,
    },
    keychain::KeychainTxOutIndex,
    local_chain::LocalChain,
    miniscript::descriptor::{DescriptorXKey, Wildcard},
    CombinedChangeSet, ConfirmationTimeHeightAnchor, IndexedTxGraph,
};
use bdk_wallet::{
    descriptor::{Descriptor, DescriptorError},
    keys::{DescriptorPublicKey, DescriptorSecretKey},
    signer::SignersContainer,
    wallet::LoadError,
};
use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use std::{collections::BTreeMap, fs};

use crate::wallet::WalletError;

use std::convert::TryFrom;

use crate::{
    bitcoind::bitcoincore_rpc::RpcApi,
    wallet::{RPCConfig, WalletStore as MetaStore},
};
use bdk_file_store::Store as BDKStore;
use bitcoind::bitcoincore_rpc::Client;
use std::{collections::HashMap, path::PathBuf, sync::Arc};
pub type ChangeSet = CombinedChangeSet<Keychain, ConfirmationTimeHeightAnchor>;

#[derive(Debug)]
pub struct Wallet {
    signers: HashMap<Keychain, Arc<SignersContainer>>,
    chain: LocalChain,
    indexed_graph: IndexedTxGraph<ConfirmationTimeHeightAnchor, KeychainTxOutIndex<Keychain>>,
    stage: ChangeSet,
    meta_store: MetaStore,
    network: Network,
    secp: Secp256k1<All>,
    rpc: Client,
    data_dir: PathBuf,
}

impl Wallet {
    pub fn init(
        data_dir: PathBuf,
        seedphrase: String,
        passphrase: String,
        rpc_config: &RPCConfig,
        network: Network,
    ) -> Result<Self, WalletError> {
        let secp = Secp256k1::new();

        // derive master key of wallet
        let mnemonic = Mnemonic::parse(&seedphrase)?;
        let seed = mnemonic.to_seed(&passphrase);
        let master_key = Xpriv::new_master(network, &seed)?;

        // derive master_fingerprint
        let master_fingerprint = master_key.fingerprint(&secp).to_string();

        // load rpc client from given rpc_config
        let rpc = Client::try_from(rpc_config)?;

        let wallet_birthday = rpc.get_block_count()?;

        // derive path for meta_store
        let meta_store_path = data_dir.join("meta_store.cbor");

        // initialise metastore:
        let meta_store = MetaStore::init(
            master_fingerprint,
            &meta_store_path,
            network,
            seedphrase,
            passphrase,
            Some(wallet_birthday),
        )?;

        // create genesis_hash of given network
        let genesis_hash = genesis_block(network).block_hash();

        // get local_chain and its corresponding changeset
        let (chain, chain_changeset) = LocalChain::from_genesis_hash(genesis_hash);

        let mut index = KeychainTxOutIndex::<Keychain>::default();

        let mut signers = HashMap::new();

        // Create descriptors for `Keychain::External` and `Keychain::Internal`,
        // add their signing data to the signers map and their corresponding descriptors to the index.
        for keychain in [Keychain::External, Keychain::Internal] {
            // find xpriv of keychain
            let keychain_xpriv = meta_store
                .master_key
                .derive_priv(
                    &secp,
                    &keychain
                        .path()
                        .into_derivation_path()
                        .map_err(|e| BdkError::Descriptor(DescriptorError::Bip32(e)))?,
                )
                .map_err(|e| BdkError::Descriptor(DescriptorError::Bip32(e)))?;

            // create descriptor strings
            let path_with_fingerprint = keychain.path().replace("m", &meta_store.file_name);
            let descriptor = format!("wpkh([{}]{}/*)", path_with_fingerprint, keychain_xpriv);

            // parse descriptor
            let (descriptor, keymap) =
                Descriptor::<DescriptorPublicKey>::parse_descriptor(&secp, &descriptor)
                    .map_err(|e| BdkError::Descriptor(DescriptorError::Miniscript(e)))?;

            // build respective signer container
            let signer_container = Arc::new(SignersContainer::build(keymap, &descriptor, &secp));

            // insert the signer_container to signer
            signers.insert(keychain, signer_container);

            // insert keychain  and its descriptor to index
            let _ = index
                .insert_descriptor(keychain, descriptor)
                .map_err(BdkError::InsertDescriptorError);
        }

        let indexed_graph = IndexedTxGraph::new(index);

        let wallet = Wallet {
            signers,
            chain,
            indexed_graph,
            stage: ChangeSet::default(),
            meta_store,
            network,
            secp,
            rpc,
            data_dir: data_dir.clone(),
        };

        // Delete existing bdk_store if it exists
        let bdk_store_path = data_dir.join("bdk_store.dat");
        if bdk_store_path.exists() {
            fs::remove_file(&bdk_store_path)?;
        }

        // get the combined changeset generated by initiating wallet.
        let init_changeset = ChangeSet {
            chain: chain_changeset,
            indexed_tx_graph: wallet.indexed_graph.initial_changeset(),
            network: Some(network),
        };

        // Save wallet state
        wallet.save(Some(init_changeset))?;

        Ok(wallet)
    }

    /// Loads a [`Wallet`] from the given previously persisted [`ChangeSet`].
    ///
    /// Note that the descriptor secret keys are not persisted to the database.
    /// They are not loaded into the returned [`Wallet`], so the wallet signers will be empty.
    fn load_from_changeset(
        changeset: ChangeSet,
        meta_store: MetaStore,
        rpc_config: &RPCConfig,
        data_dir: PathBuf,
    ) -> Result<Self, WalletError> {
        let secp = Secp256k1::new();

        // get network & LocalChain from given changeset.
        let network = changeset
            .network
            .ok_or(BdkError::Load(LoadError::MissingNetwork))?;

        let chain = LocalChain::from_changeset(changeset.chain.clone())
            .map_err(|_| BdkError::Load(LoadError::MissingGenesis))?;

        // load rpc client from given rpc_config
        let rpc = Client::try_from(rpc_config)?;

        let index = KeychainTxOutIndex::<Keychain>::default();

        let mut indexed_graph = IndexedTxGraph::new(index);

        // apply changeset to indexed_graph
        indexed_graph.apply_changeset(changeset.indexed_tx_graph.clone());

        Ok(Wallet {
            signers: HashMap::new(),
            chain,
            indexed_graph,
            stage: ChangeSet::default(),
            meta_store,
            network,
            secp,
            rpc,
            data_dir,
        })
    }

    /// Loads an existing [`Wallet`] from the specified data directory and RPC configuration.
    pub fn load(data_dir: PathBuf, rpc_config: &RPCConfig) -> Result<Self, WalletError> {
        // get meta_store path
        let meta_store_path = data_dir.join("meta_store.cbor");

        // load meta_store from its path
        let meta_store = MetaStore::read_from_disk(&meta_store_path)?;

        // Get the path to the BDK store file
        let bdk_store_path = data_dir.join("bdk_store.dat");

        // Open the BDK store file
        let mut bdk_store = BDKStore::open(meta_store.file_name.as_bytes(), bdk_store_path)
            .map_err(|e| BdkError::BdkStoreError(BdkStoreError::FileError(e)))?;

        // Get all changesets from the BDK store and move the file pointer to the end
        let changeset: ChangeSet = bdk_store
            .aggregate_changesets()
            .map_err(|e| BdkError::BdkStoreError(BdkStoreError::AggregateChangesetsError(e)))?
            .ok_or_else(|| BdkError::BdkStoreError(BdkStoreError::NoChangeSetFound))?;

        // Load the wallet from the changeset
        let mut wallet = Wallet::load_from_changeset(changeset, meta_store, rpc_config, data_dir)?;

        // Add signers for each keychain to the wallet
        //
        // This involves:
        // 1) Deriving the keymap for each keychain
        // 2) Building the signer container for each keychain
        // 3) Inserting the signer container into the wallet's signers field
        for (keychain, descriptor) in wallet.indexed_graph.index.keychains() {
            // Get the master key from the meta_store
            let master_key = wallet.meta_store.master_key;

            // Find the derivation path of the keychain
            let derivation_path = keychain.path().into_derivation_path()?;

            // Derive the keychain's Xpriv (extended private key)
            let xpriv = master_key.derive_priv(&wallet.secp, &derivation_path)?;

            // Determine the wildcard type based on the keychain
            let wildcard = match keychain {
                Keychain::External | Keychain::Internal => Wildcard::Unhardened,
                _ => Wildcard::None,
            };

            // Create a DescriptorSecretKey from the keychain's Xpriv
            let secret_key = DescriptorSecretKey::XPrv(DescriptorXKey {
                origin: Some((master_key.fingerprint(&wallet.secp), derivation_path)),
                xkey: xpriv,
                derivation_path: DerivationPath::default(),
                wildcard,
            });

            // Form the keymap from the secret key and its public key
            let keymap= BTreeMap::from([(
                secret_key
                    .to_public(&wallet.secp)
                    .map_err( BdkError::DescriptorKeyParseError)?,
                secret_key,
            )]);

            // Build the signer container for the keychain from the keymap and public descriptor
            let signer_container =
                Arc::new(SignersContainer::build(keymap, descriptor, &wallet.secp));

            // Insert the signer container into the wallet's signers field
            wallet.signers.insert(*keychain, signer_container);

            // Save wallet state: only update meta_store, no changeset needed
            wallet.save(None)?;
        }

        Ok(wallet)
    }

   

 /// Retrieves the descriptor associated with a given keychain.
    pub fn get_keychain_descriptor(
        &self,
        keychain: Keychain,
    ) -> Option<&Descriptor<DescriptorPublicKey>> {
        self.indexed_graph.index.get_descriptor(&keychain)
    }

    /// Generates a new address for the specified keychain.
    pub fn get_new_address(&mut self, keychain: &Keychain) -> Result<Address, WalletError> {
        let index = &mut self.indexed_graph.index;

        // Gets the next unused script pubkey in the keychain and its associated changeset.
        let ((_, spk), index_changeset) = index
            .next_unused_spk(keychain)
            .ok_or(BdkError::KeychainDoesNotExist)?;

        // derive combined changeset from returned ['KeychainTxOutIndex`] changeset.
        let changeset = ChangeSet::from(index_changeset);

        // generate address from  derived scriptpubkey
        let address = Address::from_script(spk.as_script(), self.network)
            .map_err(BdkError::AddressGenerationError)?;

        // Save wallet state
        self.save(Some(changeset))?;
        Ok(address)
    }

    /// save the changes made to wallet state on disk
    pub fn save(&self, changeset: Option<ChangeSet>) -> Result<(), WalletError> {
        // get meta_store path from given data_dir
        let meta_store_path = self.data_dir.join("meta_store.cbor");

        self.meta_store.write_to_disk(&meta_store_path)?;

        if let Some(changeset) = changeset {
            // get bdk_store path from given data_dir
            let bdk_store_path = self.data_dir.join("bdk_store.dat");

            // open bdk_store
            let mut bdk_store =
                BDKStore::open_or_create_new(self.meta_store.file_name.as_bytes(), bdk_store_path)
                    .map_err(|e| BdkError::BdkStoreError(BdkStoreError::FileError(e)))?;

            // append the given changesets
            bdk_store.append_changeset(&changeset)?;
        }

        Ok(())
    }

}
