//! Send regular Bitcoin payments.
//!
//! This module provides functionality for managing wallet transactions, including the creation of
//! direct sends. It leverages Bitcoin Core's RPC for wallet synchronization and implements various
//! parsing mechanisms for transaction inputs and outputs.

use std::{num::ParseIntError, str::FromStr};

use bitcoin::{
    absolute::LockTime, transaction::Version, Address, Amount, Network, OutPoint, ScriptBuf,
    Sequence, Transaction, TxIn, TxOut, Witness,
};
use bitcoind::bitcoincore_rpc::{json::ListUnspentResultEntry, RawTx, RpcApi};

use crate::wallet::{api::UTXOSpendInfo, SwapCoin};

use super::{error::WalletError, Wallet};

/// Enum representing different options for the amount to be sent in a transaction.
#[derive(Debug, Clone, PartialEq)]
pub enum SendAmount {
    Max,
    Amount(Amount),
}

impl FromStr for SendAmount {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if s == "max" {
            SendAmount::Max
        } else {
            SendAmount::Amount(Amount::from_sat(String::from(s).parse::<u64>()?))
        })
    }
}

/// Enum representing different destination options for a transaction.
#[derive(Debug, Clone, PartialEq)]
pub enum Destination {
    Wallet,
    Address(Address),
}

impl FromStr for Destination {
    type Err = bitcoin::address::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if s == "wallet" {
            Destination::Wallet
        } else {
            Destination::Address(Address::from_str(s)?.assume_checked())
        })
    }
}

impl Wallet {
    /// API to perform spending from wallet utxos, Including descriptor coins, swap coins or contract outputs (timelock/hashlock).
    /// This should not be used to spend the Fidelity Bond. Check [Wallet::redeem_fidelity] for fidelity spending.
    ///
    /// The caller needs to specify the list of utxo data and their corresponding spend_info. These can be extracted by various `list_utxo_*` Wallet APIs.
    ///
    /// Caller needs to specify a total Fee and Destination address. Using [Destination::Wallet] will create a transaction to an internal wallet change address.
    ///
    /// Using [SendAmount::Max] will sweep all the inputs, creating a transaction of max possible value to destination. To send custom value and hold remaining in
    /// a change address, use [SendAmount::Amount].
    pub fn spend_from_wallet(
        &mut self,
        fee: Amount,
        send_amount: SendAmount,
        destination: Destination,
        coins_to_spend: &[(ListUnspentResultEntry, UTXOSpendInfo)],
    ) -> Result<Transaction, WalletError> {
        log::info!("Creating Direct-Spend from Wallet.");
        let mut tx_inputs = Vec::<TxIn>::new();
        let mut spend_infos = Vec::new();
        let mut total_input_value = Amount::ZERO;

        for (utxo_data, spend_info) in coins_to_spend {
            // Sequence value required if utxo is timelock/hashlock
            let sequence = match spend_info {
                UTXOSpendInfo::TimelockContract {
                    ref swapcoin_multisig_redeemscript,
                    input_value: _,
                } => self
                    .find_outgoing_swapcoin(swapcoin_multisig_redeemscript)
                    .expect("Outgoing swapcoin expected")
                    .get_timelock()? as u32,
                UTXOSpendInfo::HashlockContract {
                    swapcoin_multisig_redeemscript: _,
                    input_value: _,
                } => 1, //hashlock spends must have 1 because of the `OP_CSV 1`
                _ => 0,
            };

            tx_inputs.push(TxIn {
                previous_output: OutPoint::new(utxo_data.txid, utxo_data.vout),
                sequence: Sequence(sequence),
                witness: Witness::new(),
                script_sig: ScriptBuf::new(),
            });

            spend_infos.push(spend_info);

            total_input_value += utxo_data.amount;
        }

        if tx_inputs.len() != coins_to_spend.len() {
            return Err(WalletError::Protocol(
                "Could not fetch all inputs.".to_string(),
            ));
        }

        log::info!("Total Input Amount: {} | Fees: {}", total_input_value, fee);

        let dest_addr = match destination {
            Destination::Wallet => self.get_next_external_address()?,
            Destination::Address(a) => {
                //testnet and signet addresses have the same vbyte
                //so a.network is always testnet even if the address is signet
                let testnet_signet_type = (a.as_unchecked().is_valid_for_network(Network::Testnet)
                    || a.as_unchecked().is_valid_for_network(Network::Signet))
                    && (self.store.network == Network::Testnet
                        || self.store.network == Network::Signet);
                if !a.as_unchecked().is_valid_for_network(self.store.network)
                    && !testnet_signet_type
                {
                    return Err(WalletError::Protocol(
                        "Wrong address type in destinations.".to_string(),
                    ));
                }
                a
            }
        };

        let mut output = Vec::<TxOut>::new();

        let txout = {
            let value = match send_amount {
                SendAmount::Max => (total_input_value - fee).to_sat(),
                SendAmount::Amount(a) => a.to_sat(),
            };
            log::info!("Sending {} to {}.", value, dest_addr);
            TxOut {
                script_pubkey: dest_addr.script_pubkey(),
                value: Amount::from_sat(value),
            }
        };

        output.push(txout);

        // Only include change if remaining > dust
        if let SendAmount::Amount(amount) = send_amount {
            let internal_spk = self.get_next_internal_addresses(1)?[0].script_pubkey();
            let remaining = total_input_value - amount - fee;
            if remaining > internal_spk.minimal_non_dust() {
                log::info!("Adding Change {}:{}", internal_spk, remaining);
                output.push(TxOut {
                    script_pubkey: internal_spk,
                    value: remaining,
                });
            }
        }

        // Set the Anti-Fee-Snipping locktime
        let current_height = self.rpc.get_block_count()?;
        let lock_time = LockTime::from_height(current_height as u32)?;

        let mut tx = Transaction {
            input: tx_inputs,
            output,
            lock_time,
            version: Version::TWO,
        };
        self.sign_transaction(
            &mut tx,
            &mut coins_to_spend.iter().map(|(_, usi)| usi.clone()),
        )?;
        log::debug!("Signed Transaction : {:?}", tx.raw_hex());
        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_amount_parsing() {
        assert_eq!(SendAmount::from_str("max").unwrap(), SendAmount::Max);
        assert_eq!(
            SendAmount::from_str("1000").unwrap(),
            SendAmount::Amount(Amount::from_sat(1000))
        );
        assert_ne!(
            SendAmount::from_str("1000").unwrap(),
            SendAmount::from_str("100").unwrap()
        );
        assert!(SendAmount::from_str("not a number").is_err());
    }

    #[test]
    fn test_destination_parsing() {
        assert_eq!(
            Destination::from_str("wallet").unwrap(),
            Destination::Wallet
        );
        let address1 = "32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf";
        assert!(matches!(
            Destination::from_str(address1),
            Ok(Destination::Address(_))
        ));

        let address1 = Destination::Address(
            Address::from_str("32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf")
                .unwrap()
                .assume_checked(),
        );

        let address2 = Destination::Address(
            Address::from_str("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM")
                .unwrap()
                .assume_checked(),
        );
        assert_ne!(address1, address2);
        assert!(Destination::from_str("invalid address").is_err());
    }
}
