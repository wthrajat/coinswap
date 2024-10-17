//! Various operational routines/functions.
//!
//! It includes functions for handshaking, requesting contract signatures, sending proofs of funding, and downloading maker offers.
//! It also defines structs for contract transactions and contract information.
//! Notable types include [ContractTransaction], [ContractsInfo], [ThisMakerInfo], and [NextPeerInfoArgs].
//! It also handles downloading maker offers with retry mechanisms and implements the necessary message structures
//! for communication between taker and maker.

use serde::{Deserialize, Serialize};
use socks::Socks5Stream;
use std::{io::ErrorKind, net::TcpStream, thread::sleep, time::Duration};

use crate::{
    error::ProtocolError,
    protocol::{
        contract::{
            calculate_coinswap_fee, create_contract_redeemscript, find_funding_output_index,
            validate_contract_tx, FUNDING_TX_VBYTE_SIZE,
        },
        messages::{
            ContractSigsAsRecvrAndSender, ContractSigsForRecvr, ContractSigsForSender,
            ContractTxInfoForRecvr, ContractTxInfoForSender, FundingTxInfo, GiveOffer,
            HashPreimage, MakerToTakerMessage, NextHopInfo, Offer, Preimage, PrivKeyHandover,
            ProofOfFunding, ReqContractSigsForRecvr, ReqContractSigsForSender, TakerHello,
            TakerToMakerMessage,
        },
        Hash160,
    },
    utill::{read_message, send_message, ConnectionType},
    wallet::WalletError,
};
use bitcoin::{secp256k1::SecretKey, Amount, PublicKey, ScriptBuf, Transaction};

use super::{
    config::TakerConfig,
    error::TakerError,
    offers::{MakerAddress, OfferAndAddress},
};

use crate::wallet::SwapCoin;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ContractTransaction {
    pub tx: Transaction,
    pub redeemscript: ScriptBuf,
    pub hashlock_spend_without_preimage: Option<Transaction>,
    pub timelock_spend: Option<Transaction>,
    pub timelock_spend_broadcasted: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ContractsInfo {
    pub contract_txes: Vec<ContractTransaction>,
    pub wallet_label: String,
}

/// Make a handshake with a maker.
/// Ensures that the Maker is alive and responding.
///
// In future, handshake can be used to find protocol compatibility across multiple versions.
pub fn handshake_maker(socket: &mut TcpStream) -> Result<(), TakerError> {
    send_message(
        socket,
        &TakerToMakerMessage::TakerHello(TakerHello {
            protocol_version_min: 1,
            protocol_version_max: 1,
        }),
    )?;
    let msg_bytes = read_message(socket)?;
    let msg: MakerToTakerMessage = serde_cbor::from_slice(&msg_bytes)?;

    // Check that protocol version is always 1.
    match msg {
        MakerToTakerMessage::MakerHello(m) => {
            if m.protocol_version_max == 1 && m.protocol_version_min == 1 {
                Ok(())
            } else {
                Err(ProtocolError::WrongMessage {
                    expected: "Only protocol version 1 is allowed".to_string(),
                    received: format!(
                        "min/max version  = {}/{}",
                        m.protocol_version_min, m.protocol_version_max
                    ),
                }
                .into())
            }
        }
        any => Err((ProtocolError::WrongMessage {
            expected: "MakerHello".to_string(),
            received: format!("{}", any),
        })
        .into()),
    }
}

/// Request signatures for sender side of the hop. Attempt once.
pub(crate) fn req_sigs_for_sender_once<S: SwapCoin>(
    socket: &mut TcpStream,
    outgoing_swapcoins: &[S],
    maker_multisig_nonces: &[SecretKey],
    maker_hashlock_nonces: &[SecretKey],
    locktime: u16,
) -> Result<ContractSigsForSender, TakerError> {
    log::info!("Connecting to {}", socket.peer_addr()?);
    handshake_maker(socket)?;
    log::info!(
        "===> Sending ReqContractSigsForSender to {}",
        socket.peer_addr()?
    );

    let txs_info = maker_multisig_nonces
        .iter()
        .zip(maker_hashlock_nonces.iter())
        .zip(outgoing_swapcoins.iter())
        .map(
            |((&multisig_key_nonce, &hashlock_key_nonce), outgoing_swapcoin)| {
                Ok(ContractTxInfoForSender {
                    multisig_nonce: multisig_key_nonce,
                    hashlock_nonce: hashlock_key_nonce,
                    timelock_pubkey: outgoing_swapcoin.get_timelock_pubkey()?,
                    senders_contract_tx: outgoing_swapcoin.get_contract_tx(),
                    multisig_redeemscript: outgoing_swapcoin.get_multisig_redeemscript(),
                    funding_input_value: outgoing_swapcoin.get_funding_amount(),
                })
            },
        )
        .collect::<Result<Vec<ContractTxInfoForSender>, WalletError>>()?;

    send_message(
        socket,
        &TakerToMakerMessage::ReqContractSigsForSender(ReqContractSigsForSender {
            txs_info,
            hashvalue: outgoing_swapcoins[0].get_hashvalue()?,
            locktime,
        }),
    )?;

    let msg_bytes = read_message(socket)?;
    let msg: MakerToTakerMessage = serde_cbor::from_slice(&msg_bytes)?;
    let contract_sigs_for_sender = match msg {
        MakerToTakerMessage::RespContractSigsForSender(m) => {
            if m.sigs.len() != outgoing_swapcoins.len() {
                return Err((ProtocolError::WrongNumOfSigs {
                    expected: outgoing_swapcoins.len(),
                    received: m.sigs.len(),
                })
                .into());
            } else {
                m
            }
        }
        any => {
            return Err((ProtocolError::WrongMessage {
                expected: "RespContractSigsForSender".to_string(),
                received: format!("{}", any),
            })
            .into());
        }
    };

    for (sig, outgoing_swapcoin) in contract_sigs_for_sender
        .sigs
        .iter()
        .zip(outgoing_swapcoins.iter())
    {
        outgoing_swapcoin.verify_contract_tx_sender_sig(sig)?;
    }
    log::info!(
        "<=== Received ContractSigsForSender from {}",
        socket.peer_addr()?
    );
    Ok(contract_sigs_for_sender)
}

/// Request signatures for receiver side of the hop. Attempt once.
pub(crate) fn req_sigs_for_recvr_once<S: SwapCoin>(
    socket: &mut TcpStream,
    incoming_swapcoins: &[S],
    receivers_contract_txes: &[Transaction],
) -> Result<ContractSigsForRecvr, TakerError> {
    log::info!("Connecting to {}", socket.peer_addr()?);
    handshake_maker(socket)?;

    let txs_info = incoming_swapcoins
        .iter()
        .zip(receivers_contract_txes.iter())
        .map(|(swapcoin, receivers_contract_tx)| ContractTxInfoForRecvr {
            multisig_redeemscript: swapcoin.get_multisig_redeemscript(),
            contract_tx: receivers_contract_tx.clone(),
        })
        .collect::<Vec<ContractTxInfoForRecvr>>();

    send_message(
        socket,
        &TakerToMakerMessage::ReqContractSigsForRecvr(ReqContractSigsForRecvr { txs: txs_info }),
    )?;

    let msg_bytes = read_message(socket)?;
    let msg: MakerToTakerMessage = serde_cbor::from_slice(&msg_bytes)?;
    let contract_sigs_for_recvr = match msg {
        MakerToTakerMessage::RespContractSigsForRecvr(m) => {
            if m.sigs.len() != incoming_swapcoins.len() {
                return Err((ProtocolError::WrongNumOfSigs {
                    expected: incoming_swapcoins.len(),
                    received: m.sigs.len(),
                })
                .into());
            } else {
                m
            }
        }
        any => {
            return Err((ProtocolError::WrongMessage {
                expected: "ContractSigsForRecvr".to_string(),
                received: format!("{}", any),
            })
            .into());
        }
    };

    for (sig, swapcoin) in contract_sigs_for_recvr
        .sigs
        .iter()
        .zip(incoming_swapcoins.iter())
    {
        swapcoin.verify_contract_tx_receiver_sig(sig)?;
    }

    log::info!(
        "<=== Received ContractSigsForRecvr from {}",
        socket.peer_addr()?
    );
    Ok(contract_sigs_for_recvr)
}

// Type for information related to `this maker` consisting of:
// `this_maker`, `funding_txs_infos`, `this_maker_contract_txs`
#[derive(Clone)]
pub struct ThisMakerInfo {
    pub this_maker: OfferAndAddress,
    pub funding_tx_infos: Vec<FundingTxInfo>,
    pub this_maker_contract_txs: Vec<Transaction>,
}

// Type for information related to the next peer
#[derive(Clone)]
pub struct NextPeerInfoArgs {
    pub next_peer_multisig_pubkeys: Vec<PublicKey>,
    pub next_peer_hashlock_pubkeys: Vec<PublicKey>,
    pub next_maker_refund_locktime: u16,
    pub next_maker_fee_rate: Amount,
}

/// [Internal] Send a Proof funding to the maker and init next hop.
pub(crate) fn send_proof_of_funding_and_init_next_hop(
    socket: &mut TcpStream,
    tmi: ThisMakerInfo,
    npi: NextPeerInfoArgs,
    hashvalue: Hash160,
) -> Result<(ContractSigsAsRecvrAndSender, Vec<ScriptBuf>), TakerError> {
    // Send POF
    let next_coinswap_info = npi
        .next_peer_multisig_pubkeys
        .iter()
        .zip(npi.next_peer_hashlock_pubkeys.iter())
        .map(
            |(&next_coinswap_multisig_pubkey, &next_hashlock_pubkey)| NextHopInfo {
                next_multisig_pubkey: next_coinswap_multisig_pubkey,
                next_hashlock_pubkey,
            },
        )
        .collect::<Vec<NextHopInfo>>();

    let pof_msg = TakerToMakerMessage::RespProofOfFunding(ProofOfFunding {
        confirmed_funding_txes: tmi.funding_tx_infos.clone(),
        next_coinswap_info,
        next_locktime: npi.next_maker_refund_locktime,
        next_fee_rate: npi.next_maker_fee_rate.to_sat(),
    });

    send_message(socket, &pof_msg)?;

    // Recv ContractSigsAsRecvrAndSender.
    let msg_bytes = read_message(socket)?;
    let msg: MakerToTakerMessage = serde_cbor::from_slice(&msg_bytes)?;
    let contract_sigs_as_recvr_and_sender = match msg {
        MakerToTakerMessage::ReqContractSigsAsRecvrAndSender(m) => {
            if m.receivers_contract_txs.len() != tmi.funding_tx_infos.len() {
                return Err((ProtocolError::WrongNumOfContractTxs {
                    expected: tmi.funding_tx_infos.len(),
                    received: m.receivers_contract_txs.len(),
                })
                .into());
            } else if m.senders_contract_txs_info.len() != npi.next_peer_multisig_pubkeys.len() {
                return Err((ProtocolError::WrongNumOfContractTxs {
                    expected: m.senders_contract_txs_info.len(),
                    received: npi.next_peer_multisig_pubkeys.len(),
                })
                .into());
            } else {
                m
            }
        }
        any => {
            return Err((ProtocolError::WrongMessage {
                expected: "ContractSigsAsRecvrAndSender".to_string(),
                received: format!("{}", any),
            })
            .into());
        }
    };

    let funding_tx_values = tmi
        .funding_tx_infos
        .iter()
        .map(|funding_info| {
            let funding_output_index =
                find_funding_output_index(funding_info).map_err(ProtocolError::Contract)?;
            Ok(funding_info
                .funding_tx
                .output
                .get(funding_output_index as usize)
                .expect("funding output expected")
                .value
                .to_sat())
        })
        .collect::<Result<Vec<u64>, TakerError>>()?;

    let this_amount = funding_tx_values.iter().sum::<u64>();

    let next_amount = contract_sigs_as_recvr_and_sender
        .senders_contract_txs_info
        .iter()
        .map(|i| i.funding_amount)
        .sum::<Amount>();
    let coinswap_fees = calculate_coinswap_fee(
        tmi.this_maker.offer.absolute_fee_sat,
        tmi.this_maker.offer.amount_relative_fee_ppb,
        tmi.this_maker.offer.time_relative_fee_ppb,
        Amount::from_sat(this_amount),
        1, //time_in_blocks just 1 for now
    );
    let miner_fees_paid_by_taker = (FUNDING_TX_VBYTE_SIZE
        * npi.next_maker_fee_rate.to_sat()
        * (npi.next_peer_multisig_pubkeys.len() as u64))
        / 1000;
    let calculated_next_amount = this_amount - coinswap_fees - miner_fees_paid_by_taker;
    if Amount::from_sat(calculated_next_amount) != next_amount {
        return Err((ProtocolError::IncorrectFundingAmount {
            expected: Amount::from_sat(calculated_next_amount),
            found: next_amount,
        })
        .into());
    }
    log::info!(
        "this_amount={} coinswap_fees={} miner_fees_paid_by_taker={} next_amount={}",
        this_amount,
        coinswap_fees,
        miner_fees_paid_by_taker,
        next_amount
    );

    for ((receivers_contract_tx, contract_tx), contract_redeemscript) in
        contract_sigs_as_recvr_and_sender
            .receivers_contract_txs
            .iter()
            .zip(tmi.this_maker_contract_txs.iter())
            .zip(
                tmi.funding_tx_infos
                    .iter()
                    .map(|fi| &fi.contract_redeemscript),
            )
    {
        validate_contract_tx(
            receivers_contract_tx,
            Some(&contract_tx.input[0].previous_output),
            contract_redeemscript,
        )
        .map_err(ProtocolError::Contract)?;
    }
    let next_swap_contract_redeemscripts = npi
        .next_peer_hashlock_pubkeys
        .iter()
        .zip(
            contract_sigs_as_recvr_and_sender
                .senders_contract_txs_info
                .iter(),
        )
        .map(|(hashlock_pubkey, senders_contract_tx_info)| {
            create_contract_redeemscript(
                hashlock_pubkey,
                &senders_contract_tx_info.timelock_pubkey,
                &hashvalue,
                &npi.next_maker_refund_locktime,
            )
        })
        .collect::<Vec<_>>();
    Ok((
        contract_sigs_as_recvr_and_sender,
        next_swap_contract_redeemscripts,
    ))
}

/// Send hash preimage via the writer and read the response.
pub(crate) fn send_hash_preimage_and_get_private_keys(
    socket: &mut TcpStream,
    senders_multisig_redeemscripts: &[ScriptBuf],
    receivers_multisig_redeemscripts: &[ScriptBuf],
    preimage: &Preimage,
) -> Result<PrivKeyHandover, TakerError> {
    let hash_preimage_msg = TakerToMakerMessage::RespHashPreimage(HashPreimage {
        senders_multisig_redeemscripts: senders_multisig_redeemscripts.to_vec(),
        receivers_multisig_redeemscripts: receivers_multisig_redeemscripts.to_vec(),
        preimage: *preimage,
    });

    send_message(socket, &hash_preimage_msg)?;

    let msg_bytes = read_message(socket)?;
    let msg: MakerToTakerMessage = serde_cbor::from_slice(&msg_bytes)?;
    let privkey_handover = match msg {
        MakerToTakerMessage::RespPrivKeyHandover(m) => {
            if m.multisig_privkeys.len() != receivers_multisig_redeemscripts.len() {
                return Err((ProtocolError::WrongNumOfPrivkeys {
                    expected: receivers_multisig_redeemscripts.len(),
                    received: m.multisig_privkeys.len(),
                })
                .into());
            } else {
                m
            }
        }
        any => {
            return Err((ProtocolError::WrongMessage {
                expected: "PrivkeyHandover".to_string(),
                received: format!("{}", any),
            })
            .into());
        }
    };

    Ok(privkey_handover)
}

fn download_maker_offer_attempt_once(
    addr: &MakerAddress,
    config: &TakerConfig,
) -> Result<Offer, TakerError> {
    let address = addr.to_string();
    let mut socket = match config.connection_type {
        ConnectionType::CLEARNET => TcpStream::connect(address)?,
        ConnectionType::TOR => Socks5Stream::connect(
            format!("127.0.0.1:{}", config.socks_port).as_str(),
            address.as_ref(),
        )?
        .into_inner(),
    };

    socket.set_read_timeout(Some(Duration::from_secs(
        config.first_connect_attempt_timeout_sec,
    )))?;
    socket.set_write_timeout(Some(Duration::from_secs(
        config.first_connect_attempt_timeout_sec,
    )))?;

    handshake_maker(&mut socket)?;

    send_message(&mut socket, &TakerToMakerMessage::ReqGiveOffer(GiveOffer))?;

    let msg_bytes = read_message(&mut socket)?;
    let msg: MakerToTakerMessage = serde_cbor::from_slice(&msg_bytes)?;
    let offer = match msg {
        MakerToTakerMessage::RespOffer(offer) => offer,
        msg => {
            return Err(TakerError::Protocol(ProtocolError::WrongMessage {
                expected: "RespOffer".to_string(),
                received: format!("{}", msg),
            }));
        }
    };

    Ok(*offer)
}

pub fn download_maker_offer(address: MakerAddress, config: TakerConfig) -> Option<OfferAndAddress> {
    let mut ii = 0;

    loop {
        ii += 1;
        match download_maker_offer_attempt_once(&address, &config) {
            Ok(offer) => return Some(OfferAndAddress { offer, address }),
            Err(TakerError::IO(e)) => {
                if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut {
                    if ii <= config.first_connect_attempts {
                        log::warn!(
                            "Timeout for request offer from maker {}, reattempting...",
                            address
                        );
                        continue;
                    } else {
                        log::error!(
                            "Timeout attempt exceeded for request offer from maker {}, ",
                            address
                        );
                        return None;
                    }
                }
            }

            Err(e) => {
                if ii <= config.first_connect_attempts {
                    log::warn!(
                        "Failed to request offer from maker {}, reattempting... error={:?}",
                        address,
                        e
                    );
                    sleep(Duration::from_secs(config.first_connect_sleep_delay_sec));
                    continue;
                } else {
                    log::error!(
                        "Connection attempt exceeded for request offer from maker {}",
                        address
                    );
                    return None;
                }
            }
        }
    }
}
