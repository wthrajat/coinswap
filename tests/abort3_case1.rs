#![cfg(feature = "integration-test")]
use bitcoin::Amount;
use coinswap::{
    maker::{start_maker_server, MakerBehavior},
    taker::SwapParams,
    utill::ConnectionType,
};

mod test_framework;
use test_framework::*;

use log::{info, warn};
use std::{fs::File, io::Read, path::PathBuf, thread, time::Duration};

/// ABORT 3: Maker Drops After Setup
/// Case 1: CloseAtContractSigsForRecvrAndSender
///
/// Maker closes connection after receiving a `ContractSigsForRecvrAndSender` and doesn't broadcasts it's funding txs.
/// Taker wait until a timeout (10ses for test, 5mins for prod) and starts recovery after that.
// This is problematic. Needs more detailed thought.
#[test]
fn abort3_case1_close_at_contract_sigs_for_recvr_and_sender() {
    // ---- Setup ----

    // 6102 is naughty. And theres not enough makers.
    let makers_config_map = [
        (
            (6102, None),
            MakerBehavior::CloseAtContractSigsForRecvrAndSender,
        ),
        ((16102, None), MakerBehavior::Normal),
    ];

    // Initiate test framework, Makers.
    // Taker has normal behavior.
    let (test_framework, taker, makers, directory_server_instance) = TestFramework::init(
        None,
        makers_config_map.into(),
        None,
        ConnectionType::CLEARNET,
    );

    warn!("Running Test: Maker closes connection after receiving a ContractSigsForRecvrAndSender");

    info!("Initiating Takers...");
    // Fund the Taker and Makers with 3 utxos of 0.05 btc each.
    for _ in 0..3 {
        let taker_address = taker
            .write()
            .unwrap()
            .get_wallet_mut()
            .get_next_external_address()
            .unwrap();
        test_framework.send_to_address(&taker_address, Amount::from_btc(0.05).unwrap());
        makers.iter().for_each(|maker| {
            let maker_addrs = maker
                .get_wallet()
                .write()
                .unwrap()
                .get_next_external_address()
                .unwrap();
            test_framework.send_to_address(&maker_addrs, Amount::from_btc(0.05).unwrap());
        });
    }

    // Coins for fidelity creation
    makers.iter().for_each(|maker| {
        let maker_addrs = maker
            .get_wallet()
            .write()
            .unwrap()
            .get_next_external_address()
            .unwrap();
        test_framework.send_to_address(&maker_addrs, Amount::from_btc(0.05).unwrap());
    });

    // confirm balances
    test_framework.generate_blocks(1);

    // ---- Start Servers and attempt Swap ----

    info!("Initiating Maker...");
    // Start the Maker server threads
    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || {
                start_maker_server(maker_clone).unwrap();
            })
        })
        .collect::<Vec<_>>();

    info!("Initiating coinswap protocol");

    // Start swap

    // Makers take time to fully setup.
    makers.iter().for_each(|maker| {
        while !*maker.is_setup_complete.read().unwrap() {
            log::info!("Waiting for maker setup completion");
            // Introduce a delay of 10 seconds to prevent write lock starvation.
            thread::sleep(Duration::from_secs(10));
            continue;
        }
    });

    let swap_params = SwapParams {
        send_amount: Amount::from_sat(500000),
        maker_count: 2,
        tx_count: 3,
        required_confirms: 1,
        fee_rate: Amount::from_sat(1000),
    };

    // Spawn a Taker coinswap thread.
    let taker_clone = taker.clone();
    let taker_thread = thread::spawn(move || {
        taker_clone
            .write()
            .unwrap()
            .do_coinswap(swap_params)
            .unwrap();
    });

    // Wait for Taker swap thread to conclude.
    taker_thread.join().unwrap();

    // Wait for Maker threads to conclude.
    makers.iter().for_each(|maker| maker.shutdown().unwrap());
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    // ---- After Swap checks ----

    let _ = directory_server_instance.shutdown();

    thread::sleep(Duration::from_secs(10));

    // TODO: Do balance asserts
    // Maker gets banned for being naughty.
    match taker.read().unwrap().config.connection_type {
        ConnectionType::CLEARNET => {
            assert_eq!(
                format!("127.0.0.1:{}", 6102),
                taker.read().unwrap().get_bad_makers()[0]
                    .address
                    .to_string()
            );
        }
        ConnectionType::TOR => {
            let onion_addr_path =
                PathBuf::from(format!("/tmp/tor-rust-maker{}/hs-dir/hostname", 6102));
            let mut file = File::open(onion_addr_path).unwrap();
            let mut onion_addr: String = String::new();
            file.read_to_string(&mut onion_addr).unwrap();
            onion_addr.pop();
            assert_eq!(
                format!("{}:{}", onion_addr, 6102),
                taker.read().unwrap().get_bad_makers()[0]
                    .address
                    .to_string()
            );
        }
    }

    test_framework.stop();
}
