#![cfg(feature = "integration-test")]
use bitcoin::{absolute::LockTime, Amount};
use coinswap::{
    maker::{start_maker_server, MakerBehavior},
    utill::ConnectionType,
};

mod test_framework;
use test_framework::*;

use std::{thread, time::Duration};

/// Test Fidelity Transactions
///
/// These tests covers
///  - Creation
///  - Redemption
///  - Valuations of Fidelity Bonds.
///
/// Fidelity Bonds can be created either via running the maker server or by calling the `create_fidelity()` API
/// on the wallet. Both of them are performed here. At the start of the maker server it will try to create a fidelity
/// bond with value and timelock provided in the configuration (default: value = 5_000_000 sats, locktime = 100 block).
///
/// Maker server will error if not enough balance is present to create fidelity bond.
/// A custom fidelity bond can be create using the `create_fidelity()` API.
#[test]
fn test_fidelity() {
    // ---- Setup ----

    let makers_config_map = [((6102, None), MakerBehavior::Normal)];

    let (test_framework, _, makers, directory_server_instance) = TestFramework::init(
        None,
        makers_config_map.into(),
        None,
        ConnectionType::CLEARNET,
    );

    let maker = makers.first().unwrap();

    // ----- Test -----

    // Give insufficient fund to maker and start the server.
    // This should return Error of Insufficient fund.
    let maker_addrs = maker
        .get_wallet()
        .write()
        .unwrap()
        .get_next_external_address()
        .unwrap();
    test_framework.send_to_address(&maker_addrs, Amount::from_btc(0.04).unwrap());
    test_framework.generate_blocks(1);

    let maker_clone = maker.clone();
    let maker_thread = thread::spawn(move || start_maker_server(maker_clone));

    thread::sleep(Duration::from_secs(20));
    maker.shutdown().unwrap();
    let _ = maker_thread.join().unwrap();

    // TODO: Assert that fund request for fidelity is printed in the log.
    *maker.shutdown.write().unwrap() = false;

    // Give Maker more funds and check fidelity bond is created at the restart of server.
    test_framework.send_to_address(&maker_addrs, Amount::from_btc(0.04).unwrap());
    test_framework.generate_blocks(1);

    let maker_clone = maker.clone();
    let maker_thread = thread::spawn(move || start_maker_server(maker_clone));

    thread::sleep(Duration::from_secs(20));
    maker.shutdown().unwrap();

    let success = maker_thread.join().unwrap();

    assert!(success.is_ok());

    // Check fidelity bond created correctly
    let first_conf_height = {
        let wallet_read = maker.get_wallet().read().unwrap();
        let (index, bond, is_spent) = wallet_read
            .get_fidelity_bonds()
            .iter()
            .map(|(i, (b, _, is_spent))| (i, b, is_spent))
            .next()
            .unwrap();
        assert_eq!(*index, 0);
        assert_eq!(bond.amount, Amount::from_sat(5000000));
        assert!(!is_spent);
        bond.conf_height
    };

    // Create another fidelity bond of 1000000 sats
    let second_conf_height = {
        let mut wallet_write = maker.get_wallet().write().unwrap();
        let index = wallet_write
            .create_fidelity(
                Amount::from_sat(1000000),
                LockTime::from_height((test_framework.get_block_count() as u32) + 100).unwrap(),
            )
            .unwrap();
        assert_eq!(index, 1);
        let (bond, _, is_spent) = wallet_write
            .get_fidelity_bonds()
            .get(&index)
            .expect("bond expected");
        assert_eq!(bond.amount, Amount::from_sat(1000000));
        assert!(!is_spent);
        bond.conf_height
    };

    // Check the balances
    {
        let wallet = maker.get_wallet().read().unwrap();
        let all_utxos = wallet.get_all_utxo().unwrap();
        let normal_balance = wallet.balance_descriptor_utxo(Some(&all_utxos)).unwrap()
            + wallet.balance_swap_coins(Some(&all_utxos)).unwrap();
        assert_eq!(normal_balance.to_sat(), 1998000);
    }

    let (first_maturity_heigh, second_maturity_height) =
        (first_conf_height + 100, second_conf_height + 100);

    // Wait for maturity and then redeem the bonds
    loop {
        let current_height = test_framework.get_block_count() as u32;
        let required_height = first_maturity_heigh.max(second_maturity_height);
        if current_height < required_height {
            log::info!(
                "Waiting for maturity. Current height {}, required height: {}",
                current_height,
                required_height
            );
            thread::sleep(Duration::from_secs(10));
            continue;
        } else {
            log::info!("Fidelity is matured. sending redemption transactions");
            let mut wallet_write = maker.get_wallet().write().unwrap();
            let indexes = wallet_write
                .get_fidelity_bonds()
                .keys()
                .cloned()
                .collect::<Vec<_>>();
            for i in indexes {
                wallet_write.redeem_fidelity(i).unwrap();
            }
            break;
        }
    }

    // Check the balances again
    {
        let wallet = maker.get_wallet().read().unwrap();
        let all_utxos = wallet.get_all_utxo().unwrap();
        let normal_balance = wallet.balance_descriptor_utxo(Some(&all_utxos)).unwrap()
            + wallet.balance_swap_coins(Some(&all_utxos)).unwrap();
        assert_eq!(normal_balance.to_sat(), 7996000);
    }

    // stop directory server
    let _ = directory_server_instance.shutdown();

    thread::sleep(Duration::from_secs(10));

    test_framework.stop();
}
