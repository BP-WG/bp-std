
use std::{thread::sleep, time::Duration};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoin::{
    Address, Amount, Network, OutPoint, Transaction, TxIn, TxOut, ScriptBuf, Sequence, Witness,
    absolute::LockTime, transaction::Version, consensus::encode::serialize,
    taproot::{TaprootBuilder, TaprootSpendInfo, LeafVersion, TapLeafHash},
    sighash::{SighashCache, Prevouts, TapSighashType},
    PrivateKey, secp256k1::{Secp256k1, SecretKey, Keypair, XOnlyPublicKey, Message},
};
use bitcoincore_rpc::json::AddressType;
use rand::thread_rng;
use derive::base58::{encode, decode};

#[allow(unused_imports)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 0) Connect to regtest RPC and load "legacy_true" wallet
    let rpc = Client::new(
        "http://127.0.0.1:18443/wallet/legacy_true",
        Auth::UserPass("foo".into(), "bar".into()),
    )?;
    // Import private keys
    let sender_wif = "cVkVW14o6zBGyhaV2xqMsGEqYijB6jzsK5EkNcmzBPJejGmcBrMQ";
    let receiver_wif = "cPMvbJRTmycMYU3pQ3dTfCwzVEtyVqpEeV3LWNaT1pzHhax2FKZF";
    rpc.import_private_key(&PrivateKey::from_wif(sender_wif)?, None, None)?;
    rpc.import_private_key(&PrivateKey::from_wif(receiver_wif)?, None, None)?;
    // Generate 101 blocks for coinbase maturity
    println!(">> Generating 101 blocks for coinbase maturity...");
    let coinbase_addr = rpc.get_new_address(None, Some(AddressType::Legacy))?.require_network(Network::Regtest)?;
    rpc.generate_to_address(210, &coinbase_addr)?;
    sleep(Duration::from_secs(3));
    println!(" Done. Funds are now available.");
    // Check wallet balance
    let balance = rpc.get_balance(None, None)?;
    println!("Wallet balance: {} BTC", balance.to_btc());

    // ---------------------------------------------------
    // STEP1: FUNDING — Create a FRA Taproot UTXO
    // ---------------------------------------------------
    let fund_utxo = rpc.list_unspent(None, None, None, None, None)?
        .into_iter()
        .find(|utxo| utxo.amount.to_sat() >= 100_000)
        .expect("No UTXO with sufficient funds (>= 0.001 BTC)");
    println!("Fund UTXO amount: {} BTC", fund_utxo.amount.to_btc());

    // 1) Generate Internal KeyPair
    let secp = Secp256k1::new();
    let internal_kp = Keypair::new(&secp, &mut thread_rng());
    let (internal_xonly, _) = internal_kp.x_only_public_key();
    println!("Internal PK: {:?}", encode(&internal_xonly.serialize()));

    // 2) Parse sender/receiver private keys
    let sender_secret = PrivateKey::from_wif(sender_wif)?.inner;
    let receiver_secret = PrivateKey::from_wif(receiver_wif)?.inner;
    let sender_kp = Keypair::from_secret_key(&secp, &sender_secret);
    let receiver_kp = Keypair::from_secret_key(&secp, &receiver_secret);
    let (sender_xonly, _) = sender_kp.x_only_public_key();
    let (receiver_xonly, _) = receiver_kp.x_only_public_key();
    let sender_pk_bytes = sender_xonly.serialize();
    let receiver_pk_bytes = receiver_xonly.serialize();
    println!("Sender PK: {:?}", encode(&sender_pk_bytes));
    println!("Receiver PK: {:?}", encode(&receiver_pk_bytes));
    // Verify public keys
    let expected_sender_pk = "d8254e7443d48c701e10dc7ae8e8e429c71f4d07100d3fcc4d374f103759764e";
    let expected_receiver_pk = "a969d4a73fdc45987eb2ec968026045cd8050750956ff0ccca38f5ee1c8032cc";
    if encode(&sender_pk_bytes) != expected_sender_pk {
        println!("Sender PK mismatch: expected {}, got {}", expected_sender_pk, encode(&sender_pk_bytes));
        return Err("Sender public key does not match expected value".into());
    }
    if encode(&receiver_pk_bytes) != expected_receiver_pk {
        println!("Receiver PK mismatch: expected {}, got {}", expected_receiver_pk, encode(&receiver_pk_bytes));
        return Err("Receiver public key does not match expected value".into());
    }

    // 3) Construct FRA script using bitcoin::ScriptBuf
    let mut script_bytes = vec![];
    script_bytes.push(0x20); // OP_PUSHDATA1
    script_bytes.extend_from_slice(&sender_pk_bytes);
    script_bytes.push(0x7c); // OP_SWAP
    script_bytes.push(0xad); // OP_CHECKSIGVERIFY
    script_bytes.push(0x20); // OP_PUSHDATA1
    script_bytes.extend_from_slice(&receiver_pk_bytes);
    script_bytes.push(0x7c); // OP_SWAP
    script_bytes.push(0xac); // OP_CHECKSIG
    let tap_script = ScriptBuf::from(script_bytes);
    println!("Generated Script Bytes: {:?}", encode(&tap_script.to_bytes()));
    // Verify script
    let expected_script = "20d8254e7443d48c701e10dc7ae8e8e429c71f4d07100d3fcc4d374f103759764e7cad20a969d4a73fdc45987eb2ec968026045cd8050750956ff0ccca38f5ee1c8032cc7cac";
    assert_eq!(encode(&tap_script.to_bytes()), expected_script);

    // 4) Build Taproot scriptPubKey
    let tap_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone())?
        .finalize(&secp, internal_xonly)
        .map_err(|e| format!("Taproot finalize failed: {:?}", e))?;
    let fra_addr = Address::p2tr(&secp, internal_xonly, tap_info.merkle_root(), Network::Regtest);
    let fra_spk = fra_addr.script_pubkey();
    println!("FRA Address: {}", fra_addr);
    println!("Taproot Merkle Root: {:?}", tap_info.merkle_root());

    // 5) Broadcast Funding TX
    let send_val = fund_utxo.amount.to_sat().saturating_sub(10_000);
    if send_val < 546 {
        return Err("Transaction amount too small: must be at least 546 satoshi".into());
    }
    let fid = rpc.send_to_address(&fra_addr, Amount::from_sat(send_val), None, None, None, None, None, None)?;
    println!(">> STEP1: Funding txid = {}", fid);
    rpc.generate_to_address(1, &coinbase_addr)?;
    sleep(Duration::from_secs(3));

    // ---------------------------------------------------
    // STEP2: SPENDING — Spend the FRA UTXO
    // ---------------------------------------------------
    println!(">> STEP2: Finding FRA UTXO from funding tx {}", fid);
    let funding_tx = rpc.get_raw_transaction(&fid, None)?;
    let (fra_vout, fra_txout) = funding_tx.output.iter().enumerate()
        .find(|(_vout, txout)| txout.script_pubkey == fra_spk)
        .expect("No output matching fra_spk in funding transaction");
    let fra_outpoint = OutPoint { txid: fid, vout: fra_vout as u32 };
    let fra_amount = fra_txout.value;
    println!(" Found FRA UTXO at {}:{} with value {} BTC", fid, fra_vout, fra_amount.to_btc());

    let left = fra_amount.to_sat().saturating_sub(10_000);
    if left < 546 {
        return Err("Spend transaction amount too small: must be at least 546 satoshi".into());
    }
    let spend_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: fra_outpoint.clone(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xFFFF_FFFF),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(left),
            script_pubkey: rpc.get_new_address(None, Some(AddressType::Legacy))?.require_network(Network::Regtest)?.script_pubkey(),
        }],
    };

    // 6) Calculate Taproot Sighash
    let mut cache = SighashCache::new(&spend_tx);
    let tapleaf_hash = TapLeafHash::from_script(&tap_script, LeafVersion::TapScript);
    let sighash = cache.taproot_script_spend_signature_hash(
        0,
        &Prevouts::All(&[fra_txout.clone()]),
        tapleaf_hash,
        TapSighashType::Default,
    )?;
    let msg = Message::from_digest_slice(sighash.as_ref())?;
    println!("Sighash: {:?}", encode(sighash.as_ref()));

    // 7) Generate Schnorr signatures
    let sig_sender = secp.sign_schnorr(&msg, &sender_kp);
    let sig_receiver = secp.sign_schnorr(&msg, &receiver_kp);
    let is_sender_sig_valid = secp.verify_schnorr(&sig_sender, &msg, &sender_xonly);
    let is_receiver_sig_valid = secp.verify_schnorr(&sig_receiver, &msg, &receiver_xonly);
    println!("Sender signature valid: {}", is_sender_sig_valid.is_ok());
    println!("Receiver signature valid: {}", is_receiver_sig_valid.is_ok());
    let sig_sender_bytes = sig_sender.as_ref().to_vec();
    let sig_receiver_bytes = sig_receiver.as_ref().to_vec();
    println!("Sig Sender: {:?}", encode(&sig_sender_bytes));
    println!("Sig Receiver: {:?}", encode(&sig_receiver_bytes));

    // 8) Generate Control Block
    let control_block_bytes = tap_info.control_block(&(tap_script.clone(), LeafVersion::TapScript))
        .expect("Failed to get control block")
        .serialize();
    println!("Control Block: {:?}", encode(&control_block_bytes));

    // 9) Assemble Witness and broadcast
    let mut final_tx = spend_tx.clone();
    final_tx.input[0].witness = Witness::from_slice(&[
        sig_sender_bytes,    // Corresponds to sender_pk (OP_CHECKSIGVERIFY)
        sig_receiver_bytes,  // Corresponds to receiver_pk (OP_CHECKSIG)
        tap_script.to_bytes(),
        control_block_bytes,
    ]);
    println!("Final Witness elements:");
    for (i, elem) in final_tx.input[0].witness.iter().enumerate() {
        println!(" Witness[{}] (len {}): {:?}", i, elem.len(), encode(elem));
    }

    let raw_spend = serialize(&final_tx);
    println!("Raw Spend Tx: {:?}", encode(&raw_spend));
    let sid = rpc.send_raw_transaction(&raw_spend)?;
    println!("Spend txid = {}", sid);
    Ok(())
}
