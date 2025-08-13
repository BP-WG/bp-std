// fra_demo5_final_solution_v3.rs

use std::str::FromStr;

use bitcoin::{
    self,
    consensus::encode,
    secp256k1::SecretKey,
    key::{Keypair, Secp256k1},
    absolute::LockTime,
    network::Network,
    sighash::{self, Prevouts, SighashCache, TapSighash},
    taproot::{self, LeafVersion, TaprootBuilder},
    Address, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};

use bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoincore_rpc::json::AddressType;

use derive::{
    fra::{build_fra_script, FraAction},
    XOnlyPk,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ===================================================================
    // 步骤 0-2: RPC 设置和 UTXO 准备
    // ===================================================================
    let rpc = Client::new(
        "http://127.0.0.1:18443/wallet/legacy_true",
        Auth::UserPass("foo".into(), "bar".into()),
    )?;
    rpc.import_private_key(
        &bitcoin::PrivateKey::from_wif("cVkVW14o6zBGyhaV2xqMsGEqYijB6jzsK5EkNcmzBPJejGmcBrMQ")?,
        None,
        None,
    )?;
    rpc.import_private_key(
        &bitcoin::PrivateKey::from_wif("cPMvbJRTmycMYU3pQ3dTfCwzVEtyVqpEeV3LWNaT1pzHhax2FKZF")?,
        None,
        None,
    )?;
    let coinbase_addr_unchecked = rpc.get_new_address(None, Some(AddressType::Legacy))?;
    let coinbase_addr = coinbase_addr_unchecked.require_network(Network::Regtest)?;
    rpc.generate_to_address(101, &coinbase_addr)?;
    let balance = rpc.get_balance(None, None)?;
    println!("Wallet balance: {} BTC", balance);
    let fund_utxo = rpc
        .list_unspent(None, None, None, None, None)?
        .into_iter()
        .find(|u| u.amount.to_sat() >= 100_000)
        .expect("没有足够的 UTXO (>= 0.001 BTC)");

    // ===================================================================
    // 步骤 3-4: 密钥生成
    // ===================================================================
    let secp = Secp256k1::new();
    let internal_kp = Keypair::new(&secp, &mut rand::thread_rng());
    let internal_pk = internal_kp.x_only_public_key().0;

    let sender_sk = SecretKey::from_slice(
        &bitcoin::PrivateKey::from_wif("cVkVW14o6zBGyhaV2xqMsGEqYijB6jzsK5EkNcmzBPJejGmcBrMQ")?
            .inner
            .secret_bytes(),
    )?;
    let sender_kp = Keypair::from_secret_key(&secp, &sender_sk);
    let sender_pk = sender_kp.x_only_public_key().0;

    let recv_sk = SecretKey::from_slice(
        &bitcoin::PrivateKey::from_wif("cPMvbJRTmycMYU3pQ3dTfCwzVEtyVqpEeV3LWNaT1pzHhax2FKZF")?
            .inner
            .secret_bytes(),
    )?;
    let recv_kp = Keypair::from_secret_key(&secp, &recv_sk);
    let recv_pk = recv_kp.x_only_public_key().0;

    // ===================================================================
    // 步骤 5-8: 地址生成 (调用 build_fra_script)
    // ===================================================================
    let action = FraAction::Transfer {
        asset_id: [0u8; 32],
        amount: 1000,
        receiver: XOnlyPk::from_byte_array(recv_pk.serialize()).unwrap(),
        sender: XOnlyPk::from_byte_array(sender_pk.serialize()).unwrap(),
    };
    let leaf_script_bytes = build_fra_script(action).as_unconfined().to_vec();
    let script = ScriptBuf::from(leaf_script_bytes);
    println!("Leaf Script ({} bytes): {}", script.len(), script.to_hex_string());

    let builder = TaprootBuilder::new().add_leaf(0, script.clone()).unwrap();
    let spend_info = builder.finalize(&secp, internal_pk).unwrap();
    let fra_addr = Address::p2tr(&secp, internal_pk, spend_info.merkle_root(), Network::Regtest);
    println!("FRA Taproot 地址: {}", fra_addr);

    // ===================================================================
    // 步骤 9-11: 交易注资和花费交易骨架构建
    // ===================================================================
    let rpc_address = Address::from_str(&fra_addr.to_string())?.assume_checked();
    let funding_txid = rpc.send_to_address(
        &rpc_address,
        Amount::from_sat(fund_utxo.amount.to_sat() - 10_000),
        None, None, None, None, None, None,
    )?;
    rpc.generate_to_address(1, &coinbase_addr)?;
    println!("Funding TXID: {}", funding_txid);
    let funding_tx_raw = rpc.get_raw_transaction(&funding_txid, None)?;
    let (vout, prevout_value) = funding_tx_raw
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.script_pubkey == fra_addr.script_pubkey())
        .map(|(i, o)| (i as u32, o.value))
        .expect("FRA UTXO not found in funding tx");
    let fra_outpoint = OutPoint {
        txid: funding_txid,
        vout,
    };

    let dest_addr_unchecked = rpc.get_new_address(None, Some(AddressType::Legacy))?;
    let dest_addr = dest_addr_unchecked.require_network(Network::Regtest)?;
    let mut spend_tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: fra_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: prevout_value - Amount::from_sat(10_000),
            script_pubkey: dest_addr.script_pubkey(),
        }],
    };
    let prevouts = vec![TxOut {
        value: prevout_value,
        script_pubkey: fra_addr.script_pubkey(),
    }];

    // ===================================================================
    // 步骤 12: 计算 Sighash
    // ===================================================================
    let mut sighasher = SighashCache::new(&spend_tx);
    let leaf_hash = taproot::TapLeafHash::from_script(&script, LeafVersion::TapScript);
    let sighash: TapSighash = sighasher
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            leaf_hash,
            sighash::TapSighashType::Default,
        )?;

    let msg = bitcoin::secp256k1::Message::from(sighash);
    println!("Sighash (rust-bitcoin): {}", sighash.to_string());

    // ===================================================================
    // 步骤 13: 签名并构建 Witness
    // ===================================================================
    let sig_sender = secp.sign_schnorr(&msg, &sender_kp);
    let sig_receiver = secp.sign_schnorr(&msg, &recv_kp);

    let control_block = spend_info
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .unwrap();

    let mut witness = Witness::new();

    // --- Witness 顺序必须与脚本消耗顺序相反 ---
    // 脚本: <sender_pk> OP_CHECKSIGVERIFY <receiver_pk> OP_CHECKSIG
    // 1. 脚本先验证 sender，所以 sender_sig 必须在栈顶。
    // 2. 为了让 sender_sig 在栈顶，它必须是最后一个被 push 的签名。
    witness.push(sig_receiver.as_ref()); // 先推入 receiver 签名 (对应 OP_CHECKSIG)
    witness.push(sig_sender.as_ref());   // 后推入 sender 签名 (对应 OP_CHECKSIGVERIFY)

    witness.push(script);
    witness.push(control_block.serialize());
    spend_tx.input[0].witness = witness;

    // ===================================================================
    // 步骤 14: 广播交易
    // ===================================================================
    let tx_hex = encode::serialize_hex(&spend_tx);
    println!("Final TX Hex: {}", tx_hex);

    let final_txid = rpc.send_raw_transaction(&*tx_hex)?;
    println!("\n🎉🎉🎉 交易成功广播! TXID = {} 🎉🎉🎉", final_txid);

    Ok(())
}