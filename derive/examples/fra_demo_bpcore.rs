// fra_demo4_method_a_aligned.rs

use std::{thread::sleep, time::Duration, str::FromStr};

use bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoincore_rpc::bitcoin::{
    Address as RpcAddress,
    Amount,
    Network,
    OutPoint,
    secp256k1::{Secp256k1, Keypair, SecretKey, XOnlyPublicKey, Message},
};
use bitcoincore_rpc::json::AddressType;
use bitcoin_hashes::Hash;
use amplify::hex::ToHex;

// bp-std / bp-core 相关类型（保持主导地位）
use derive::{
    fra::{FraAction, build_fra_control_blocks},
    XOnlyPk,
};
use bc::{
    self,
    ConsensusEncode,
    ScriptPubkey,
    SighashCache,
    Witness,
};
use amplify::{Wrapper, ByteArray};

/// helper: rpc OutPoint -> bc::Outpoint
fn to_bc_outpoint(rpc_out: OutPoint) -> bc::Outpoint {
    bc::Outpoint::new(
        bc::Txid::from_byte_array(rpc_out.txid.to_byte_array()),
        bc::Vout::from_u32(rpc_out.vout),
    )
}

/// helper: rpc TxOut -> bc::TxOut
fn to_bc_txout(rpc_txout: bitcoincore_rpc::bitcoin::TxOut) -> bc::TxOut {
    bc::TxOut {
        value: bc::Sats::from(rpc_txout.value.to_sat()),
        script_pubkey: ScriptPubkey::from_inner(
            bc::ScriptBytes::try_from(rpc_txout.script_pubkey.to_bytes()).unwrap()
        ),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 0) RPC + 钱包
    let rpc = Client::new(
        "http://127.0.0.1:18443/wallet/legacy_true",
        Auth::UserPass("foo".into(), "bar".into()),
    )?;
    // 导入两个演示用私钥
    rpc.import_private_key(&bitcoincore_rpc::bitcoin::PrivateKey::from_wif(
        "cVkVW14o6zBGyhaV2xqMsGEqYijB6jzsK5EkNcmzBPJejGmcBrMQ"
    )?, None, None)?;
    rpc.import_private_key(&bitcoincore_rpc::bitcoin::PrivateKey::from_wif(
        "cPMvbJRTmycMYU3pQ3dTfCwzVEtyVqpEeV3LWNaT1pzHhax2FKZF"
    )?, None, None)?;

    // 1) 挖 101 块确保 coinbase 成熟
    let coinbase_addr = rpc.get_new_address(None, Some(AddressType::Legacy))?
        .require_network(Network::Regtest)?;
    rpc.generate_to_address(101, &coinbase_addr)?;
    sleep(Duration::from_secs(3));

    // 2) 选 UTXO
    let balance = rpc.get_balance(None, None)?;
    println!("Wallet balance: {} BTC", balance.to_btc());
    let fund_utxo = rpc.list_unspent(None, None, None, None, None)?
        .into_iter()
        .find(|u| u.amount.to_sat() >= 100_000)
        .expect("没有足够的 UTXO (>= 0.001 BTC)");

    // 3) 生成 internal keypair（用于 Taproot internal key）
    let secp = Secp256k1::new();
    let internal_kp = Keypair::new(&secp, &mut rand::thread_rng());
    let internal_xonly_key: XOnlyPublicKey = internal_kp.public_key().x_only_public_key().0;

    // 转为 bp-core 的 InternalPk
    let internal_x_bytes = internal_xonly_key.serialize();
    let internal_xonly = XOnlyPk::from_byte_array(internal_x_bytes).expect("bad internal xonly");
    let internal_pk = bc::InternalPk::from_unchecked(internal_xonly);

    // 4) sender / receiver 密钥对
    let sender_priv = bitcoincore_rpc::bitcoin::PrivateKey::from_wif(
        "cVkVW14o6zBGyhaV2xqMsGEqYijB6jzsK5EkNcmzBPJejGmcBrMQ"
    )?;
    let recv_priv = bitcoincore_rpc::bitcoin::PrivateKey::from_wif(
        "cPMvbJRTmycMYU3pQ3dTfCwzVEtyVqpEeV3LWNaT1pzHhax2FKZF"
    )?;
    let sender_sk = SecretKey::from_slice(&sender_priv.inner.secret_bytes())?;
    let recv_sk = SecretKey::from_slice(&recv_priv.inner.secret_bytes())?;
    let sender_kp = Keypair::from_secret_key(&secp, &sender_sk);
    let recv_kp = Keypair::from_secret_key(&secp, &recv_sk);

    // 转为 bp-core XOnlyPk（用于脚本公钥字节）
    let sender_xonly_key = sender_kp.public_key().x_only_public_key().0;
    let recv_xonly_key = recv_kp.public_key().x_only_public_key().0;
    let sender_xonly = XOnlyPk::from_byte_array(sender_xonly_key.serialize()).expect("bad sender");
    let recv_xonly   = XOnlyPk::from_byte_array(recv_xonly_key.serialize()).expect("bad recv");

    // 5) 构造 FRA Transfer leaf（bp-std）
    //    <sender_pk> OP_CHECKSIGVERIFY <receiver_pk> OP_CHECKSIG
    let action = FraAction::Transfer {
        asset_id: [0u8; 32],
        amount: 1000,
        receiver: recv_xonly,
        sender: sender_xonly,
    };
    let depth: amplify::num::u7 = 0u8.try_into().unwrap();

    // 6) 用 bp-std 构建 (ControlBlock, LeafScript)
    let proofs = build_fra_control_blocks(internal_pk.clone(), vec![(action, depth)]);
    let (control_block, leaf_script) = &proofs[0];

    println!("⛑️ ControlBlock bytes: {:?}", control_block.consensus_serialize());
    println!("⛑️ LeafScript bytes: {:?}", leaf_script.script.as_inner());

    // 7) 计算 leaf hash（bp-core TapLeafHash），并转换为 rust-bitcoin TapNodeHash
    let leaf_hash = leaf_script.tap_leaf_hash();
    println!("Leaf Hash: {:?}", leaf_hash.to_byte_array().to_hex());
    let inner_arr = leaf_hash.into_inner();
    let inner_bytes = inner_arr.to_byte_array();
    let merkle_root = bitcoin::TapNodeHash::from_slice(&inner_bytes)
        .expect("Invalid tap node hash");

    // 8) 生成带脚本路径的 P2TR 地址（rust-bitcoin 计算 tweak）
    let fra_addr = bitcoincore_rpc::bitcoin::Address::p2tr(
        &secp,
        internal_xonly_key,
        Some(merkle_root),
        Network::Regtest,
    );
    let fra_spk = fra_addr.script_pubkey();
    println!("FRA Taproot 地址: {}", fra_addr);

    // 9) 广播 Funding TX（钱包自动签名）
    let rpc_addr = RpcAddress::from_str(&fra_addr.to_string())?.assume_checked();
    let fid = rpc.send_to_address(
        &rpc_addr,
        Amount::from_sat(fund_utxo.amount.to_sat().saturating_sub(10_000)),
        None, None, None, None, None, None,
    )?;
    rpc.generate_to_address(1, &coinbase_addr)?;
    sleep(Duration::from_secs(3));

    // 10) 找到 funding 输出并构造要花费的交易（bp-core Tx）
    let funding_tx = rpc.get_raw_transaction(&fid, None)?;
    let (idx, found_vout) = funding_tx.output.iter().enumerate()
        .find(|(_, o)| o.script_pubkey.to_bytes() == fra_spk.to_bytes())
        .expect("FRA UTXO not found");
    let fra_outpoint = OutPoint { txid: fid, vout: idx as u32 };

    let dest_addr = rpc.get_new_address(None, Some(AddressType::Legacy))?.assume_checked();
    let mut spend_tx = bc::Tx {
        version: bc::TxVer::V2,
        lock_time: bc::LockTime::ZERO,
        inputs: bc::VarIntArray::from_iter_checked([bc::TxIn {
            prev_output: to_bc_outpoint(fra_outpoint.clone()),
            sig_script: bc::SigScript::new(),
            sequence: bc::SeqNo::from_consensus_u32(0xFFFF_FFFF),
            witness: bc::Witness::new(),
        }]),
        outputs: bc::VarIntArray::from_iter_checked([bc::TxOut {
            value: bc::Sats::from(found_vout.value.to_sat().saturating_sub(10_000)),
            script_pubkey: ScriptPubkey::from_inner(
                bc::ScriptBytes::try_from(dest_addr.script_pubkey().to_bytes()).unwrap()
            ),
        }]),
    };

    // 11) 计算 sighash（bp-core 的 SighashCache）
    let prevout_bc = to_bc_txout(found_vout.clone());
    let mut cache = SighashCache::new(&mut spend_tx, vec![prevout_bc])?;
    let sighash = cache.tap_sighash_script(0, leaf_script.tap_leaf_hash(), None)?;
    let sighash_bytes: [u8; 32] = sighash.into();
    println!("Sighash: {}", sighash_bytes.to_hex());

    let msg = Message::from_digest_slice(&sighash_bytes).expect("32 bytes");

    // 12) 双方 Schnorr 签名
    let sig_sender = secp.sign_schnorr(&msg, &sender_kp);
    let sig_receiver = secp.sign_schnorr(&msg, &recv_kp);
    println!("sig_sender length: {}", sig_sender.as_ref().len());
    println!("sig_receiver length: {}", sig_receiver.as_ref().len());

    // 13) 组装 witness —— 与 fra_demo6.rs 完全一致
    // 脚本逻辑：<sender_pk> OP_CHECKSIGVERIFY <receiver_pk> OP_CHECKSIG
    // Witness（从栈顶 -> 栈底）：
    //   - receiver_sig  （对应最后一步 OP_CHECKSIG）
    //   - sender_sig    （对应第一步 OP_CHECKSIGVERIFY）
    //   - leaf_script
    //   - control_block
    spend_tx.inputs[0].witness = Witness::from_consensus_stack(vec![
        sig_receiver.as_ref().to_vec(), // 对应 <receiver_pk> OP_CHECKSIG
        sig_sender.as_ref().to_vec(),   // 对应 <sender_pk>   OP_CHECKSIGVERIFY
        leaf_script.script.as_inner().to_vec(),
        control_block.consensus_serialize(),
    ]);

    // 14) 广播（raw）
    let raw_bytes = spend_tx.consensus_serialize();
    let raw_hex = raw_bytes.to_hex();
    println!("RAW_TX_HEX: {}", raw_hex);
    let sid = rpc.send_raw_transaction(&*raw_hex)?;
    println!("🎉 Spend TXID = {}", sid);

    Ok(())
}