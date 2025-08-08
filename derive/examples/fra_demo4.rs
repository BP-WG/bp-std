// fra_demo4_method_a.rs
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
    // 【修改】bitcoincore-rpc 的 Txid 需要先 as_hash() 再 to_byte_array()
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
    // 确保用于 demo 的两个私钥已导入钱包（只是为了方便广播 funding tx）
    rpc.import_private_key(&bitcoincore_rpc::bitcoin::PrivateKey::from_wif(
        "cVkVW14o6zBGyhaV2xqMsGEqYijB6jzsK5EkNcmzBPJejGmcBrMQ"
    )?, None, None)?;
    rpc.import_private_key(&bitcoincore_rpc::bitcoin::PrivateKey::from_wif(
        "cPMvbJRTmycMYU3pQ3dTfCwzVEtyVqpEeV3LWNaT1pzHhax2FKZF"
    )?, None, None)?;

    // 1) 挖 101 确保 coinbase 成熟
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
    // 【注意】这里保留 bitcoin::secp256k1::XOnlyPublicKey 以便传给 rust-bitcoin::Address::p2tr
    let internal_xonly_key: XOnlyPublicKey = internal_kp.public_key().x_only_public_key().0;

    // 同时为了 bp-core 使用，将其转换为 bp-core 的 XOnlyPk -> InternalPk
    let internal_x_bytes = internal_xonly_key.serialize();
    let internal_xonly = XOnlyPk::from_byte_array(internal_x_bytes).expect("bad internal xonly");
    let internal_pk = bc::InternalPk::from_unchecked(internal_xonly);

    // 4) 解析 sender / receiver 私钥，并建 keypairs（用于签名）
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

    // 构造 bp-core XOnlyPk（用于脚本中的公钥字节）
    let sender_xonly_key = sender_kp.public_key().x_only_public_key().0;
    let recv_xonly_key = recv_kp.public_key().x_only_public_key().0;
    let sender_xonly = XOnlyPk::from_byte_array(sender_xonly_key.serialize()).expect("bad sender");
    let recv_xonly   = XOnlyPk::from_byte_array(recv_xonly_key.serialize()).expect("bad recv");

    // 5) 构造 FRA Transfer leaf（bp-std）
    let action = FraAction::Transfer {
        asset_id: [0u8; 32],
        amount: 1000,
        receiver: recv_xonly,
        sender: sender_xonly,
    };
    let depth: amplify::num::u7 = 0u8.try_into().unwrap();

    // 6) 使用 bp-std 构建 ControlBlock + LeafScript
    let proofs = build_fra_control_blocks(internal_pk.clone(), vec![(action, depth)]);
    let (control_block, leaf_script) = &proofs[0];

    println!("⛑️ ControlBlock bytes: {:?}", control_block.consensus_serialize());
    println!("⛑️ LeafScript bytes: {:?}", leaf_script.script.as_inner());

    // 7) 计算 leaf hash (bp-core TapLeafHash)
    let leaf_hash = leaf_script.tap_leaf_hash(); // bp-core 类型

    // ---------------------------
    // 【关键：Method A 的单一转换点】
    // 在此把 bp-core 的 TapLeafHash（bytes） -> bitcoin::TapNodeHash（rust-bitcoin）
    // 仅此一次的字节级转换，然后传给 Address::p2tr。
    // 这样 rust-bitcoin 会自己计算 tweak（internal_xonly + merkle_root），
    // 并生成与 bp-core 相同的 tweaked output key。
    // ---------------------------
    let inner_arr = leaf_hash.into_inner(); // 得到 amplify::Array<u8, 32>
    let inner_bytes = inner_arr.to_byte_array(); // -> [u8; 32]
    let merkle_root = bitcoin::TapNodeHash::from_slice(&inner_bytes)
        .expect("Invalid tap node hash");


    // 8) 用 rust-bitcoin 的 Address::p2tr 生成带脚本路径的 P2TR 地址
    //    传入 internal_xonly_key 和 merkle_root（上一步转好的）
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
    // 确认 funding
    rpc.generate_to_address(1, &coinbase_addr)?;
    sleep(Duration::from_secs(3));

    // 10) 找到 funding 输出并构造要花费的交易（用 bp-core 的 Tx）
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

    // 11) 计算 sighash（仍然用 bp-core 的 SighashCache）
    let prevout_bc = to_bc_txout(found_vout.clone());
    let mut cache = SighashCache::new(&mut spend_tx, vec![prevout_bc])?;
    let sighash = cache.tap_sighash_script(0, leaf_hash, None)?; // bp-core TapSighash
    let sighash_bytes: [u8; 32] = sighash.into(); // 转成 32 字节数组
    let msg = Message::from_digest_slice(&sighash_bytes).expect("32 bytes");


    // 12) signer：双方用 schnorr 签名（message + keypair）
    let sig_sender = secp.sign_schnorr(&msg, &sender_kp);
    let sig_receiver = secp.sign_schnorr(&msg, &recv_kp);

    // 13) 组装 witness（遵循脚本：接收方签名在前 -> 发送方签名 -> script -> control_block）
    spend_tx.inputs[0].witness = Witness::from_consensus_stack(vec![
        sig_receiver.as_ref().to_vec(),
        sig_sender.as_ref().to_vec(),
        leaf_script.script.as_inner().to_vec(),
        control_block.consensus_serialize(),
    ]);

    // 14) 广播（raw）
    let raw = spend_tx.consensus_serialize();
    let sid = rpc.send_raw_transaction(&raw)?;
    println!("🎉 Spend TXID = {}", sid);

    Ok(())
}
