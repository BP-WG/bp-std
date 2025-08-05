// derive/examples/fra_demo.rs

use std::{thread::sleep, time::Duration};

use bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoincore_rpc::bitcoin::{
    Address, Amount, Network,
    OutPoint, Transaction, TxIn, TxOut,
    ScriptBuf, Sequence, Witness,
    absolute::LockTime, transaction::Version,
    consensus::encode::serialize,
    taproot::{TaprootBuilder, TaprootSpendInfo, LeafVersion, TapLeafHash},
    sighash::{SighashCache, Prevouts, TapSighashType},
    PrivateKey,
    secp256k1::{
        Secp256k1 as BitcoinSecp,
        SecretKey as BitcoinSecretKey,
        Keypair as BitcoinKeypair,
        XOnlyPublicKey as BitcoinXOnlyPublicKey,
        Message as BitcoinMessage,
    },
};
use bitcoincore_rpc::json::AddressType;

use derive::fra::{FraAction, build_fra_control_blocks};
use bc::{InternalPk, OutputPk, XOnlyPk};
use secp256k1::{
    Secp256k1 as DeriveSecp,
    SecretKey as DeriveSecretKey,
    Keypair as DeriveKeypair,
};

use rand::thread_rng;
use amplify::num::u7;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 0) 连接 regtest RPC，并加载“legacy_true”钱包
    let rpc = Client::new(
        "http://127.0.0.1:18443/wallet/legacy_true",
        Auth::UserPass("foo".into(), "bar".into()),
    )?;

    // 确保私钥已导入
    rpc.import_private_key(&PrivateKey::from_wif("cVkVW14o6zBGyhaV2xqMsGEqYijB6jzsK5EkNcmzBPJejGmcBrMQ")?, None, None)?;
    rpc.import_private_key(&PrivateKey::from_wif("cPMvbJRTmycMYU3pQ3dTfCwzVEtyVqpEeV3LWNaT1pzHhax2FKZF")?, None, None)?;

    // (Optional) 挖 101 块，生成成熟 UTXO
    println!(">> Generating 101 blocks for coinbase maturity...");
    let coinbase_addr = rpc.get_new_address(None, Some(AddressType::Legacy))?.require_network(Network::Regtest)?;
    rpc.generate_to_address(101, &coinbase_addr)?;
    sleep(Duration::from_secs(3));
    println!("   Done. Funds are now available.");

    // 检查钱包余额
    let balance = rpc.get_balance(None, None)?;
    println!("Wallet balance: {} BTC", balance.to_btc());

    // ---------------------------------------------------
    // STEP1: FUNDING — 铸造一个 FRA Taproot UTXO
    // ---------------------------------------------------
    let fund_utxo = rpc.list_unspent(None, None, None, None, None)?
        .into_iter()
        .find(|utxo| utxo.amount.to_sat() >= 100_000) // 确保 UTXO 金额足够
        .expect("没有找到金额足够的 UTXO（需 >= 0.001 BTC）");
    let _fund_outpoint = OutPoint { txid: fund_utxo.txid, vout: fund_utxo.vout };
    println!("Fund UTXO amount: {} BTC", fund_utxo.amount.to_btc());

    // 1) DERIVE：生成 Internal KeyPair（FRA 控制块用）
    let derive_secp = DeriveSecp::new();
    let mut rng = thread_rng();
    let derive_internal_kp = DeriveKeypair::new(&derive_secp, &mut rng);
    let (derive_ix, _) = derive_internal_kp.x_only_public_key();
    let internal_pk = InternalPk::from(derive_ix);

    // 2) 解析发送者/接收者 WIF 私钥（bitcoin crate）
    let sender_secret: BitcoinSecretKey = PrivateKey::from_wif(
        "cVkVW14o6zBGyhaV2xqMsGEqYijB6jzsK5EkNcmzBPJejGmcBrMQ"
    )?.inner;
    let recv_secret: BitcoinSecretKey = PrivateKey::from_wif(
        "cPMvbJRTmycMYU3pQ3dTfCwzVEtyVqpEeV3LWNaT1pzHhax2FKZF"
    )?.inner;

    // 3) bitcoin-secret → derive-secret → derive KeyPair → OutputPk
    let derive_sender_sk = DeriveSecretKey::from_slice(&sender_secret.secret_bytes())?;
    let derive_recv_sk = DeriveSecretKey::from_slice(&recv_secret.secret_bytes())?;
    let derive_sender_kp = DeriveKeypair::from_secret_key(&derive_secp, &derive_sender_sk);
    let derive_recv_kp = DeriveKeypair::from_secret_key(&derive_secp, &derive_recv_sk);
    let (sx, _) = derive_sender_kp.x_only_public_key();
    let (rx, _) = derive_recv_kp.x_only_public_key();
    let sender_xonly_pk = XOnlyPk::from(sx);
    let receiver_xonly_pk = XOnlyPk::from(rx);

    println!("Sender PK bytes length: {}", sender_xonly_pk.to_byte_array().len());
    println!("Receiver PK bytes length: {}", receiver_xonly_pk.to_byte_array().len());
    // 4) 构造 FRA Transfer Leaf
    let action = FraAction::Transfer {
        asset_id: [0u8; 32],
        amount: 1000,
        receiver: receiver_xonly_pk,
        sender: sender_xonly_pk,
    };
    let depth = u7::try_from(0).unwrap();
    let proofs = build_fra_control_blocks(internal_pk.clone(), vec![(action, depth)]);
    let (control_block, leaf_script) = &proofs[0];

    // ---------------------------------------------------
    // ---------------------------------------------------
    // STEP1.5: 构建 Taproot scriptPubKey
    // ---------------------------------------------------
    let bitcoin_secp = BitcoinSecp::new();
    let bitcoin_ix = BitcoinXOnlyPublicKey::from_slice(&derive_ix.serialize())?;

    // 取出 leaf 脚本字节
    let sb = ScriptBuf::from(AsRef::<[u8]>::as_ref(&leaf_script.script).to_vec()); // 不再手动添加 OP_DROP

    let tap_info: TaprootSpendInfo = TaprootBuilder::new()
        .add_leaf(depth.into(), sb.clone())?
        .finalize(&bitcoin_secp, bitcoin_ix)
        .expect("Taproot finalize failed");
    let fra_addr = Address::p2tr(
        &bitcoin_secp,
        bitcoin_ix,
        tap_info.merkle_root(),
        Network::Regtest,
    );
    let fra_spk = fra_addr.script_pubkey();

    // 5) 广播 Funding TX via 钱包 RPC，自动签名
    let send_val = fund_utxo.amount.to_sat().saturating_sub(10_000); // 降低费用预留到 0.0001 BTC
    println!("Sending value: {} satoshi", send_val);
    if send_val < 546 {
        return Err("Transaction amount too small: must be at least 546 satoshi".into());
    }
    let fid = rpc.send_to_address(
        &fra_addr,
        Amount::from_sat(send_val),
        None, // label
        None, // comment
        None, // comment_to
        None, // replaceable
        None, // conf_target
        None, // estimate_mode
    )?;
    println!(">> STEP1: Funding txid = {}", fid);
    // 立即挖一块确认
    let confirm_addr = rpc.get_new_address(None, Some(AddressType::Legacy))?.require_network(Network::Regtest)?;
    rpc.generate_to_address(1, &confirm_addr)?;
    sleep(Duration::from_secs(3));

    // ---------------------------------------------------
    // STEP2: SPENDING — 花费 FRA UTXO
    // ---------------------------------------------------
    println!(">> STEP2: Finding FRA UTXO from funding tx {}", fid);
    let funding_tx = rpc.get_raw_transaction(&fid, None)?;
    let (fra_vout, fra_txout) = funding_tx.output.iter().enumerate()
        .find(|(_vout, txout)| txout.script_pubkey == fra_spk)
        .expect("在 funding transaction 中没找到与 fra_spk 匹配的输出");
    let fra_outpoint = OutPoint { txid: fid, vout: fra_vout as u32 };
    let fra_amount = fra_txout.value;
    println!("   Found FRA UTXO at {}:{} with value {} BTC", fid, fra_vout, fra_amount.to_btc());

    let left = fra_amount.to_sat().saturating_sub(10_000); // 降低费用预留
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

    // 6) 计算 Taproot‑FRA 花费 sighash
    let mut cache = SighashCache::new(&spend_tx);
    let tapleaf_hash = TapLeafHash::from_script(&sb, LeafVersion::TapScript);
    let sighash = cache.taproot_script_spend_signature_hash(
        0,
        &Prevouts::All(&[fra_txout.clone()]),
        tapleaf_hash,
        TapSighashType::Default,
    )?;
    let msg = BitcoinMessage::from_digest_slice(sighash.as_ref())?;
    println!("Sighash: {:?}", AsRef::<[u8]>::as_ref(&sighash));

    // 7) 双 Schnorr 签名
    let btc_sender_kp = BitcoinKeypair::from_secret_key(&bitcoin_secp, &sender_secret);
    let btc_recv_kp = BitcoinKeypair::from_secret_key(&bitcoin_secp, &recv_secret);

    let sig_sender = bitcoin_secp.sign_schnorr(&msg, &btc_sender_kp);
    let sig_receiver = bitcoin_secp.sign_schnorr(&msg, &btc_recv_kp); // 确保这里是接收方的签名
    // 添加以下验证代码
    let is_sender_sig_valid = bitcoin_secp.verify_schnorr(&sig_sender, &msg, &btc_sender_kp.x_only_public_key().0);
    let is_receiver_sig_valid = bitcoin_secp.verify_schnorr(&sig_receiver, &msg, &btc_recv_kp.x_only_public_key().0);

    println!("Sender signature internal verification: {}", is_sender_sig_valid.is_ok());
    println!("Receiver signature internal verification: {}", is_receiver_sig_valid.is_ok());

    let sig_sender_bytes = sig_sender.as_ref().to_vec();
    let sig_receiver_bytes = sig_receiver.as_ref().to_vec();

    println!("Signature receiver length: {}", sig_receiver_bytes.len()); // 应该显示 64
    println!("Signature sender length: {}", sig_sender_bytes.len());   // 应该显示 64

    // 8) 使用 TaprootSpendInfo 生成正确的 ControlBlock
    let control_block_bytes = tap_info.control_block(&(sb.clone(), LeafVersion::TapScript))
        .expect("Failed to get control block")
        .serialize();
    println!("ControlBlock bytes length: {}", control_block_bytes.len());
    println!("Script bytes: {:?}", sb.to_bytes());
    println!("ControlBlock bytes: {:?}", control_block_bytes);

    // 9) 填 witness 并广播 Spend TX
    let mut final_tx = spend_tx.clone();
    final_tx.input[0].witness = Witness::from_slice(&[
        sig_receiver_bytes,     // <--- ！！！关键修正：接收方签名必须在第一个位置 (栈顶)
        sig_sender_bytes,       // 发送方签名 (在接收方签名之后消耗)
        sb.to_bytes(),          // 完整的脚本
        control_block_bytes,    // control block
    ]);
    println!("Final Witness elements:");
    for (i, elem) in final_tx.input[0].witness.iter().enumerate() {
        println!("  Witness[{}] (len {}): {:?}", i, elem.len(), elem);
    }
    let raw_spend = serialize(&final_tx);
    let sid = rpc.send_raw_transaction(&raw_spend[..])?;
    println!("Spend txid = {}", sid);

    Ok(())
}