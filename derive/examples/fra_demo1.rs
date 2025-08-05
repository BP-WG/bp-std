// derive/examples/fra_demo.rs

use std::str::FromStr;
use strict_encoding::StreamWriter;
use derive::secp256k1::{Secp256k1, Keypair};
use rand::thread_rng;
use bitcoincore_rpc::{Auth, Client, RpcApi};

// 全部从 bitcoincore_rpc::bitcoin 引入，不要再用单独的 bitcoin crate
use bitcoincore_rpc::bitcoin::{
    Transaction, TxIn, TxOut, OutPoint, Address,
    ScriptBuf, Sequence, Witness,
    absolute::LockTime, Amount,
    taproot::{TapLeafHash, LeafVersion},
    sighash::{SighashCache, Prevouts, TapSighashType},
    consensus::encode::serialize,
    Network, transaction::Version, Script,
};
// 用 StrictWriter 来做 TypedWrite
use strict_encoding::StrictEncode;

// 从你的 derive crate 拿到 FRA 相关类型和工厂
use derive::fra::{FraAction, build_fra_control_blocks};
use bc::{InternalPk, OutputPk, XOnlyPk};

use amplify::num::u7;

fn main() {
    // 1) RPC setup
    let rpc = Client::new(
        "http://127.0.0.1:18443",
        Auth::UserPass("foo".into(), "bar".into()),
    ).unwrap();

    // 2) 拿一个可花 UTXO
    let utxo = rpc
        .list_unspent(None, None, None, None, None)
        .unwrap()
        .into_iter()
        .next()
        .expect("请先在 regtest 挖矿并生产 UTXO");
    let outpoint = OutPoint { txid: utxo.txid, vout: utxo.vout };

    // 原 UTXO 的脚本和金额
    let prev_amount = utxo.amount;
    let prev_script = utxo.script_pub_key.clone();

    // 构造 TxIn
    let txin = TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence(0xFFFF_FFFF),
        witness: Witness::new(),
    };

    // 3) 构造普通的发送输出：从 RPC 拿一个新地址，并校验网络
    let recipient = rpc.get_new_address(None, None).unwrap()
        .require_network(Network::Regtest).unwrap();
    let fee = 1_000u64;
    let send_sat = utxo.amount.to_sat() - fee;
    let txout = TxOut {
        value: Amount::from_sat(send_sat),
        script_pubkey: recipient.script_pubkey(),
    };


    let mut tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![txin],
        output: vec![txout],
    };

    // 4) 用随机密钥生成 InternalPk / OutputPk
    let secp = Secp256k1::new();
    let mut rng = thread_rng();

    // Internal key for Taproot tweak
    let internal_kp = Keypair::new(&secp, &mut rng);
    let (ix, _) = internal_kp.x_only_public_key();
    // From<bitcoin::XOnlyPublicKey> for XOnlyPk, then From<XOnlyPk> for InternalPk:
    let internal_pk = InternalPk::from(XOnlyPk::from(ix));

    // Sender
    let sender_kp = Keypair::new(&secp, &mut rng);
    let (sx, _) = sender_kp.x_only_public_key();
    let sender_pk = OutputPk::from(XOnlyPk::from(sx));

    // Receiver
    let recv_kp = Keypair::new(&secp, &mut rng);
    let (rx, _) = recv_kp.x_only_public_key();
    let receiver_pk = OutputPk::from(XOnlyPk::from(rx));

    // 5) 构造 FRA Merkle 证明
    let depth = u7::try_from(0).unwrap();
    let action = FraAction::Transfer {
        asset_id: [0u8; 32],
        amount:   1_000,
        receiver: receiver_pk.clone(),
        sender:   sender_pk.clone(),
    };
    let proofs = build_fra_control_blocks(internal_pk, vec![(action, depth)]);
    let (control_block, leaf_script) = &proofs[0];

    // 6) 计算 sighash
    let mut cache = SighashCache::new(&tx);
    let tapleaf = TapLeafHash::from_script(
        &Script::from_bytes(leaf_script.script.as_slice()),
        LeafVersion::TapScript,
    );
    let sighash = cache.taproot_script_spend_signature_hash(
        0,
        &Prevouts::All(&[TxOut { value: prev_amount, script_pubkey: prev_script }]),
        tapleaf,
        TapSighashType::Default,
    ).unwrap();

    // 7) Schnorr 签名：直接用 TapSighash 的字节切片
    let hash_bytes: &[u8; 32] = sighash.as_ref();
    let sig_recv = secp.sign_schnorr(hash_bytes, &recv_kp);
    let sig_send = secp.sign_schnorr(hash_bytes, &sender_kp);

    // 8) 填充 witness 并广播
    let mut wit = Vec::new();
    wit.push(sig_recv.as_ref().to_vec());
    wit.push(sig_send.as_ref().to_vec());
    // —— 把 TapScript 脚本本身压进去 ——
    // 先将 Confined<Vec<u8>, …> 强制成 &[u8]，再 to_vec()
    let script_slice: &[u8] = leaf_script.script.as_ref();
    wit.push(script_slice.to_vec());
    // ControlBlock 序列化 -> Vec<u8>
    let mut cb_ser = Vec::new();
    let writer: StreamWriter<&mut Vec<u8>> = StreamWriter::new::<1024>(&mut cb_ser);
    control_block.strict_write(writer).unwrap();
    wit.push(cb_ser);

    tx.input[0].witness = Witness::from_slice(&wit);

    let raw_tx = serialize(&tx);
    let txid   = rpc.send_raw_transaction(&raw_tx[..]).unwrap();
    println!("Broadcast txid = {}", txid);
}