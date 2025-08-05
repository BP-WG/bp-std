use std::{thread::sleep, time::Duration, str::FromStr};

use bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoincore_rpc::bitcoin::{
    Address as RpcAddress, Amount, Network, OutPoint, Transaction, TxIn, TxOut,
    Sequence, Witness, absolute::LockTime, transaction::Version,PrivateKey,
    hashes::Hash,
};
use bitcoincore_rpc::json::AddressType;

// --- 使用 bp-std 生态系统内的类型 ---
use derive::{self, fra::{FraAction, build_fra_script, build_fra_control_blocks}, base58::encode, KeyOrigin, XOnlyPk, Xpriv, XpubDerivable};
use bc::{self, ConsensusEncode, ScriptPubkey, SighashCache, SighashFlag, SighashType, TapSighash, TapMerklePath, TapNodeHash , TapBranchHash};
use invoice::{Address, AddressNetwork, AddressPayload};
use secp256k1::{Secp256k1, Message, Keypair, SecretKey, PublicKey};
use amplify::{Wrapper, ByteArray, hex}; // [修复] 导入 Wrapper, ByteArray 和 hex


// `bitcoincore-rpc` 生态系统使用的版本（通过其依赖 `bitcoin`）
use bitcoincore_rpc::bitcoin::secp256k1 as bitcoin_secp;



// ... (所有帮助函数保持不变) ...
fn to_bc_outpoint(rpc_outpoint: OutPoint) -> bc::Outpoint {
    bc::Outpoint::new(
        bc::Txid::from_byte_array(rpc_outpoint.txid.to_byte_array()),
        bc::Vout::from_u32(rpc_outpoint.vout)
    )
}

fn to_bc_txout(rpc_txout: bitcoincore_rpc::bitcoin::TxOut) -> bc::TxOut {
    bc::TxOut {
        value: bc::Sats::from(rpc_txout.value.to_sat()),
        script_pubkey: ScriptPubkey::from_inner(
            bc::ScriptBytes::try_from(rpc_txout.script_pubkey.to_bytes()).unwrap()
        ),
    }
}

fn calculate_merkle_root(path: &TapMerklePath, leaf_hash: bc::TapLeafHash) -> TapNodeHash {
    let mut current_hash: TapNodeHash = leaf_hash.into();
    for sibling_hash in path.iter() {
        current_hash = bc::TapBranchHash::with_nodes(current_hash, (*sibling_hash).into()).into();
    }
    current_hash
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc = Client::new(
        "http://127.0.0.1:18443/wallet/legacy_true",
        Auth::UserPass("foo".into(), "bar".into()),
    )?;
    rpc.import_private_key(&PrivateKey::from_wif("cVkVW14o6zBGyhaV2xqMsGEqYijB6jzsK5EkNcmzBPJejGmcBrMQ")?, None, None)?;
    rpc.import_private_key(&PrivateKey::from_wif("cPMvbJRTmycMYU3pQ3dTfCwzVEtyVqpEeV3LWNaT1pzHhax2FKZF")?, None, None)?;

    let coinbase_addr = rpc.get_new_address(None, Some(AddressType::Legacy))?.assume_checked();
    rpc.generate_to_address(101, &coinbase_addr)?;
    sleep(Duration::from_secs(3));

    let secp = Secp256k1::new();

    // 1. 生成内部密钥
    let internal_keypair = Keypair::new(&secp, &mut rand::thread_rng());
    // [最终修复] 显式地从 PublicKey 获取 XOnlyPublicKey，与 simple_test.rs 保持一致
    let internal_public_key = PublicKey::from_keypair(&internal_keypair);
    let (internal_pk_xonly, _) = internal_public_key.x_only_public_key();
    let internal_pk = bc::InternalPk::from(XOnlyPk::from(internal_pk_xonly));

    // 2. 解析发送方/接收方私钥
    let sender_secret_rpc = PrivateKey::from_wif("cVkVW14o6zBGyhaV2xqMsGEqYijB6jzsK5EkNcmzBPJejGmcBrMQ")?.inner;
    let sender_secret = SecretKey::from_slice(&sender_secret_rpc.secret_bytes())?;
    let sender_keypair = Keypair::from_secret_key(&secp, &sender_secret);
    let sender_public_key = PublicKey::from_keypair(&sender_keypair);
    let (sender_pk_xonly, _) = sender_public_key.x_only_public_key();

    let recv_secret_rpc = PrivateKey::from_wif("cPMvbJRTmycMYU3pQ3dTfCwzVEtyVqpEeV3LWNaT1pzHhax2FKZF")?.inner;
    let recv_secret = SecretKey::from_slice(&recv_secret_rpc.secret_bytes())?;
    let recv_keypair = Keypair::from_secret_key(&secp, &recv_secret);
    let receiver_public_key = PublicKey::from_keypair(&recv_keypair);
    let (receiver_pk_xonly, _) = receiver_public_key.x_only_public_key();

    // 3. 构建脚本和叶子
    let action = FraAction::Transfer {
        asset_id: [0u8; 32],
        amount: 1000,
        receiver: XOnlyPk::from(receiver_pk_xonly),
        sender: XOnlyPk::from(sender_pk_xonly),
    };
    let tap_script = derive::fra::build_fra_script(action);
    let leaf_script = bc::LeafScript::from_tap_script(tap_script.clone());
    let leaf_hash = leaf_script.tap_leaf_hash();

    // 4. 手动构建 Taproot 地址 (对于单一脚本，默克尔根就是叶子哈希)
    let (output_pk, output_pk_parity) = internal_pk.to_output_pk(Some(leaf_hash.into()));
    let fra_addr = Address::new(AddressPayload::Tr(output_pk), AddressNetwork::Regtest);
    let fra_spk = fra_addr.script_pubkey();

    // 5. 注资交易...
    let fund_utxo = rpc.list_unspent(None, None, None, None, None)?.into_iter().find(|u| u.amount.to_sat() >= 100_000).unwrap();
    let rpc_addr = RpcAddress::from_str(&fra_addr.to_string())?.assume_checked();
    let fid = rpc.send_to_address(&rpc_addr, Amount::from_sat(fund_utxo.amount.to_sat() - 10000), None, None, None, None, None, None)?;
    rpc.generate_to_address(1, &coinbase_addr)?;

    // 6. 准备花费交易...
    let funding_tx = rpc.get_raw_transaction(&fid, None)?;
    let (fra_vout, fra_txout) = funding_tx.output.iter().enumerate().find(|(_, o)| o.script_pubkey.to_bytes() == fra_spk.as_slice()).unwrap();
    let fra_outpoint = OutPoint { txid: fid, vout: fra_vout as u32 };

    let dest_addr = rpc.get_new_address(None, Some(AddressType::Legacy))?.assume_checked();
    let mut spend_tx = bc::Tx {
        version: bc::TxVer::V2,
        lock_time: bc::LockTime::ZERO,
        inputs: bc::VarIntArray::from_iter_checked([bc::TxIn {
            prev_output: to_bc_outpoint(fra_outpoint),
            sig_script: bc::SigScript::new(),
            sequence: bc::SeqNo::from_consensus_u32(0xFFFF_FFFF),
            witness: bc::Witness::new(),
        }]),
        outputs: bc::VarIntArray::from_iter_checked([bc::TxOut {
            value: bc::Sats::from(fra_txout.value.to_sat() - 10000),
            script_pubkey: ScriptPubkey::from_inner(bc::ScriptBytes::try_from(dest_addr.script_pubkey().to_bytes()).unwrap()),
        }]),
    };

    // 7. 计算 Sighash
    let prevout_bc = to_bc_txout(fra_txout.clone());
    let mut cache = SighashCache::new(&mut spend_tx, vec![prevout_bc])?;
    let sighash = cache.tap_sighash_script(0, leaf_hash, None)?;
    let msg = Message::from(sighash);

    // 8. 签名
    let sig_sender = secp.sign_schnorr(msg.as_ref(), &sender_keypair);
    let sig_receiver = secp.sign_schnorr(msg.as_ref(), &recv_keypair);

    // 9. 手动构建 Control Block (对于单一脚本，路径为空)
    let merkle_path = TapMerklePath::try_from(Vec::new())?;
    let control_block = bc::ControlBlock::with(
        leaf_script.version,
        internal_pk,
        output_pk_parity,
        merkle_path,
    );
    let control_block_bytes = control_block.consensus_serialize();

    // 10. 组装 Witness
    spend_tx.inputs[0].witness = bc::Witness::from_consensus_stack(vec![
        sig_receiver.as_ref().to_vec(),
        sig_sender.as_ref().to_vec(),
        tap_script.to_vec(),
        control_block_bytes,
    ]);

    // 11. 广播
    let raw_spend_tx = spend_tx.consensus_serialize();
    let sid = rpc.send_raw_transaction(&raw_spend_tx)?;
    println!("\n🎉 成功! 花费交易已广播: {}", sid);

    Ok(())
}