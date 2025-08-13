
use bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoincore_rpc::bitcoin::{
    blockdata::opcodes, Address, Amount, Network, OutPoint, ScriptBuf,
    Sequence, Transaction, TxIn, TxOut, Witness, absolute::LockTime,

    transaction::Version,
    secp256k1::{Secp256k1, Message, Keypair, SecretKey, PublicKey},
    taproot::{TaprootBuilder, LeafVersion, TapLeafHash},
    sighash::{SighashCache, Prevouts, TapSighashType},
};
use bitcoincore_rpc::json::AddressType;
use std::str::FromStr;
use derive::base58::encode;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 设置
    let rpc = Client::new(
        "http://127.0.0.1:18443/wallet/legacy_true",
        Auth::UserPass("foo".into(), "bar".into()),
    )?;
    let legacy_addr = rpc.get_new_address(None, Some(AddressType::Legacy))?
        .require_network(Network::Regtest)?;
    if rpc.get_balance(None, Some(true))? < Amount::from_btc(1.0)? {
        rpc.generate_to_address(101, &legacy_addr)?;
    }

    println!("\n--- [simple_test.rs] Golden Standard ---");

    // 2. 密钥和脚本
    let secp = Secp256k1::new();
    let internal_keypair = Keypair::from_secret_key(&secp, &secp.generate_keypair(&mut rand::thread_rng()).0);
    let internal_public_key: PublicKey = internal_keypair.public_key();
    let (internal_xonly_pk, _) = internal_public_key.x_only_public_key();
    println!("1. Internal Key: {}", encode(&internal_xonly_pk.serialize()));

    let script_seckey = SecretKey::from_str("1111111111111111111111111111111111111111111111111111111111111111")?;
    let script_keypair = Keypair::from_secret_key(&secp, &script_seckey);
    let script_public_key: PublicKey = script_keypair.public_key();
    let (script_xonly_pk, _) = script_public_key.x_only_public_key();

    let script = ScriptBuf::builder()
        .push_x_only_key(&script_xonly_pk)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script();
    println!("2. Script (hex): {}", encode(script.as_bytes()));

    let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
    println!("3. Leaf Hash: {}", leaf_hash);

    // 3. 创建 Taproot 地址
    let tap_builder = TaprootBuilder::new().add_leaf(0, script.clone())?;
    let tap_info = tap_builder.finalize(&secp, internal_xonly_pk)
        .expect("Failed to finalize Taproot builder");
    println!("4. Merkle Root: {}", tap_info.merkle_root().unwrap());
    let address = Address::p2tr(&secp, internal_xonly_pk, tap_info.merkle_root(), Network::Regtest);
    println!("5. Tweaked Output Key: {}", encode(&address.script_pubkey().as_bytes()[2..].to_vec()));

    // ... 后续代码不变 ...
    let txid = rpc.send_to_address(&address, Amount::from_sat(50_000), None, None, None, None, None, None)?;
    rpc.generate_to_address(1, &legacy_addr)?;

    let funding_tx = rpc.get_raw_transaction(&txid, None)?;
    let vout = funding_tx.output.iter().position(|o| o.script_pubkey == address.script_pubkey()).unwrap() as u32;
    let previous_output = OutPoint { txid, vout };
    let prevout_to_spend = funding_tx.output[vout as usize].clone();

    let dest_addr = rpc.get_new_address(Some("dest"), Some(AddressType::Bech32))?.require_network(Network::Regtest)?;
    let mut spend_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn { previous_output, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }],
        output: vec![TxOut { value: Amount::from_sat(40_000), script_pubkey: dest_addr.script_pubkey() }],
    };

    let mut sighash_cache = SighashCache::new(&mut spend_tx);
    let sighash = sighash_cache.taproot_script_spend_signature_hash(0, &Prevouts::All(&[prevout_to_spend]), leaf_hash, TapSighashType::Default)?;
    println!("6. Sighash: {}", sighash);

    let msg = Message::from_digest_slice(sighash.as_ref())?;
    let signature = secp.sign_schnorr(&msg, &script_keypair);

    let control_block = tap_info.control_block(&(script.clone(), LeafVersion::TapScript)).unwrap();
    println!("7. Control Block (hex): {}", encode(&control_block.serialize()));
    let witness = Witness::from(vec![signature.as_ref().to_vec(), script.to_bytes(), control_block.serialize()]);
    spend_tx.input[0].witness = witness;

    let spend_txid = rpc.send_raw_transaction(&spend_tx)?;
    println!("\n🎉 Success! Spend txid: {}", spend_txid);

    Ok(())
}