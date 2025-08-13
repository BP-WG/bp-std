// tests/fra_actions.rs

use std::str::FromStr;
use bitcoincore_rpc::{Auth, Client, RpcApi, json::ListUnspentResultEntry};
use bitcoincore_rpc::bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    absolute::LockTime, transaction::Version,
    secp256k1::{Secp256k1, Keypair, SecretKey, Message, All},
    taproot::{self, LeafVersion, TaprootBuilder},
    sighash::{self, Prevouts, SighashCache, TapSighash},
    consensus::encode,
};
use rand::thread_rng;

// 导入合约逻辑
use derive::{
    fra::{build_fra_script, FraAction},
    XOnlyPk, OutputPk,
};
use amplify::Wrapper; // For .as_inner()

// --- 测试辅助结构体和函数 ---

// 封装测试环境所需的所有组件
struct TestEnv {
    rpc: Client,
    secp: Secp256k1<All>,
    funding_utxo: ListUnspentResultEntry,
    internal_kp: Keypair,
    authority_kp: Keypair, // 用于 Freeze, Unfreeze, Upgrade, Metadata
    minter_kp: Keypair,    // 用于 Mint
    admin_kp: Keypair,     // 用于 GrantRole, RevokeRole
    sender_kp: Keypair,    // 用于 Transfer, a.k.a owner
    receiver_kp: Keypair,  // 用于 Transfer
}

// 统一的测试环境设置函数
fn setup_test_environment() -> Result<TestEnv, Box<dyn std::error::Error>> {
    let rpc = Client::new(
        "http://127.0.0.1:18443/wallet/legacy_true",
        Auth::UserPass("foo".into(), "bar".into()),
    )?;

    // 确保钱包有资金
    if rpc.get_balance(None, Some(true))? < Amount::from_btc(5.0)? {
        let addr = rpc.get_new_address(None, None)?.assume_checked();
        rpc.generate_to_address(101, &addr)?;
    }

    // 寻找一个可用的 UTXO
    let funding_utxo = rpc.list_unspent(Some(1), None, None, None, None)?
        .into_iter()
        .find(|u| u.amount > Amount::from_sat(100_000))
        .ok_or("No suitable funding UTXO found")?;

    let secp = Secp256k1::new();
    let mut rng = thread_rng();

    // 生成所有需要的密钥对
    Ok(TestEnv {
        rpc,
        secp: secp.clone(),
        funding_utxo,
        internal_kp: Keypair::new(&secp, &mut rng),
        authority_kp: Keypair::new(&secp, &mut rng),
        minter_kp: Keypair::new(&secp, &mut rng),
        admin_kp: Keypair::new(&secp, &mut rng),
        sender_kp: Keypair::from_secret_key(&secp, &SecretKey::from_str("1111111111111111111111111111111111111111111111111111111111111111")?),
        receiver_kp: Keypair::from_secret_key(&secp, &SecretKey::from_str("2222222222222222222222222222222222222222222222222222222222222222")?),
    })
}

// 统一的单签操作测试函数
fn run_single_signer_test(
    action: FraAction,
    signer_kp: &Keypair,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = setup_test_environment()?;
    let (internal_pk, _) = env.internal_kp.x_only_public_key();

    // 1. 构建脚本和地址
    let script_bytes = build_fra_script(action).as_inner().to_vec();
    let script = ScriptBuf::from(script_bytes);

    let builder = TaprootBuilder::new().add_leaf(0, script.clone()).unwrap();
    let spend_info = builder.finalize(&env.secp, internal_pk).unwrap();
    let address = Address::p2tr(&env.secp, internal_pk, spend_info.merkle_root(), Network::Regtest);

    // 2. 注资
    let funding_txid = env.rpc.send_to_address(
        &address,
        Amount::from_sat(env.funding_utxo.amount.to_sat() - 10000),
        None, None, None, None, None, None,
    )?;
    let funding_addr = env.rpc.get_new_address(None, None)?.assume_checked();
    env.rpc.generate_to_address(1, &funding_addr)?;
    println!("\nAction funded with TXID: {}", funding_txid);

    // 3. 准备花费
    let funding_tx_raw = env.rpc.get_raw_transaction(&funding_txid, None)?;
    let (vout, prevout_value) = funding_tx_raw.output.iter().enumerate()
        .find(|(_, o)| o.script_pubkey == address.script_pubkey())
        .map(|(i, o)| (i as u32, o.value))
        .expect("Funded UTXO not found");

    let dest_addr = env.rpc.get_new_address(None, None)?.assume_checked();
    let mut spend_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: funding_txid, vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: prevout_value - Amount::from_sat(10000),
            script_pubkey: dest_addr.script_pubkey(),
        }],
    };

    // 4. 计算 Sighash 并签名
    let mut sighasher = SighashCache::new(&spend_tx);
    let leaf_hash = taproot::TapLeafHash::from_script(&script, LeafVersion::TapScript);
    let sighash: TapSighash = sighasher.taproot_script_spend_signature_hash(
        0,
        &Prevouts::All(&[TxOut { value: prevout_value, script_pubkey: address.script_pubkey() }]),
        leaf_hash,
        sighash::TapSighashType::Default,
    )?;
    let msg = Message::from(sighash);
    let signature = env.secp.sign_schnorr(&msg, signer_kp);

    // 5. 构建 Witness 并广播
    let control_block = spend_info.control_block(&(script.clone(), LeafVersion::TapScript)).unwrap();
    let mut witness = Witness::new();
    witness.push(signature.as_ref()); // 单签脚本，只需一个签名
    witness.push(script);
    witness.push(control_block.serialize());
    spend_tx.input[0].witness = witness;

    let tx_hex = encode::serialize_hex(&spend_tx);
    let final_txid = env.rpc.send_raw_transaction(&*tx_hex)?;
    println!("Successfully spent! TXID = {}", final_txid);

    Ok(())
}


// --- 测试用例 ---

#[test]
fn test_fra_transfer() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Testing FraAction::Transfer ---");
    let env = setup_test_environment()?;
    let (internal_pk, _) = env.internal_kp.x_only_public_key();
    let (sender_pk, _) = env.sender_kp.x_only_public_key();
    let (receiver_pk, _) = env.receiver_kp.x_only_public_key();

    let action = FraAction::Transfer {
        asset_id: [1; 32],
        amount: 1000,
        receiver: XOnlyPk::from_byte_array(receiver_pk.serialize()).unwrap(),
        sender: XOnlyPk::from_byte_array(sender_pk.serialize()).unwrap(),
    };

    let script = ScriptBuf::from(build_fra_script(action).as_inner().to_vec());
    let builder = TaprootBuilder::new().add_leaf(0, script.clone()).unwrap();
    let spend_info = builder.finalize(&env.secp, internal_pk).unwrap();
    let address = Address::p2tr(&env.secp, internal_pk, spend_info.merkle_root(), Network::Regtest);

    let funding_txid = env.rpc.send_to_address(&address, Amount::from_sat(50000), None, None, None, None, None, None)?;
    let funding_addr = env.rpc.get_new_address(None, None)?.assume_checked();
    env.rpc.generate_to_address(1, &funding_addr)?;
    println!("\nAction funded with TXID: {}", funding_txid);

    let funding_tx_raw = env.rpc.get_raw_transaction(&funding_txid, None)?;
    let (vout, prevout_value) = funding_tx_raw.output.iter().enumerate()
        .find(|(_, o)| o.script_pubkey == address.script_pubkey())
        .map(|(i, o)| (i as u32, o.value))
        .expect("Funded UTXO not found");

    let dest_addr = env.rpc.get_new_address(None, None)?.assume_checked();
    let mut spend_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: funding_txid, vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: prevout_value - Amount::from_sat(10000),
            script_pubkey: dest_addr.script_pubkey(),
        }],
    };

    let mut sighasher = SighashCache::new(&spend_tx);
    let leaf_hash = taproot::TapLeafHash::from_script(&script, LeafVersion::TapScript);
    let sighash: TapSighash = sighasher.taproot_script_spend_signature_hash(0, &Prevouts::All(&[TxOut { value: prevout_value, script_pubkey: address.script_pubkey() }]), leaf_hash, sighash::TapSighashType::Default)?;
    let msg = Message::from(sighash);

    let sig_sender = env.secp.sign_schnorr(&msg, &env.sender_kp);
    let sig_receiver = env.secp.sign_schnorr(&msg, &env.receiver_kp);

    let control_block = spend_info.control_block(&(script.clone(), LeafVersion::TapScript)).unwrap();
    let mut witness = Witness::new();
    witness.push(sig_receiver.as_ref());
    witness.push(sig_sender.as_ref());
    witness.push(script);
    witness.push(control_block.serialize());
    spend_tx.input[0].witness = witness;

    let tx_hex = encode::serialize_hex(&spend_tx);
    let final_txid = env.rpc.send_raw_transaction(&*tx_hex)?;
    println!("Successfully spent! TXID = {}", final_txid);

    Ok(())
}

#[test]
fn test_fra_mint() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Testing FraAction::Mint ---");
    let env = setup_test_environment()?;
    let (minter_pk, _) = env.minter_kp.x_only_public_key();
    let (receiver_pk, _) = env.receiver_kp.x_only_public_key();

    let action = FraAction::Mint {
        asset_id: [2; 32],
        amount: 500,
        receiver: OutputPk::from_unchecked(XOnlyPk::from_byte_array(receiver_pk.serialize()).unwrap()),
        minter: XOnlyPk::from_byte_array(minter_pk.serialize()).unwrap(),
    };
    run_single_signer_test(action, &env.minter_kp)
}

#[test]
fn test_fra_burn() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Testing FraAction::Burn ---");
    let env = setup_test_environment()?;
    let (owner_pk, _) = env.sender_kp.x_only_public_key();

    let action = FraAction::Burn {
        asset_id: [3; 32],
        amount: 200,
        owner: XOnlyPk::from_byte_array(owner_pk.serialize()).unwrap(),
    };
    run_single_signer_test(action, &env.sender_kp)
}

#[test]
fn test_fra_rollback() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Testing FraAction::Rollback ---");
    let env = setup_test_environment()?;
    let (owner_pk, _) = env.sender_kp.x_only_public_key();
    let (minter_pk, _) = env.minter_kp.x_only_public_key();

    let action = FraAction::Rollback {
        asset_id: [4; 32],
        amount: 150,
        owner: XOnlyPk::from_byte_array(owner_pk.serialize()).unwrap(),
        minter: XOnlyPk::from_byte_array(minter_pk.serialize()).unwrap(),
    };
    run_single_signer_test(action, &env.sender_kp)
}

#[test]
fn test_fra_redeem() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Testing FraAction::Redeem ---");
    let env = setup_test_environment()?;
    let (owner_pk, _) = env.sender_kp.x_only_public_key();

    let action = FraAction::Redeem {
        asset_id: [5; 32],
        amount: 100,
        owner: XOnlyPk::from_byte_array(owner_pk.serialize()).unwrap(),
    };
    run_single_signer_test(action, &env.sender_kp)
}

#[test]
fn test_fra_freeze() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Testing FraAction::Freeze ---");
    let env = setup_test_environment()?;
    let (authority_pk, _) = env.authority_kp.x_only_public_key();

    let action = FraAction::Freeze {
        asset_id: [6; 32],
        authority: XOnlyPk::from_byte_array(authority_pk.serialize()).unwrap(),
    };
    run_single_signer_test(action, &env.authority_kp)
}

#[test]
fn test_fra_unfreeze() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Testing FraAction::Unfreeze ---");
    let env = setup_test_environment()?;
    let (authority_pk, _) = env.authority_kp.x_only_public_key();

    let action = FraAction::Unfreeze {
        asset_id: [7; 32],
        authority: XOnlyPk::from_byte_array(authority_pk.serialize()).unwrap(),
    };
    run_single_signer_test(action, &env.authority_kp)
}

#[test]
fn test_fra_grant_role() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Testing FraAction::GrantRole ---");
    let env = setup_test_environment()?;
    let (admin_pk, _) = env.admin_kp.x_only_public_key();
    let (target_pk, _) = env.receiver_kp.x_only_public_key();

    let action = FraAction::GrantRole {
        asset_id: [8; 32],
        role: b"MINTER".to_vec(),
        target: XOnlyPk::from_byte_array(target_pk.serialize()).unwrap(),
        admin: XOnlyPk::from_byte_array(admin_pk.serialize()).unwrap(),
    };
    run_single_signer_test(action, &env.admin_kp)
}

#[test]
fn test_fra_revoke_role() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Testing FraAction::RevokeRole ---");
    let env = setup_test_environment()?;
    let (admin_pk, _) = env.admin_kp.x_only_public_key();
    let (target_pk, _) = env.receiver_kp.x_only_public_key();

    let action = FraAction::RevokeRole {
        asset_id: [9; 32],
        role: b"MINTER".to_vec(),
        target: XOnlyPk::from_byte_array(target_pk.serialize()).unwrap(),
        admin: XOnlyPk::from_byte_array(admin_pk.serialize()).unwrap(),
    };
    run_single_signer_test(action, &env.admin_kp)
}

#[test]
fn test_fra_upgrade() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Testing FraAction::Upgrade ---");
    let env = setup_test_environment()?;
    let (authority_pk, _) = env.authority_kp.x_only_public_key();

    let action = FraAction::Upgrade {
        asset_id: [10; 32],
        new_version: [0xff; 32],
        authority: XOnlyPk::from_byte_array(authority_pk.serialize()).unwrap(),
    };
    run_single_signer_test(action, &env.authority_kp)
}

#[test]
fn test_fra_metadata_update() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Testing FraAction::MetadataUpdate ---");
    let env = setup_test_environment()?;
    let (authority_pk, _) = env.authority_kp.x_only_public_key();

    let action = FraAction::MetadataUpdate {
        asset_id: [11; 32],
        metadata: b"NEW_METADATA_HASH".to_vec(),
        authority: XOnlyPk::from_byte_array(authority_pk.serialize()).unwrap(),
    };
    run_single_signer_test(action, &env.authority_kp)
}

#[test]
fn test_fra_split() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Testing FraAction::Split ---");
    let env = setup_test_environment()?;
    let (owner_pk, _) = env.sender_kp.x_only_public_key();
    let (out_pk, _) = env.receiver_kp.x_only_public_key();

    let action = FraAction::Split {
        asset_id: [12; 32],
        orig_amount: 1000,
        outputs: vec![
            (600, OutputPk::from_unchecked(XOnlyPk::from_byte_array(out_pk.serialize()).unwrap())),
            (400, OutputPk::from_unchecked(XOnlyPk::from_byte_array(out_pk.serialize()).unwrap())),
        ],
        owner: XOnlyPk::from_byte_array(owner_pk.serialize()).unwrap(),
    };
    run_single_signer_test(action, &env.sender_kp)
}

#[test]
fn test_fra_merge() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Testing FraAction::Merge ---");
    let env = setup_test_environment()?;
    let (owner_pk, _) = env.sender_kp.x_only_public_key();
    let (recipient_pk, _) = env.receiver_kp.x_only_public_key();

    let action = FraAction::Merge {
        asset_id: [13; 32],
        inputs: vec![300, 700],
        recipient: OutputPk::from_unchecked(XOnlyPk::from_byte_array(recipient_pk.serialize()).unwrap()),
        owner: XOnlyPk::from_byte_array(owner_pk.serialize()).unwrap(),
    };
    run_single_signer_test(action, &env.sender_kp)
}