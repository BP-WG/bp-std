
use amplify::num::u7;
use bc::{
    TapScript, TapCode, ControlBlock, LeafScript, XOnlyPk,
    InternalPk, OutputPk
};
use crate::taptree::{TapTree, LeafInfo, ControlBlockFactory};

// --- Helper 函数  ---

/// Helper: 将字节块编码到脚本缓冲
fn push_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len == 0 {
        buf.push(TapCode::PushBytes0 as u8);
    } else if len <= 75 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(TapCode::PushData1 as u8);
        buf.push(len as u8);
    } else if len < 0x10000 {
        buf.push(TapCode::PushData2 as u8);
        buf.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        buf.push(TapCode::PushData4 as u8);
        buf.extend_from_slice(&(len as u32).to_le_bytes());
    }
    buf.extend_from_slice(data);
}

/// Helper: 将整数编码为最小脚本数字或字节块推送
fn push_int(buf: &mut Vec<u8>, value: u64) {
    if value == 0 {
        buf.push(TapCode::PushBytes0 as u8);
        return;
    }
    if (1..=16).contains(&value) {
        buf.push((TapCode::PushNum1 as u8) + (value - 1) as u8);
        return;
    }
    let mut bytes = value.to_le_bytes().to_vec();
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    if bytes.last().map_or(false, |&b| b & 0x80 != 0) {
        bytes.push(0);
    }
    push_bytes(buf, &bytes);
}

/// 支持的 FRA 操作类型
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FraAction {
    /// 转账：双重签名
    Transfer {
        asset_id: [u8; 32],
        amount: u64,
        receiver: XOnlyPk,
        sender: XOnlyPk,
    },
    /// 增发：单方授权
    Mint {
        asset_id: [u8; 32],
        amount: u64,
        receiver: OutputPk,
        minter: XOnlyPk,
    },
    /// 销毁
    Burn {
        asset_id: [u8; 32],
        amount: u64,
        owner: XOnlyPk,
    },
    /// 回退：持有者主动返还给发行者
    Rollback {
        asset_id: [u8; 32],
        amount: u64,
        owner: XOnlyPk,
        minter: XOnlyPk,
    },
    /// 赎回：返还底层资产或销毁代币
    Redeem {
        asset_id: [u8; 32],
        amount: u64,
        owner: XOnlyPk,
    },
    /// 拆分：将一笔 UTXO 拆成多笔
    Split {
        asset_id: [u8; 32],
        orig_amount: u64,
        outputs: Vec<(u64, OutputPk)>,
        owner: XOnlyPk,
    },
    /// 合并：将多笔 UTXO 合并为一笔
    Merge {
        asset_id: [u8; 32],
        inputs: Vec<u64>,
        recipient: OutputPk,
        owner: XOnlyPk,
    },
    /// 冻结资产
    Freeze {
        asset_id: [u8; 32],
        authority: XOnlyPk,
    },
    /// 解冻资产
    Unfreeze {
        asset_id: [u8; 32],
        authority: XOnlyPk,
    },
    /// 授予角色
    GrantRole {
        asset_id: [u8; 32],
        role: Vec<u8>,
        target: XOnlyPk,
        admin: XOnlyPk,
    },
    /// 撤销角色
    RevokeRole {
        asset_id: [u8; 32],
        role: Vec<u8>,
        target: XOnlyPk,
        admin: XOnlyPk,
    },
    /// 升级脚本版本
    Upgrade {
        asset_id: [u8; 32],
        new_version: [u8; 32],
        authority: XOnlyPk,
    },
    /// 更新元数据
    MetadataUpdate {
        asset_id: [u8; 32],
        metadata: Vec<u8>,
        authority: XOnlyPk,
    },
}

/// 构造对应操作的 TapScript
pub fn build_fra_script(action: FraAction) -> TapScript {
    let mut buf = Vec::new();
    match action {
        // --- Transfer
        FraAction::Transfer { receiver, sender, .. } => {
            push_bytes(&mut buf, &sender.to_byte_array());
            buf.push(TapCode::CheckSigVerify as u8);
            push_bytes(&mut buf, &receiver.to_byte_array());
            buf.push(TapCode::CheckSig as u8);
        }

        // --- 单签通用模式: Commit -> Cleanup -> Verify ---
        FraAction::Mint { asset_id, amount, receiver, minter } => {
            // Commit: 3 items
            push_bytes(&mut buf, &asset_id);
            push_int(&mut buf, amount);
            push_bytes(&mut buf, &receiver.to_byte_array());
            // Cleanup
            buf.push(TapCode::Drop as u8);
            buf.push(TapCode::Drop as u8);
            buf.push(TapCode::Drop as u8);
            // Verify
            push_bytes(&mut buf, &minter.to_byte_array());
            buf.push(TapCode::CheckSig as u8);
        }
        FraAction::Burn { asset_id, amount, owner } => {
            // Commit: 2 items
            push_bytes(&mut buf, &asset_id);
            push_int(&mut buf, amount);
            // Cleanup
            buf.push(TapCode::Drop2 as u8); // Nip is equivalent to SWAP then DROP
            // Verify
            push_bytes(&mut buf, &owner.to_byte_array());
            buf.push(TapCode::CheckSig as u8);
        }
        FraAction::Rollback { asset_id, amount, owner, minter } => {
            // Commit: 3 items
            push_bytes(&mut buf, &asset_id);
            push_int(&mut buf, amount);
            push_bytes(&mut buf, &minter.to_byte_array()); // 承诺归还目标
            // Cleanup
            buf.push(TapCode::Drop as u8);
            buf.push(TapCode::Drop as u8);
            buf.push(TapCode::Drop as u8);
            // Verify
            push_bytes(&mut buf, &owner.to_byte_array());
            buf.push(TapCode::CheckSig as u8);
        }
        FraAction::Redeem { asset_id, amount, owner } => {
            // Commit: 2 items
            push_bytes(&mut buf, &asset_id);
            push_int(&mut buf, amount);
            // Cleanup
            buf.push(TapCode::Drop2 as u8);
            // Verify
            push_bytes(&mut buf, &owner.to_byte_array());
            buf.push(TapCode::CheckSig as u8);
        }
        FraAction::Split { asset_id, orig_amount, outputs, owner } => {
            // Commit data
            push_bytes(&mut buf, &asset_id);
            for (_, pk) in &outputs {
                push_bytes(&mut buf, &pk.to_byte_array());
            }
            // Math part
            for (amt, _) in &outputs {
                push_int(&mut buf, *amt);
            }
            for _ in 0..outputs.len().saturating_sub(1) {
                buf.push(TapCode::Add as u8);
            }
            push_int(&mut buf, orig_amount);
            buf.push(TapCode::EqualVerify as u8);
            // Cleanup data commitments (asset_id + N output pks)
            for _ in 0..=outputs.len() {
                buf.push(TapCode::Drop as u8);
            }
            // Verify
            push_bytes(&mut buf, &owner.to_byte_array());
            buf.push(TapCode::CheckSig as u8);
        }
        FraAction::Merge { asset_id, inputs, recipient, owner } => {
            // Commit data
            push_bytes(&mut buf, &asset_id);
            push_bytes(&mut buf, &recipient.to_byte_array());
            // Math part
            let merged_amt: u64 = inputs.iter().sum();
            for amt in &inputs {
                push_int(&mut buf, *amt);
            }
            for _ in 0..inputs.len().saturating_sub(1) {
                buf.push(TapCode::Add as u8);
            }
            push_int(&mut buf, merged_amt);
            buf.push(TapCode::EqualVerify as u8);
            // Cleanup data commitments (asset_id + recipient_pk)
            buf.push(TapCode::Drop2 as u8);
            // Verify
            push_bytes(&mut buf, &owner.to_byte_array());
            buf.push(TapCode::CheckSig as u8);
        }
        FraAction::Freeze { asset_id, authority } => {
            push_bytes(&mut buf, &asset_id);
            buf.push(TapCode::Drop as u8);
            push_bytes(&mut buf, &authority.to_byte_array());
            buf.push(TapCode::CheckSig as u8);
        }
        FraAction::Unfreeze { asset_id, authority } => {
            push_bytes(&mut buf, &asset_id);
            buf.push(TapCode::Drop as u8);
            push_bytes(&mut buf, &authority.to_byte_array());
            buf.push(TapCode::CheckSig as u8);
        }
        FraAction::GrantRole { asset_id, role, target, admin } => {
            push_bytes(&mut buf, &asset_id);
            push_bytes(&mut buf, &role);
            push_bytes(&mut buf, &target.to_byte_array());
            buf.push(TapCode::Drop as u8);
            buf.push(TapCode::Drop as u8);
            buf.push(TapCode::Drop as u8);
            push_bytes(&mut buf, &admin.to_byte_array());
            buf.push(TapCode::CheckSig as u8);
        }
        FraAction::RevokeRole { asset_id, role, target, admin } => {
            push_bytes(&mut buf, &asset_id);
            push_bytes(&mut buf, &role);
            push_bytes(&mut buf, &target.to_byte_array());
            buf.push(TapCode::Drop as u8);
            buf.push(TapCode::Drop as u8);
            buf.push(TapCode::Drop as u8);
            push_bytes(&mut buf, &admin.to_byte_array());
            buf.push(TapCode::CheckSig as u8);
        }
        FraAction::Upgrade { asset_id, new_version, authority } => {
            push_bytes(&mut buf, &asset_id);
            push_bytes(&mut buf, &new_version);
            buf.push(TapCode::Drop2 as u8);
            push_bytes(&mut buf, &authority.to_byte_array());
            buf.push(TapCode::CheckSig as u8);
        }
        FraAction::MetadataUpdate { asset_id, metadata, authority } => {
            push_bytes(&mut buf, &asset_id);
            push_bytes(&mut buf, &metadata);
            buf.push(TapCode::Drop2 as u8);
            push_bytes(&mut buf, &authority.to_byte_array());
            buf.push(TapCode::CheckSig as u8);
        }
    }
    TapScript::from_checked(buf)
}

/// 将 TapScript 包装成叶子信息
pub fn fra_leaf_info(action: FraAction, depth: u7) -> LeafInfo<LeafScript> {
    let ts = build_fra_script(action);
    LeafInfo::tap_script(depth, ts)
}

/// 将一系列 FRA 动作打包成 Taproot 解锁证明
pub fn build_fra_control_blocks(
    internal_pk: InternalPk,
    actions: Vec<(FraAction, u7)>,
) -> Vec<(ControlBlock, LeafScript)> {
    let leaf_infos = actions
        .into_iter()
        .map(|(action, depth)| fra_leaf_info(action, depth))
        .collect::<Vec<_>>();

    let tap_tree = TapTree::from_leaves(leaf_infos)
        .expect("FRA script tree build failed");

    ControlBlockFactory::with(internal_pk, tap_tree)
        .collect()
}