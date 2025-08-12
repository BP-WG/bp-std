
use amplify::num::u7;
use bc::{
    TapScript, TapCode, ControlBlock, LeafScript, XOnlyPk,
    InternalPk, OutputPk
};
use crate::taptree::{TapTree, LeafInfo, ControlBlockFactory};

// --- Helper 函数 ---

/// Helper: 将字节块编码到脚本缓冲
fn push_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len == 0 {
        buf.push(TapCode::PushBytes0 as u8);
    } else if len <= 75 {
        buf.push((TapCode::PushBytes1 as u8).wrapping_add((len - 1) as u8));
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
    /// 转账：双重签名，先接收方同意再发送方授权
    Transfer {
        asset_id: [u8; 32],   // 资产标识
        amount: u64,          // 转账数量
        receiver: XOnlyPk,    // 接收方公钥
        sender: XOnlyPk,      // 发送方公钥
    },
    /// 增发：单方授权，只有增发者能执行
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
        // --- 转账动作 (Transfer) ---
        //
        // 脚本逻辑:
        //   <receiver_pk> OP_SWAP OP_CHECKSIGVERIFY <sender_pk> OP_SWAP OP_CHECKSIG
        //
        // 预期 Witness (从栈顶 -> 栈底):
        //   - sender_sig (发送方签名)
        //   - receiver_sig (接收方签名)
        //
        // 执行流程:
        // 1. 初始栈: [sender_sig, receiver_sig]
        // 2. 推入 receiver_pk -> 栈: [sender_sig, receiver_sig, receiver_pk]
        // 3. OP_SWAP -> 栈: [sender_sig, receiver_pk, receiver_sig]
        // 4. OP_CHECKSIGVERIFY 消耗 receiver_pk 和 receiver_sig, 验证通过。栈: [sender_sig]
        // 5. 推入 sender_pk -> 栈: [sender_sig, sender_pk]
        // 6. OP_SWAP -> 栈: [sender_pk, sender_sig]
        // 7. OP_CHECKSIG 消耗 sender_pk 和 sender_sig, 验证通过, 最终在栈上留下 TRUE。
        FraAction::Transfer { receiver, sender, .. } => {
            // 注意：当前实现仅包含签名逻辑。
            // 未来可在这里添加对 asset_id 和 amount 的承诺校验 (例如使用 OP_EQUALVERIFY)。

            // --- 验证接收方签名 ---
            push_bytes(&mut buf, &receiver.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSigVerify as u8);

            // --- 验证发送方签名 ---
            push_bytes(&mut buf, &sender.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSig as u8);
        }

        // --- 增发、销毁等其他操作的脚本实现 ---
        // 以下逻辑基于 "数据承诺 + 单签名" 模式，即先将操作数据压栈，
        // 然后提供授权者公钥，用 OP_SWAP 交换栈顶的签名和公钥，最后用 OP_CHECKSIGVERIFY 验证。
        // 这是一种健壮且常见的模式。

        FraAction::Mint { asset_id, amount, receiver, minter } => {
            push_bytes(&mut buf, &asset_id);
            push_int(&mut buf, amount);
            push_bytes(&mut buf, &receiver.to_byte_array());
            push_bytes(&mut buf, &minter.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSigVerify as u8);
        }
        FraAction::Burn { asset_id, amount, owner } => {
            push_bytes(&mut buf, &asset_id);
            push_int(&mut buf, amount);
            push_bytes(&mut buf, &owner.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSigVerify as u8);
        }
        FraAction::Rollback { asset_id, amount, owner, minter } => {
            push_bytes(&mut buf, &asset_id);
            push_int(&mut buf, amount);
            push_bytes(&mut buf, &minter.to_byte_array()); // 承诺归还目标
            push_bytes(&mut buf, &owner.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSigVerify as u8);
        }
        FraAction::Redeem { asset_id, amount, owner } => {
            push_bytes(&mut buf, &asset_id);
            push_int(&mut buf, amount);
            push_bytes(&mut buf, &owner.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSigVerify as u8);
        }
        FraAction::Split { asset_id, orig_amount, outputs, owner } => {
            push_bytes(&mut buf, &asset_id);
            push_int(&mut buf, orig_amount);
            for (amt, _) in &outputs {
                push_int(&mut buf, *amt);
            }
            for _ in 0..outputs.len().saturating_sub(1) {
                buf.push(TapCode::Add as u8);
            }
            buf.push(TapCode::EqualVerify as u8);
            push_bytes(&mut buf, &owner.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSigVerify as u8);
        }
        FraAction::Merge { asset_id, inputs, recipient, owner } => {
            push_bytes(&mut buf, &asset_id);
            let merged_amt: u64 = inputs.iter().sum();
            for amt in &inputs {
                push_int(&mut buf, *amt);
            }
            for _ in 0..inputs.len().saturating_sub(1) {
                buf.push(TapCode::Add as u8);
            }
            push_int(&mut buf, merged_amt);
            buf.push(TapCode::EqualVerify as u8);
            push_bytes(&mut buf, &recipient.to_byte_array());
            push_bytes(&mut buf, &owner.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSigVerify as u8);
        }
        FraAction::Freeze { asset_id, authority } => {
            push_bytes(&mut buf, &asset_id);
            push_bytes(&mut buf, &authority.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSigVerify as u8);
        }
        FraAction::Unfreeze { asset_id, authority } => {
            push_bytes(&mut buf, &asset_id);
            push_bytes(&mut buf, &authority.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSigVerify as u8);
        }
        FraAction::GrantRole { asset_id, role, target, admin } => {
            push_bytes(&mut buf, &asset_id);
            push_bytes(&mut buf, &role);
            push_bytes(&mut buf, &target.to_byte_array());
            push_bytes(&mut buf, &admin.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSigVerify as u8);
        }
        FraAction::RevokeRole { asset_id, role, target, admin } => {
            push_bytes(&mut buf, &asset_id);
            push_bytes(&mut buf, &role);
            push_bytes(&mut buf, &target.to_byte_array());
            push_bytes(&mut buf, &admin.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSigVerify as u8);
        }
        FraAction::Upgrade { asset_id, new_version, authority } => {
            push_bytes(&mut buf, &asset_id);
            push_bytes(&mut buf, &new_version);
            push_bytes(&mut buf, &authority.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSigVerify as u8);
        }
        FraAction::MetadataUpdate { asset_id, metadata, authority } => {
            push_bytes(&mut buf, &asset_id);
            push_bytes(&mut buf, &metadata);
            push_bytes(&mut buf, &authority.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSigVerify as u8);
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