use amplify::num::u7;
use bc::{
    TapScript, TapCode, ControlBlock, LeafScript, XOnlyPk,
    InternalPk, OutputPk};

use crate::taptree::{TapTree, LeafInfo, ControlBlockFactory};

/// —— FRA 操作对应的 OP_SUCCESSxx 常量 ——
const OP_FRA_TRANSFER:        TapCode = TapCode::Success80;
const OP_FRA_MINT:            TapCode = TapCode::Success98;
const OP_FRA_BURN:            TapCode = TapCode::Success126;
const OP_FRA_ROLLBACK:        TapCode = TapCode::Success127;
const OP_FRA_REDEEM:          TapCode = TapCode::Success128;
const OP_FRA_SPLIT:           TapCode = TapCode::Success129;
const OP_FRA_MERGE:           TapCode = TapCode::Success131;
const OP_FRA_FREEZE:          TapCode = TapCode::Success132;
const OP_FRA_UNFREEZE:        TapCode = TapCode::Success133;
const OP_FRA_GRANT_ROLE:      TapCode = TapCode::Success134;
const OP_FRA_REVOKE_ROLE:     TapCode = TapCode::Success137;
const OP_FRA_UPGRADE:         TapCode = TapCode::Success138;
const OP_FRA_METADATA_UPDATE: TapCode = TapCode::Success141;

/// Helper: 将字节块编码到脚本缓冲
fn push_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len == 0 {
        buf.push(TapCode::PushBytes0 as u8);
    } else if len <= 75 {
        let opcode = (TapCode::PushBytes1 as u8).wrapping_add((len - 1) as u8);
        buf.push(opcode);
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
    match value {
        0 => buf.push(TapCode::PushBytes0 as u8),
        1..=16 => {
            let code = match value {
                1  => TapCode::PushNum1,
                2  => TapCode::PushNum2,
                3  => TapCode::PushNum3,
                4  => TapCode::PushNum4,
                5  => TapCode::PushNum5,
                6  => TapCode::PushNum6,
                7  => TapCode::PushNum7,
                8  => TapCode::PushNum8,
                9  => TapCode::PushNum9,
                10 => TapCode::PushNum10,
                11 => TapCode::PushNum11,
                12 => TapCode::PushNum12,
                13 => TapCode::PushNum13,
                14 => TapCode::PushNum14,
                15 => TapCode::PushNum15,
                16 => TapCode::PushNum16,
                _  => unreachable!(),
            };
            buf.push(code as u8);
        }
        _ => {
            let mut v = value;
            let mut bytes = Vec::new();
            while v > 0 {
                bytes.push((v & 0xFF) as u8);
                v >>= 8;
            }
            if bytes.last().map_or(false, |b| b & 0x80 != 0) {
                bytes.push(0);
            }
            push_bytes(buf, &bytes);
        }
    }
}

/// 支持的 FRA 操作类型
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FraAction {
    /// 转账：双重签名，先接收方同意再发送方授权
    Transfer {
        asset_id: [u8; 32],   // 资产标识
        amount: u64,          // 转账数量
        receiver: XOnlyPk,   // 接收方公钥
        sender: XOnlyPk,     // 发送方公钥
    },
    /// 增发：单方授权，只有增发者能执行
    Mint {
        asset_id: [u8; 32],   // 资产标识
        amount: u64,          // 增发数量
        receiver: OutputPk,   // 接收方公钥
        minter: XOnlyPk,     // 增发者公钥
    },
    /// 销毁（燃烧）
    Burn {
        asset_id: [u8; 32],   // 资产标识
        amount: u64,          // 燃烧数量
        owner: XOnlyPk,      // 授权者公钥
    },
    /// 回退：持有者主动返还给发行者
    Rollback {
        asset_id: [u8; 32],   // 资产标识
        amount: u64,          // 回退数量
        owner: XOnlyPk,      // 资产持有者公钥
        minter: XOnlyPk,     // 发行者（归还目标）公钥
    },
    /// 赎回：返还底层资产或销毁代币
    Redeem {
        asset_id: [u8; 32],   // 资产标识
        amount: u64,          // 赎回数量
        owner: XOnlyPk,      // 授权者公钥
        // 可扩展：time_lock: Option<u32>,  // 时间锁或其他条件
    },
    /// 拆分：将一笔 UTXO 拆成多笔
    Split {
        asset_id: [u8; 32],       // 资产标识
        orig_amount: u64,          // 原始总量
        outputs: Vec<(u64, OutputPk)>, // 拆分后数量 + 接收方公钥
        owner: XOnlyPk,          // 授权者公钥
    },
    /// 合并：将多笔 UTXO 合并为一笔
    Merge {
        asset_id: [u8; 32],       // 资产标识
        inputs: Vec<u64>,          // 待合并的数量列表
        recipient: OutputPk,       // 合并后接收方公钥
        owner: XOnlyPk,           // 授权者公钥
    },
    /// 冻结资产
    Freeze {
        asset_id: [u8; 32],   // 资产标识
        authority: XOnlyPk,  // 冻结权限公钥
        // 可扩展：freeze_until: Option<u64>,
    },
    /// 解冻资产
    Unfreeze {
        asset_id: [u8; 32],   // 资产标识
        authority: XOnlyPk,  // 解冻权限公钥
    },
    /// 授予角色
    GrantRole {
        asset_id: [u8; 32],   // 资产标识或 UTXO 唯一 ID
        role: Vec<u8>,        // 角色标识
        target: XOnlyPk,     // 被授予方公钥
        admin: XOnlyPk,      // 管理员公钥（签名者）
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
        asset_id: [u8; 32],    // 资产标识或 UTXO ID
        new_version: [u8; 32],  // 新脚本版本哈希
        authority: XOnlyPk,    // 升级权限公钥
    },
    /// 更新元数据
    MetadataUpdate {
        asset_id: [u8; 32],    // 资产标识或 UTXO ID
        metadata: Vec<u8>,      // 新元数据二进制/JSON
        authority: XOnlyPk,    // 授权者公钥
    },
}

/// 构造对应操作的 TapScript
pub fn build_fra_script(action: FraAction) -> TapScript {
    let mut buf = Vec::new();
    match action {
        // —— 转账动作 ——
        FraAction::Transfer { asset_id: _, amount: _, receiver, sender } => {
            // 初始堆栈: [sig_receiver], [sig_sender]

            // --- 验证接收方签名 ---
            push_bytes(&mut buf, &receiver.to_byte_array()); // 压入接收方公钥
            buf.push(TapCode::Swap as u8);                   // 交换 -> [sig_receiver], [receiver_pk]
            buf.push(TapCode::CheckSigVerify as u8);         // 验证并消耗

            // --- 验证发送方签名 ---
            push_bytes(&mut buf, &sender.to_byte_array());    // 压入发送方公钥
            buf.push(TapCode::Swap as u8);                   // 交换 -> [sig_sender], [sender_pk]
            buf.push(TapCode::CheckSig as u8);               // 验证
        }
        // —— 增发动作 ——
        FraAction::Mint { asset_id, amount, receiver, minter } => {
            // 1) AssetID
            push_bytes(&mut buf, &asset_id);
            // 2) 增发数量
            push_int(&mut buf, amount);
            // 3) 接收方公钥
            push_bytes(&mut buf, &receiver.to_byte_array());
            // 4) 增发者公钥
            push_bytes(&mut buf, &minter.to_byte_array());
            buf.push(TapCode::Swap as u8); // <--- [关键修正] 修正堆栈顺序
            // 5) 验签
            buf.push(TapCode::CheckSigVerify as u8);
        }
        // 销毁：授权者签名后销毁
        FraAction::Burn { asset_id, amount, owner } => {
            push_bytes(&mut buf, &asset_id);
            push_int(&mut buf, amount);
            push_bytes(&mut buf, &owner.to_byte_array());
            buf.push(TapCode::Swap as u8); //
            buf.push(TapCode::CheckSigVerify as u8);
        }
        // 回退：持有者发起, 回退给发行者
        FraAction::Rollback { asset_id, amount, owner, minter } => {
            push_bytes(&mut buf, &asset_id);
            push_int(&mut buf, amount);
            push_bytes(&mut buf, &owner.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSigVerify as u8);
            push_bytes(&mut buf, &minter.to_byte_array());
        }
        // 赎回：持有者签名并执行赎回逻辑
        FraAction::Redeem { asset_id, amount, owner } => {
            push_bytes(&mut buf, &asset_id);
            push_int(&mut buf, amount);
            push_bytes(&mut buf, &owner.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSigVerify as u8);
        }
        // 拆分：校验总量一致并签名
        FraAction::Split { asset_id, orig_amount, outputs, owner } => {
            push_bytes(&mut buf, &asset_id);
            push_int(&mut buf, orig_amount);
            // push new amounts
            for (amt, _) in &outputs {
                push_int(&mut buf, *amt);
            }
            // sum all new amounts
            for _ in 0..outputs.len().saturating_sub(1) {
                buf.push(TapCode::Add as u8);
            }
            // 验证 Orig == sum(new)
            buf.push(TapCode::EqualVerify as u8);
            // 持有者签名验证
            push_bytes(&mut buf, &owner.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSigVerify as u8);
        }
        // 合并：校验合并后数量并签名
        FraAction::Merge { asset_id, inputs, recipient, owner } => {
            push_bytes(&mut buf, &asset_id);
            for amt in &inputs {
                push_int(&mut buf, *amt);
            }
            for _ in 0..inputs.len().saturating_sub(1) {
                buf.push(TapCode::Add as u8);
            }
            // push expected merged amount
            let merged_amt: u64 = inputs.iter().sum();
            push_int(&mut buf, merged_amt);
            buf.push(TapCode::EqualVerify as u8);
            // 持有者签名验证
            push_bytes(&mut buf, &owner.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSigVerify as u8);
            // 输出接收方公钥，用于后续输出分配
            push_bytes(&mut buf, &recipient.to_byte_array());
        }
        // 冻结：授权者签名验证
        FraAction::Freeze { asset_id, authority } => {
            push_bytes(&mut buf, &asset_id);
            push_bytes(&mut buf, &authority.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSigVerify as u8);
        }
        // 解冻：授权者签名验证
        FraAction::Unfreeze { asset_id, authority } => {
            push_bytes(&mut buf, &asset_id);
            push_bytes(&mut buf, &authority.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSigVerify as u8);
        }
        // 授予角色：校验管理员签名
        FraAction::GrantRole { asset_id, role, target, admin } => {
            push_bytes(&mut buf, &asset_id);
            push_bytes(&mut buf, &role);
            push_bytes(&mut buf, &target.to_byte_array());
            push_bytes(&mut buf, &admin.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSigVerify as u8);
        }
        // 撤销角色：校验管理员签名
        FraAction::RevokeRole { asset_id, role, target, admin } => {
            push_bytes(&mut buf, &asset_id);
            push_bytes(&mut buf, &role);
            push_bytes(&mut buf, &target.to_byte_array());
            push_bytes(&mut buf, &admin.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSigVerify as u8);
        }
        // 升级：校验授权签名
        FraAction::Upgrade { asset_id, new_version, authority } => {
            push_bytes(&mut buf, &asset_id);
            push_bytes(&mut buf, &new_version);
            push_bytes(&mut buf, &authority.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSigVerify as u8);
        }
        // 元数据更新：校验授权签名
        FraAction::MetadataUpdate { asset_id, metadata, authority } => {
            push_bytes(&mut buf, &asset_id);
            push_bytes(&mut buf, &metadata);
            push_bytes(&mut buf, &authority.to_byte_array());
            buf.push(TapCode::Swap as u8);
            buf.push(TapCode::CheckSigVerify as u8);
        }
    }
    println!("Generated raw script bytes: {:?}", buf); // 添加这一行
    TapScript::from_checked(buf)
}

/// 将 TapScript 包装成叶子信息
/// 把一个 FRA 动作和它在 Merkle 树里的深度，打包成 LeafInfo<LeafScript>
pub fn fra_leaf_info(action: FraAction, depth: u7) -> LeafInfo<LeafScript> {
    // 1) 用 build_fra_script 根据动作构造对应的 TapScript
    let ts = build_fra_script(action);
    // 2) 把 TapScript 包装成 LeafScript 并带上深度
    LeafInfo::tap_script(depth, ts)
}


/// 将一系列 FRA 动作打包成 Taproot 解锁证明 (ControlBlock + LeafScript)
///
/// 输入：
/// - `internal_pk`: Taproot 内部公钥，用于 tweaked 输出 key
/// - `actions`: Vec<(FraAction, depth)>，每个元素包含一个 FRA 动作和 Merkle 树深度
///
/// 输出：
/// Vec<(ControlBlock, LeafScript)>，对应每个动作的 ControlBlock 及其脚本叶子，可直接放入交易 `witness`。
pub fn build_fra_control_blocks(
    internal_pk: InternalPk,
    actions: Vec<(FraAction, u7)>,
) -> Vec<(ControlBlock, LeafScript)> {
    // 1. 把每个 (action, depth) 包装成 LeafInfo<LeafScript>
    let leaf_infos = actions
        .into_iter()
        .map(|(action, depth)| fra_leaf_info(action, depth))
        .collect::<Vec<_>>();

    // 2. 用所有叶子构造一棵 Merkle 树
    let tap_tree = TapTree::from_leaves(leaf_infos)
        .expect("FRA script tree build failed");

    // 3. 用 ControlBlockFactory 结合 internal_pk 生成每个叶子的 ControlBlock
    ControlBlockFactory::with(internal_pk, tap_tree)
        .collect()
}

