

# FRA: 用于 Taproot 的可替代资产脚本库

[![测试状态](https://img.shields.io/badge/tests-13/13%20passed-brightgreen)](./tests/fra_actions.rs)
[![许可证](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)

`fra` 是一个现代、简约且符合标准的 Rust 模块，专为在比特币 Taproot 上构建可替代资产（Fungible Asset）协议而设计。它提供了一套用于生成特定资产操作脚本的核心功能，完全兼容 `bp-core` 和 `rust-bitcoin` 生态。

本项目旨在提供一个纯粹的脚本生成引擎，它不处理私钥，确保了冷钱包环境下的安全性。

## 核心特性

- **全面的资产操作**: 支持发行、转账、销毁、拆分、合并等多种原子化操作。
- **Taproot 原生**: 所有脚本都为 Taproot 结构设计，充分利用其效率和隐私优势。
- **标准兼容**: 遵循 BIP-340/341/342 规范，生成的脚本逻辑清晰、健壮。
- **无私钥依赖**: 库本身不涉及任何私钥管理和签名操作，仅负责生成脚本，适用于离线环境。
- **技术栈灵活**: 可与 `rust-bitcoin` 或 `bp-core` 无缝集成，满足不同项目的需求。
- **经过验证**: 附带了覆盖所有操作的完整集成测试套件，在 Regtest 环境下验证通过。

## 核心概念

### `FraAction` 枚举

这是与库交互的主要入口点。它定义了所有支持的资产操作，每个操作都包含了生成相应脚本所需的所有参数。

```rust
pub enum FraAction {
    // 双重签名转账
    Transfer { asset_id: [u8; 32], amount: u64, receiver: XOnlyPk, sender: XOnlyPk },
    // 单签增发
    Mint { asset_id: [u8; 32], amount: u64, receiver: OutputPk, minter: XOnlyPk },
    // 单签销毁
    Burn { asset_id: [u8; 32], amount: u64, owner: XOnlyPk },
    // UTXO 拆分
    Split { asset_id: [u8; 32], orig_amount: u64, outputs: Vec<(u64, OutputPk)>, owner: XOnlyPk },
    // UTXO 合并
    Merge { asset_id: [u8; 32], inputs: Vec<u64>, recipient: OutputPk, owner: XOnlyPk },
    // ... 以及其他管理类操作，如冻结、授权等
}
````

### `build_fra_script` 函数

这是库的核心功能函数。它接收一个 `FraAction` 实例，并返回一个 `bc::TapScript`，其中包含了可在 Taproot 叶子节点中使用的比特币脚本字节码。

```rust
pub fn build_fra_script(action: FraAction) -> TapScript;
```

### 数据承诺与堆栈清理

本库生成的脚本广泛采用“数据承诺”模式，即将关键数据（如 `asset_id`、`amount`、`receiver` 等）直接编码进脚本中。这确保了这些数据被包含在签名哈希（Sighash）内，无法被篡改。

同时，所有脚本都经过精心设计，以确保在成功执行后**正确清理堆栈**，只留下一个代表 `TRUE` 的值，从而满足比特币脚本的有效性规则。

## 快速上手

以下是一个构建 `Mint` 操作脚本并创建 Taproot 地址的简要流程：

```rust
use bc::{TapScript, TapCode, XOnlyPk, OutputPk, InternalPk};
use derive::fra::{FraAction, build_fra_script};
use derive::taptree::{TapTree, LeafInfo};
use amplify::num::u7;

// 1. 定义一个资产操作
let minter_pk = XOnlyPk::from_byte_array([2; 32]).unwrap();
let receiver_pk = OutputPk::from_unchecked(XOnlyPk::from_byte_array([3; 32]).unwrap());

let action = FraAction::Mint {
    asset_id: [1; 32],
    amount: 1000,
    receiver: receiver_pk,
    minter: minter_pk,
};

// 2. 生成对应的 TapScript
let tap_script = build_fra_script(action);
println!("生成的脚本 (Hex): {}", tap_script.as_inner().to_hex());

// 3. 将脚本放入 TapTree 中
// 在真实的 Taproot 应用中，你可以组合多个脚本
let internal_key = InternalPk::from_byte_array([4; 32]).unwrap();
let leaf_info = LeafInfo::tap_script(u7::ZERO, tap_script);
let tap_tree = TapTree::from_leaves(vec![leaf_info]).unwrap();

// 4. 计算 Merkle Root 并生成地址
// (此步骤通常使用 rust-bitcoin 或类似库完成)
let merkle_root = tap_tree.merkle_root();
let (output_key, _) = internal_key.to_output_pk(Some(merkle_root));
let address = bc::Address::p2tr_tweaked(output_key, bc::AddressNetwork::Regtest);

println!("生成的 Taproot 地址: {}", address);
```

## 详细用法示例

我们提供了两个完整的、可在 Regtest 环境下运行的示例，展示了如何将 `fra.rs` 集成到你的项目中。

  - **[示例 1: 结合 `rust-bitcoin` 使用]** 
    这是最常见的使用方式，利用 `rust-bitcoin` 库构建、签名和广播交易，与 `bitcoincore-rpc` 完美兼容。

  - **[示例 2: 结合 `bp-core` 使用]**
    如果你整个项目都构建在 `bp-core` 生态之上，此示例展示了如何使用 `bc::Tx` 等类型来完成同样的工作，保持技术栈的一致性。

## API 参考

### `fra.rs`

  - `pub enum FraAction`: 定义了所有支持的资产操作。
  - `pub fn build_fra_script(action: FraAction) -> TapScript`: 根据 `FraAction` 构建比特币脚本。
  - `pub fn fra_leaf_info(action: FraAction, depth: u7) -> LeafInfo<LeafScript>`: 将脚本打包成 `TapTree` 所需的叶子节点信息。
  - `pub fn build_fra_control_blocks(...) -> Vec<(ControlBlock, LeafScript)>`: 批量为一系列 `FraAction` 构建 Taproot 证明。

## 如何测试

本模块包含一套完整的集成测试，覆盖了 `FraAction` 的所有变体。

**前提**:

1.  确保本地运行一个 Bitcoin Core 节点，并开启 Regtest 模式。
2.  确保 `bitcoin.conf` 中配置了 RPC 用户名和密码。
3.  创建一个名为 `legacy_true` 的钱包 (`bitcoin-cli createwallet legacy_true`)。

运行以下命令来执行测试：

```bash
cargo test --test fra_actions -- --nocapture --test-threads=1
```

  - `--nocapture`: 实时显示 `println!` 输出，便于调试。
  - `--test-threads=1`: **必须设置**。由于测试需要与同一个 `bitcoind` 实例交互，此参数可防止因并发 RPC 请求导致的竞态条件。

## 许可证

本项目采用 [Apache 2.0](https://www.google.com/search?q=./LICENSE) 许可证。

