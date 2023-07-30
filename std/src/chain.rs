// Modern, minimalistic & standard-compliant cold wallet library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2020-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2020-2023 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2020-2023 Dr Maxim Orlovsky. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::num::NonZeroU32;

use bc::{BlockHash, BlockHeader, LockTime, Outpoint, Sats, SeqNo, SigScript, Txid, Witness};

use crate::{Address, NormalIndex};

pub type BlockHeight = NonZeroU32;

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct BlockInfo {
    pub header: BlockHeader,
    pub difficulty: u8,
    pub tx_count: u32,
    pub size: u32,
    pub weight: u32,
    pub mediantime: u32,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct MiningInfo {
    pub height: BlockHeight,
    pub time: u64,
    pub block_hash: BlockHash,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum TxStatus {
    Mined(MiningInfo),
    Mempool,
    Channel,
    Unknown,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct TxInfo {
    pub txid: Txid,
    pub status: TxStatus,
    pub inputs: Vec<TxInInfo>,
    pub outputs: Vec<TxOutInfo>,
    pub fee: Sats,
    pub size: u32,
    pub weight: u32,
    pub version: i32,
    pub locktime: LockTime,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct TxInInfo {
    pub outpoint: Outpoint,
    pub sequence: SeqNo,
    pub coinbase: bool,
    pub script_sig: SigScript,
    pub witness: Witness,
    pub value: Option<Sats>,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct TxOutInfo {
    pub outpoint: Outpoint,
    pub value: Sats,
    pub derivation: Option<(NormalIndex, NormalIndex)>,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct UtxoInfo {
    pub outpoint: Outpoint,
    pub value: Sats,
    pub address: Address,
    pub derivation: (NormalIndex, NormalIndex),
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct AddrInfo {
    pub derivation: (NormalIndex, NormalIndex),
    pub used: u32,
    pub volume: Sats,
    pub balance: Sats,
}
