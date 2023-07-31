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

use std::cmp::max;
use std::num::NonZeroU32;

use bc::{
    BlockHash, BlockHeader, LockTime, Outpoint, Sats, ScriptPubkey, SeqNo, SigScript, Txid, Witness,
};

use crate::{
    Address, DeriveSpk, DerivedAddr, Idx, NormalIndex, Terminal, WalletCache, WalletDescr,
};

pub type BlockHeight = NonZeroU32;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct BlockInfo {
    pub header: BlockHeader,
    pub difficulty: u8,
    pub tx_count: u32,
    pub size: u32,
    pub weight: u32,
    pub mediantime: u32,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct MiningInfo {
    pub height: BlockHeight,
    pub time: u64,
    pub block_hash: BlockHash,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
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

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct TxOutInfo {
    pub outpoint: Outpoint,
    pub value: Sats,
    pub derivation: Option<Terminal>,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct UtxoInfo {
    pub outpoint: Outpoint,
    pub value: Sats,
    pub address: Address,
    pub terminal: Terminal,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct AddrInfo {
    pub addr: Address,
    pub terminal: Terminal,
    pub used: u32,
    pub volume: Sats,
    pub balance: Sats,
}

impl From<DerivedAddr> for AddrInfo {
    fn from(derived: DerivedAddr) -> Self {
        AddrInfo {
            addr: derived.addr,
            terminal: derived.terminal,
            used: 0,
            volume: Sats::ZERO,
            balance: Sats::ZERO,
        }
    }
}

pub trait Blockchain {
    type Error;

    fn get_blocks(
        &self,
        heights: impl IntoIterator<Item = BlockHeight>,
    ) -> (Vec<BlockInfo>, Vec<Self::Error>);

    fn get_txes(&self, txids: impl IntoIterator<Item = Txid>) -> (Vec<TxInfo>, Vec<Self::Error>);

    fn get_utxo<'s>(
        &self,
        scripts: impl IntoIterator<Item = &'s ScriptPubkey>,
    ) -> (Vec<UtxoInfo>, Vec<Self::Error>);
}

impl WalletCache {
    pub fn with<B: Blockchain, D: DeriveSpk>(
        descriptor: &WalletDescr<D>,
        blockchain: &B,
    ) -> Result<Self, (Self, Vec<B::Error>)> {
        const BATCH_SIZE: u8 = 20;
        let mut cache = WalletCache::new();
        let mut errors = vec![];

        let mut txids = set! {};
        for keychain in &descriptor.keychains {
            let mut index = NormalIndex::ZERO;
            loop {
                let scripts = descriptor.derive_batch(keychain, index, BATCH_SIZE);
                let (r, e) = blockchain.get_utxo(&scripts);
                errors.extend(e);
                txids.extend(r.iter().map(|utxo| utxo.outpoint.txid));
                let max_known = cache.max_known.entry(*keychain).or_default();
                *max_known = max(
                    r.iter().map(|utxo| utxo.terminal.index).max().unwrap_or_default(),
                    *max_known,
                );
                if r.is_empty() {
                    break;
                }
                cache.utxo.extend(r.into_iter().map(|utxo| (utxo.address, set! {utxo})));
                if !index.saturating_add_assign(BATCH_SIZE) {
                    break;
                }
            }
        }

        let (r, e) = blockchain.get_txes(txids);
        errors.extend(e);
        cache.tx.extend(r.into_iter().map(|tx| (tx.txid, tx)));

        // TODO: Update headers & tip
        // TODO: Construct addr information

        if errors.is_empty() {
            Ok(cache)
        } else {
            Err((cache, errors))
        }
    }

    pub fn update<B: Blockchain, D: DeriveSpk>(
        &mut self,
        descriptor: &D,
        blockchain: &B,
    ) -> Result<(), Vec<B::Error>> {
        todo!()
    }
}
