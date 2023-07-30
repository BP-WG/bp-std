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
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::num::NonZeroU32;
use std::ops::Deref;

use bc::{Chain, Outpoint, ScriptPubkey, Txid};

use crate::chain::BlockHeight;
use crate::derive::DeriveSpk;
use crate::{AddrInfo, Address, BlockInfo, Idx, NormalIndex, TxInfo, UtxoInfo};

#[derive(Getters, Clone, Eq, PartialEq, Debug)]
pub struct WalletDescr<D>
where D: DeriveSpk
{
    script_pubkey: D,
    keychains: BTreeSet<NormalIndex>,
    #[getter(as_copy)]
    chain: Chain,
}

impl<D: DeriveSpk> Deref for WalletDescr<D> {
    type Target = D;

    fn deref(&self) -> &Self::Target { &self.script_pubkey }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct WalletData {
    pub name: String,
    pub tx_annotations: BTreeMap<Txid, String>,
    pub txout_annotations: BTreeMap<Outpoint, String>,
    pub txin_annotations: BTreeMap<Outpoint, String>,
    pub addr_annotations: BTreeMap<Address, String>,
    pub last_used: NormalIndex,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct WalletCache {
    tip: u32,
    headers: HashMap<NonZeroU32, BlockInfo>,
    tx: HashMap<Txid, TxInfo>,
    utxo: HashMap<Outpoint, UtxoInfo>,
    addr: HashMap<(NormalIndex, NormalIndex), AddrInfo>,
    max_known: HashMap<NormalIndex, NormalIndex>,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Wallet<D: DeriveSpk, L2: Default = ()> {
    descr: WalletDescr<D>,
    data: WalletData,
    cache: WalletCache,
    layer2: L2,
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
    fn new() -> Self {
        WalletCache {
            tip: 0,
            headers: none!(),
            tx: none!(),
            utxo: none!(),
            addr: none!(),
            max_known: none!(),
        }
    }

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
                    r.iter().map(|utxo| utxo.derivation.1).max().unwrap_or_default(),
                    *max_known,
                );
                if r.is_empty() {
                    break;
                }
                cache.utxo.extend(r.into_iter().map(|utxo| (utxo.outpoint, utxo)));
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
