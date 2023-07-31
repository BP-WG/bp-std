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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::num::NonZeroU32;
use std::ops::Deref;

use bc::{Chain, Outpoint, Txid};

use crate::derive::DeriveSpk;
use crate::{AddrInfo, Address, BlockInfo, Idx, NormalIndex, TxInfo, UtxoInfo};

#[derive(Getters, Clone, Eq, PartialEq, Debug)]
pub struct WalletDescr<D>
where D: DeriveSpk
{
    pub(crate) script_pubkey: D,
    pub(crate) keychains: BTreeSet<NormalIndex>,
    #[getter(as_copy)]
    pub(crate) chain: Chain,
}

impl<D: DeriveSpk> WalletDescr<D> {
    pub fn new_standard(descr: D, network: Chain) -> Self {
        WalletDescr {
            script_pubkey: descr,
            keychains: bset! { NormalIndex::ZERO, NormalIndex::ONE },
            chain: network,
        }
    }
}

impl<D: DeriveSpk> Deref for WalletDescr<D> {
    type Target = D;

    fn deref(&self) -> &Self::Target { &self.script_pubkey }
}

#[derive(Clone, Eq, PartialEq, Debug, Default)]
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
    pub(crate) tip: u32,
    pub(crate) headers: HashMap<NonZeroU32, BlockInfo>,
    pub(crate) tx: HashMap<Txid, TxInfo>,
    pub(crate) utxo: HashMap<Outpoint, UtxoInfo>,
    pub(crate) addr: HashMap<(NormalIndex, NormalIndex), AddrInfo>,
    pub(crate) max_known: HashMap<NormalIndex, NormalIndex>,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Wallet<D: DeriveSpk, L2: Default = ()> {
    descr: WalletDescr<D>,
    data: WalletData,
    cache: WalletCache,
    layer2: L2,
}

impl<D: DeriveSpk, L2: Default> Deref for Wallet<D, L2> {
    type Target = WalletDescr<D>;

    fn deref(&self) -> &Self::Target { &self.descr }
}

impl<D: DeriveSpk, L2: Default> Wallet<D, L2> {
    pub fn new(descr: D, network: Chain) -> Self {
        Wallet {
            descr: WalletDescr::new_standard(descr, network),
            data: empty!(),
            cache: WalletCache::new(),
            layer2: default!(),
        }
    }
}

impl WalletCache {
    pub(crate) fn new() -> Self {
        WalletCache {
            tip: 0,
            headers: none!(),
            tx: none!(),
            utxo: none!(),
            addr: none!(),
            max_known: none!(),
        }
    }
}
