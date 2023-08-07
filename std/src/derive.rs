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

use std::cmp::Ordering;

use bc::{InternalPk, ScriptPubkey};

use crate::address::AddressError;
use crate::{Address, AddressNetwork, ComprPubkey, Idx, NormalIndex, XpubDescriptor};

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display)]
#[display("/{keychain}/{index}")]
pub struct Terminal {
    pub keychain: NormalIndex,
    pub index: NormalIndex,
}

impl Terminal {
    pub fn new(keychain: NormalIndex, index: NormalIndex) -> Self { Terminal { keychain, index } }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct DerivedAddr {
    pub addr: Address,
    pub terminal: Terminal,
}

impl Ord for DerivedAddr {
    fn cmp(&self, other: &Self) -> Ordering { self.terminal.cmp(&other.terminal) }
}

impl PartialOrd for DerivedAddr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl DerivedAddr {
    pub fn new(addr: Address, keychain: NormalIndex, index: NormalIndex) -> Self {
        DerivedAddr {
            addr,
            terminal: Terminal::new(keychain, index),
        }
    }
}

pub trait Derive<D> {
    fn derive(&self, change: impl Into<NormalIndex>, index: impl Into<NormalIndex>) -> D;

    fn derive_batch(
        &self,
        change: impl Into<NormalIndex>,
        from: impl Into<NormalIndex>,
        max_count: u8,
    ) -> Vec<D> {
        let change = change.into();
        let mut index = from.into();
        let mut count = 0u8;
        let mut batch = Vec::with_capacity(max_count as usize);
        loop {
            batch.push(self.derive(change, index));
            count += 1;
            if index.checked_inc_assign().is_none() || count >= max_count {
                return batch;
            }
        }
    }
}

pub trait DeriveCompr: Derive<ComprPubkey> {}
impl<T: Derive<ComprPubkey>> DeriveCompr for T {}

pub trait DeriveXOnly: Derive<InternalPk> {}
impl<T: Derive<InternalPk>> DeriveXOnly for T {}

pub trait DeriveSpk: Derive<ScriptPubkey> {
    fn derive_address(
        &self,
        network: AddressNetwork,
        change: impl Into<NormalIndex>,
        index: impl Into<NormalIndex>,
    ) -> Result<Address, AddressError> {
        let spk = self.derive(change, index);
        Address::with(&spk, network)
    }

    fn derive_address_batch(
        &self,
        network: AddressNetwork,
        change: impl Into<NormalIndex>,
        from: impl Into<NormalIndex>,
        max_count: u8,
    ) -> Result<Vec<Address>, AddressError> {
        self.derive_batch(change, from, max_count)
            .into_iter()
            .map(|spk| Address::with(&spk, network))
            .collect()
    }
}
impl<T: Derive<ScriptPubkey>> DeriveSpk for T {}

impl Derive<ComprPubkey> for XpubDescriptor {
    fn derive(&self, change: impl Into<NormalIndex>, index: impl Into<NormalIndex>) -> ComprPubkey {
        self.xpub().derive_pub([change.into(), index.into()]).to_compr_pub()
    }
}

impl Derive<InternalPk> for XpubDescriptor {
    fn derive(&self, change: impl Into<NormalIndex>, index: impl Into<NormalIndex>) -> InternalPk {
        self.xpub().derive_pub([change.into(), index.into()]).to_xonly_pub().into()
    }
}

pub trait DeriveSet {
    type Compr: DeriveCompr;
    type XOnly: DeriveXOnly;
}

impl DeriveSet for XpubDescriptor {
    type Compr = XpubDescriptor;
    type XOnly = XpubDescriptor;
}
