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
use std::num::ParseIntError;
use std::ops::Range;
use std::str::FromStr;

use bc::secp256k1::XOnlyPublicKey;
use bc::{InternalPk, ScriptPubkey};

use crate::address::AddressError;
use crate::{
    Address, AddressNetwork, AddressParseError, ComprPubkey, Idx, IndexParseError, NormalIndex,
    XpubDescriptor,
};

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display)]
#[display("&{keychain}/{index}")]
pub struct Terminal {
    pub keychain: u8,
    pub index: NormalIndex,
}

impl Terminal {
    pub fn new(keychain: u8, index: NormalIndex) -> Self { Terminal { keychain, index } }
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum TerminalParseError {
    /// terminal derivation path must start with keychain index prefixed with '&'.
    NoKeychain,

    /// keychain index in terminal derivation path is not a number.
    #[from]
    InvalidKeychain(ParseIntError),

    #[from]
    Index(IndexParseError),

    /// derivation path '{0}' is not a terminal path - terminal path must contain exactly two
    /// components.
    InvalidComponents(String),
}

impl FromStr for Terminal {
    type Err = TerminalParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut iter = s.split('/');
        match (iter.next(), iter.next(), iter.next()) {
            (Some(keychain), Some(index), None) => {
                if !keychain.starts_with('&') {
                    return Err(TerminalParseError::NoKeychain);
                }
                Ok(Terminal::new(keychain.trim_start_matches('&').parse()?, index.parse()?))
            }
            _ => Err(TerminalParseError::InvalidComponents(s.to_owned())),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[non_exhaustive]
pub enum DerivedScript {
    Bare(ScriptPubkey),
    Bip13(RedeemScript),
    Segwit(WitnessScript),
    Nested(WitnessScript),
    // Taproot(XOnlyPublicKey, Option<TapTree>)
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display)]
#[display("{addr}{terminal}")]
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
    pub fn new(addr: Address, keychain: u8, index: NormalIndex) -> Self {
        DerivedAddr {
            addr,
            terminal: Terminal::new(keychain, index),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(inner)]
pub enum DerivedAddrParseError {
    #[display("address must be followed by a & and derivation information")]
    NoSeparator,

    #[from]
    Address(AddressParseError),

    #[from]
    Terminal(TerminalParseError),
}

impl FromStr for DerivedAddr {
    type Err = DerivedAddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let pos = s.find('&').ok_or(DerivedAddrParseError::NoSeparator)?;
        let (addr, terminal) = s.split_at(pos);
        Ok(DerivedAddr {
            addr: addr.parse()?,
            terminal: terminal.parse()?,
        })
    }
}

pub trait Derive<D> {
    fn keychains(&self) -> Range<u8>;

    fn derive(&self, keychain: u8, index: impl Into<NormalIndex>) -> D;

    fn derive_batch(&self, keychain: u8, from: impl Into<NormalIndex>, max_count: u8) -> Vec<D> {
        let keychain = keychain.into();
        let mut index = from.into();
        let mut count = 0u8;
        let mut batch = Vec::with_capacity(max_count as usize);
        loop {
            batch.push(self.derive(keychain, index));
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
        keychain: u8,
        index: impl Into<NormalIndex>,
    ) -> Result<Address, AddressError> {
        let spk = self.derive(keychain, index);
        Address::with(&spk, network)
    }

    fn derive_address_batch(
        &self,
        network: AddressNetwork,
        keychain: u8,
        from: impl Into<NormalIndex>,
        max_count: u8,
    ) -> Result<Vec<Address>, AddressError> {
        self.derive_batch(keychain, from, max_count)
            .into_iter()
            .map(|spk| Address::with(&spk, network))
            .collect()
    }
}
impl<T: Derive<ScriptPubkey>> DeriveSpk for T {}

impl Derive<ComprPubkey> for XpubDescriptor {
    #[inline]
    fn keychains(&self) -> Range<u8> { 0..self.keychains.count() }

    fn derive(&self, keychain: u8, index: impl Into<NormalIndex>) -> ComprPubkey {
        self.xpub().derive_pub([keychain.into(), index.into()]).to_compr_pub()
    }
}

impl Derive<InternalPk> for XpubDescriptor {
    #[inline]
    fn keychains(&self) -> Range<u8> { 0..self.keychains.count() }

    fn derive(&self, keychain: u8, index: impl Into<NormalIndex>) -> InternalPk {
        self.xpub().derive_pub([keychain.into(), index.into()]).to_xonly_pub().into()
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
