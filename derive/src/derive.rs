// Modern, minimalistic & standard-compliant Bitcoin library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Labs, Institute for Distributed and Cognitive Systems (InDCS).
// Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
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
use std::collections::BTreeSet;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::iter;
use std::num::ParseIntError;
use std::str::FromStr;

use amplify::Wrapper;
use bc::{
    CompressedPk, ControlBlock, InternalPk, LeafScript, LegacyPk, PubkeyHash, RedeemScript,
    ScriptPubkey, TapNodeHash, WitnessScript, XOnlyPk,
};
use indexmap::IndexMap;

use crate::{
    Address, AddressNetwork, AddressParseError, ControlBlockFactory, DerivationIndex, IdxBase,
    IndexParseError, NormalIndex, TapTree, XpubAccount, XpubDerivable,
};

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug, Display, From)]
#[wrapper(FromStr)]
#[display(inner)]
pub struct Keychain(u8);

impl From<Keychain> for NormalIndex {
    #[inline]
    fn from(keychain: Keychain) -> Self { NormalIndex::from(keychain.0) }
}

impl From<Keychain> for DerivationIndex {
    #[inline]
    fn from(keychain: Keychain) -> Self { DerivationIndex::Normal(keychain.into()) }
}

impl Keychain {
    pub const OUTER: Self = Keychain(0);
    pub const INNER: Self = Keychain(1);

    pub const fn with(idx: u8) -> Self { Keychain(idx) }
}

impl IdxBase for Keychain {
    #[inline]
    fn is_hardened(&self) -> bool { false }

    #[inline]
    fn child_number(&self) -> u32 { self.0 as u32 }

    #[inline]
    fn index(&self) -> u32 { self.0 as u32 }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display)]
#[display("&{keychain}/{index}")]
pub struct Terminal {
    pub keychain: Keychain,
    pub index: NormalIndex,
}

impl Terminal {
    pub fn new(keychain: impl Into<Keychain>, index: NormalIndex) -> Self {
        Terminal {
            keychain: keychain.into(),
            index,
        }
    }
    pub fn change(index: NormalIndex) -> Self { Self::new(1, index) }
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
                Ok(Terminal::new(
                    Keychain::from_str(keychain.trim_start_matches('&'))?,
                    index.parse()?,
                ))
            }
            _ => Err(TerminalParseError::InvalidComponents(s.to_owned())),
        }
    }
}

#[cfg(feature = "serde")]
mod _serde {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for Keychain {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            if serializer.is_human_readable() {
                self.0.to_string().serialize(serializer)
            } else {
                self.0.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for Keychain {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            if deserializer.is_human_readable() {
                let s = String::deserialize(deserializer)?;
                Self::from_str(&s).map_err(D::Error::custom)
            } else {
                Ok(Self(u8::deserialize(deserializer)?))
            }
        }
    }

    impl Serialize for Terminal {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            if serializer.is_human_readable() {
                self.to_string().serialize(serializer)
            } else {
                let tuple = (self.keychain, self.index);
                tuple.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for Terminal {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            if deserializer.is_human_readable() {
                let s = String::deserialize(deserializer)?;
                Self::from_str(&s).map_err(D::Error::custom)
            } else {
                let d = <(Keychain, NormalIndex)>::deserialize(deserializer)?;
                Ok(Self {
                    keychain: d.0,
                    index: d.1,
                })
            }
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[non_exhaustive]
pub enum DerivedScript {
    Bare(ScriptPubkey),
    Bip13(RedeemScript),
    Segwit(WitnessScript),
    NestedKey(CompressedPk),
    NestedScript(WitnessScript),
    TaprootKeyOnly(InternalPk),
    TaprootScript(InternalPk, TapTree),
}

impl DerivedScript {
    pub fn to_script_pubkey(&self) -> ScriptPubkey {
        match self {
            DerivedScript::Bare(script_pubkey) => script_pubkey.clone(),
            DerivedScript::Bip13(redeem_script) => redeem_script.to_script_pubkey(),
            DerivedScript::Segwit(witness_script) => witness_script.to_script_pubkey(),
            DerivedScript::NestedKey(_) => self
                .to_redeem_script()
                .expect("redeedm script must be defined for ShWpkh")
                .to_script_pubkey(),

            DerivedScript::NestedScript(witness_script) => {
                witness_script.to_redeem_script().to_script_pubkey()
            }
            DerivedScript::TaprootKeyOnly(internal_key) => {
                ScriptPubkey::p2tr_key_only(*internal_key)
            }
            DerivedScript::TaprootScript(internal_pk, tap_tree) => {
                internal_pk.to_output_pk(Some(tap_tree.merkle_root())).0.to_script_pubkey()
            }
        }
    }

    pub fn to_redeem_script(&self) -> Option<RedeemScript> {
        match self {
            DerivedScript::Bare(_) => None,
            DerivedScript::Bip13(redeem_script) => Some(redeem_script.clone()),
            DerivedScript::Segwit(_) => None,
            DerivedScript::NestedKey(pk) => Some(RedeemScript::from_checked(
                ScriptPubkey::p2pkh(PubkeyHash::from(*pk)).into_inner().into_vec(),
            )),
            DerivedScript::NestedScript(witness_script) => Some(witness_script.to_redeem_script()),
            DerivedScript::TaprootKeyOnly(_) => None,
            DerivedScript::TaprootScript(_, _) => None,
        }
    }
    pub fn as_witness_script(&self) -> Option<&WitnessScript> {
        match self {
            DerivedScript::Bare(_) => None,
            DerivedScript::Bip13(_) => None,
            DerivedScript::NestedKey(_) => None,
            DerivedScript::Segwit(witness_script) | DerivedScript::NestedScript(witness_script) => {
                Some(witness_script)
            }
            DerivedScript::TaprootKeyOnly(_) => None,
            DerivedScript::TaprootScript(_, _) => None,
        }
    }
    pub fn to_witness_script(&self) -> Option<WitnessScript> { self.as_witness_script().cloned() }

    pub fn to_internal_pk(&self) -> Option<InternalPk> {
        match self {
            DerivedScript::Bare(_)
            | DerivedScript::Bip13(_)
            | DerivedScript::Segwit(_)
            | DerivedScript::NestedKey(_)
            | DerivedScript::NestedScript(_) => None,
            DerivedScript::TaprootKeyOnly(internal_key) => Some(*internal_key),
            DerivedScript::TaprootScript(internal_key, _) => Some(*internal_key),
        }
    }

    pub fn as_tap_tree(&self) -> Option<&TapTree> {
        match self {
            DerivedScript::Bare(_)
            | DerivedScript::Bip13(_)
            | DerivedScript::Segwit(_)
            | DerivedScript::NestedKey(_)
            | DerivedScript::NestedScript(_)
            | DerivedScript::TaprootKeyOnly(_) => None,
            DerivedScript::TaprootScript(_, tap_tree) => Some(tap_tree),
        }
    }

    pub fn to_tap_tree(&self) -> Option<TapTree> { self.as_tap_tree().cloned() }

    pub fn to_leaf_scripts(&self) -> IndexMap<ControlBlock, LeafScript> {
        let (Some(internal_pk), Some(tap_tree)) = (self.to_internal_pk(), self.to_tap_tree())
        else {
            return empty!();
        };
        ControlBlockFactory::with(internal_pk, tap_tree).collect()
    }

    #[inline]
    pub fn to_tap_root(&self) -> Option<TapNodeHash> {
        self.to_tap_tree().as_ref().map(TapTree::merkle_root)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
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
    pub fn new(addr: Address, keychain: Keychain, index: NormalIndex) -> Self {
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
    // TODO: Make D an associated type (since each descriptor must derive only one type of keys).

    fn default_keychain(&self) -> Keychain;

    fn keychains(&self) -> BTreeSet<Keychain>;

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = D>;

    fn derive_range(
        &self,
        keychain: impl Into<Keychain>,
        from: impl Into<NormalIndex>,
        to: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = D> {
        let from = from.into().child_number();
        let to = to.into().child_number();
        let keychain = keychain.into();
        (from..to)
            .flat_map(move |index| self.derive(keychain, NormalIndex::normal_unchecked(index)))
    }
}

pub trait DeriveKey<D>: Derive<D> + Clone + Eq + Hash + Debug + Display {
    fn xpub_spec(&self) -> &XpubAccount;
}

pub trait DeriveLegacy: DeriveKey<LegacyPk> {}
impl<T: DeriveKey<LegacyPk>> DeriveLegacy for T {}

pub trait DeriveCompr: DeriveKey<CompressedPk> {}
impl<T: DeriveKey<CompressedPk>> DeriveCompr for T {}

pub trait DeriveXOnly: DeriveKey<XOnlyPk> {}
impl<T: DeriveKey<XOnlyPk>> DeriveXOnly for T {}

pub trait DeriveScripts: Derive<DerivedScript> {
    /// Derives addresses for a given index.
    ///
    /// If the descriptor is not representable in form of an address (uses non-standard script etc),
    /// returns an empty iterator.
    fn derive_address(
        &self,
        network: AddressNetwork,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = Address> {
        self.derive(keychain, index)
            .flat_map(move |spk| Address::with(&spk.to_script_pubkey(), network).ok())
    }

    /// Derives addresses for a range of indexes.
    ///
    /// If the descriptor is not representable in form of an address (uses non-standard script etc),
    /// returns an empty iterator.
    fn derive_address_range(
        &self,
        network: AddressNetwork,
        keychain: impl Into<Keychain>,
        from: impl Into<NormalIndex>,
        to: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = Address> {
        self.derive_range(keychain, from, to)
            .flat_map(move |spk| Address::with(&spk.to_script_pubkey(), network).ok())
    }
}
impl<T: Derive<DerivedScript>> DeriveScripts for T {}

impl DeriveKey<LegacyPk> for XpubDerivable {
    fn xpub_spec(&self) -> &XpubAccount { self.spec() }
}

impl DeriveKey<CompressedPk> for XpubDerivable {
    fn xpub_spec(&self) -> &XpubAccount { self.spec() }
}

impl DeriveKey<XOnlyPk> for XpubDerivable {
    fn xpub_spec(&self) -> &XpubAccount { self.spec() }
}

impl Derive<LegacyPk> for XpubDerivable {
    #[inline]
    fn default_keychain(&self) -> Keychain { self.keychains.first() }

    #[inline]
    fn keychains(&self) -> BTreeSet<Keychain> { self.keychains.to_set() }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = LegacyPk> {
        iter::once(self.xpub().derive_pub([keychain.into().into(), index.into()]).to_legacy_pk())
    }
}

impl Derive<CompressedPk> for XpubDerivable {
    #[inline]
    fn default_keychain(&self) -> Keychain { self.keychains.first() }

    #[inline]
    fn keychains(&self) -> BTreeSet<Keychain> { self.keychains.to_set() }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = CompressedPk> {
        iter::once(self.xpub().derive_pub([keychain.into().into(), index.into()]).to_compr_pk())
    }
}

impl Derive<XOnlyPk> for XpubDerivable {
    #[inline]
    fn default_keychain(&self) -> Keychain { self.keychains.first() }

    #[inline]
    fn keychains(&self) -> BTreeSet<Keychain> { self.keychains.to_set() }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = XOnlyPk> {
        iter::once(self.xpub().derive_pub([keychain.into().into(), index.into()]).to_xonly_pk())
    }
}

pub trait DeriveSet {
    type Legacy: DeriveLegacy;
    type Compr: DeriveCompr;
    type XOnly: DeriveXOnly;
}

impl DeriveSet for XpubDerivable {
    type Legacy = XpubDerivable;
    type Compr = XpubDerivable;
    type XOnly = XpubDerivable;
}
