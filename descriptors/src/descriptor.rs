// Modern, minimalistic & standard-compliant cold wallet library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2020-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2020-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2020-2024 Dr Maxim Orlovsky. All rights reserved.
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

use std::collections::{BTreeSet, HashMap};
use std::fmt::{Display, Formatter};
use std::{fmt, iter};

use derive::{
    Bip340Sig, Derive, DeriveCompr, DeriveScripts, DeriveSet, DeriveXOnly, DerivedScript,
    KeyOrigin, Keychain, LegacyPk, LegacySig, NormalIndex, Sats, SigScript, TapDerivation,
    Terminal, Witness, XOnlyPk, XpubAccount, XpubDerivable,
};
use indexmap::IndexMap;

use crate::{TrKey, Wpkh};

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display)]
#[display(lowercase)]
pub enum SpkClass {
    Bare,
    P2pkh,
    P2sh,
    P2wpkh,
    P2wsh,
    P2tr,
}

impl SpkClass {
    pub const fn dust_limit(self) -> Sats {
        match self {
            SpkClass::Bare => Sats(0),
            SpkClass::P2pkh => Sats(546),
            SpkClass::P2sh => Sats(540),
            SpkClass::P2wpkh => Sats(294),
            SpkClass::P2wsh | SpkClass::P2tr => Sats(330),
        }
    }

    pub const fn is_taproot(self) -> bool {
        match self {
            SpkClass::Bare
            | SpkClass::P2pkh
            | SpkClass::P2sh
            | SpkClass::P2wpkh
            | SpkClass::P2wsh => false,
            SpkClass::P2tr => true,
        }
    }
}

pub struct LegacyKeySig {
    pub key: LegacyPk,
    pub sig: LegacySig,
}

impl LegacyKeySig {
    pub fn new(key: LegacyPk, sig: LegacySig) -> Self { LegacyKeySig { key, sig } }
}

pub struct TaprootKeySig {
    pub key: XOnlyPk,
    pub sig: Bip340Sig,
}

impl TaprootKeySig {
    pub fn new(key: XOnlyPk, sig: Bip340Sig) -> Self { TaprootKeySig { key, sig } }
}

pub trait Descriptor<K = XpubDerivable, V = ()>: DeriveScripts + Clone + Display {
    fn class(&self) -> SpkClass;
    #[inline]
    fn is_taproot(&self) -> bool { self.class().is_taproot() }

    fn keys<'a>(&'a self) -> impl Iterator<Item = &'a K>
    where K: 'a;
    fn vars<'a>(&'a self) -> impl Iterator<Item = &'a V>
    where V: 'a;
    fn xpubs(&self) -> impl Iterator<Item = &XpubAccount>;

    fn legacy_keyset(&self, terminal: Terminal) -> IndexMap<LegacyPk, KeyOrigin>;
    fn xonly_keyset(&self, terminal: Terminal) -> IndexMap<XOnlyPk, TapDerivation>;

    fn legacy_witness(
        &self,
        keysigs: HashMap<&KeyOrigin, LegacyKeySig>,
    ) -> Option<(SigScript, Witness)>;

    fn taproot_witness(&self, keysigs: HashMap<&KeyOrigin, TaprootKeySig>) -> Option<Witness>;
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        crate = "serde_crate",
        rename_all = "camelCase",
        bound(
            serialize = "S::Compr: serde::Serialize, S::XOnly: serde::Serialize",
            deserialize = "S::Compr: serde::Deserialize<'de>, S::XOnly: serde::Deserialize<'de>"
        )
    )
)]
#[non_exhaustive]
pub enum StdDescr<S: DeriveSet = XpubDerivable> {
    /*
    #[from]
    Bare(Bare<S::Legacy>),

    #[from]
    Pkh(Pkh<S::Legacy>),

    #[from]
    ShMulti(ShMulti<S::Legacy>),

    #[from]
    ShSortedMulti(ShSortedMulti<S::Legacy>),

    #[from]
    ShTlMulti(ShTlMulti<S::Legacy>),

    #[from]
    ShTemplate(ShTemplate<S::Legacy>),
     */
    #[from]
    Wpkh(Wpkh<S::Compr>),

    /*
    #[from]
    WshMulti(WshMulti<S::Compr>),

    #[from]
    WshSortedMulti(WshSortedMulti<S::Compr>),

    #[from]
    WshTlMulti(WshTlMulti<S::Compr>),

    #[from]
    WshTemplate(ShTemplate<S::Compr>),
     */
    #[from]
    TrKey(TrKey<S::XOnly>),
    /*
    #[from]
    TrMusig(TrMusig<S::XOnly>),

    #[from]
    TrMulti(TrMulti<S::XOnly>),

    #[from]
    TrTlMulti(TrTlMulti<S::XOnly>),

    #[from]
    TrTree(TrTree<S::XOnly>),

    // This should go into LNP:
    Bolt(Bolt<S::Compr>)

    // The rest should go to RGB:
    #[from]
    TapretKey(TapretKey<S::XOnly),

    #[from]
    TapretMusig(TapretMusig<S::XOnly>),

    #[from]
    TrMulti(TapretMulti<S::XOnly>),

    #[from]
    TapretTlMulti(TapretTlMulti<S::XOnly>),

    #[from]
    TapretTree(TapretTree<S::XOnly>),
     */
}

impl<S: DeriveSet> Derive<DerivedScript> for StdDescr<S> {
    fn default_keychain(&self) -> Keychain {
        match self {
            StdDescr::Wpkh(d) => d.default_keychain(),
            StdDescr::TrKey(d) => d.default_keychain(),
        }
    }

    fn keychains(&self) -> BTreeSet<Keychain> {
        match self {
            StdDescr::Wpkh(d) => d.keychains(),
            StdDescr::TrKey(d) => d.keychains(),
        }
    }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> DerivedScript {
        match self {
            StdDescr::Wpkh(d) => d.derive(keychain, index),
            StdDescr::TrKey(d) => d.derive(keychain, index),
        }
    }
}

impl<K: DeriveSet<Compr = K, XOnly = K> + DeriveCompr + DeriveXOnly> Descriptor<K> for StdDescr<K>
where Self: Derive<DerivedScript>
{
    fn class(&self) -> SpkClass {
        match self {
            StdDescr::Wpkh(d) => d.class(),
            StdDescr::TrKey(d) => d.class(),
        }
    }

    fn keys<'a>(&'a self) -> impl Iterator<Item = &'a K>
    where K: 'a {
        match self {
            StdDescr::Wpkh(d) => d.keys().collect::<Vec<_>>(),
            StdDescr::TrKey(d) => d.keys().collect::<Vec<_>>(),
        }
        .into_iter()
    }

    fn vars<'a>(&'a self) -> impl Iterator<Item = &'a ()>
    where (): 'a {
        iter::empty()
    }

    fn xpubs(&self) -> impl Iterator<Item = &XpubAccount> {
        match self {
            StdDescr::Wpkh(d) => d.xpubs().collect::<Vec<_>>(),
            StdDescr::TrKey(d) => d.xpubs().collect::<Vec<_>>(),
        }
        .into_iter()
    }

    fn legacy_keyset(&self, terminal: Terminal) -> IndexMap<LegacyPk, KeyOrigin> {
        match self {
            StdDescr::Wpkh(d) => d.legacy_keyset(terminal),
            StdDescr::TrKey(d) => d.legacy_keyset(terminal),
        }
    }

    fn xonly_keyset(&self, terminal: Terminal) -> IndexMap<XOnlyPk, TapDerivation> {
        match self {
            StdDescr::Wpkh(d) => d.xonly_keyset(terminal),
            StdDescr::TrKey(d) => d.xonly_keyset(terminal),
        }
    }

    fn legacy_witness(
        &self,
        keysigs: HashMap<&KeyOrigin, LegacyKeySig>,
    ) -> Option<(SigScript, Witness)> {
        match self {
            StdDescr::Wpkh(d) => d.legacy_witness(keysigs),
            StdDescr::TrKey(d) => d.legacy_witness(keysigs),
        }
    }

    fn taproot_witness(&self, keysigs: HashMap<&KeyOrigin, TaprootKeySig>) -> Option<Witness> {
        match self {
            StdDescr::Wpkh(d) => d.taproot_witness(keysigs),
            StdDescr::TrKey(d) => d.taproot_witness(keysigs),
        }
    }
}

impl<S: DeriveSet> Display for StdDescr<S>
where
    S::Legacy: Display,
    S::Compr: Display,
    S::XOnly: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            StdDescr::Wpkh(d) => Display::fmt(d, f),
            StdDescr::TrKey(d) => Display::fmt(d, f),
        }
    }
}
