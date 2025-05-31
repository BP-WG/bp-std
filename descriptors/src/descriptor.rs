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
    Bip340Sig, ControlBlock, Derive, DeriveCompr, DeriveLegacy, DeriveScripts, DeriveSet,
    DeriveXOnly, DerivedScript, KeyOrigin, Keychain, LegacyPk, LegacySig, NormalIndex,
    RedeemScript, Sats, SigScript, TapDerivation, Terminal, Witness, WitnessScript, XOnlyPk,
    XpubAccount, XpubDerivable,
};
use indexmap::IndexMap;

use crate::{
    Pkh, Raw, Sh, ShMulti, ShSortedMulti, ShWpkh, ShWsh, TrKey, TrMulti, TrScript, TrSortedMulti,
    Wpkh, Wsh, WshMulti, WshSortedMulti,
};

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
        redeem_script: Option<RedeemScript>,
        witness_script: Option<WitnessScript>,
    ) -> Option<(SigScript, Option<Witness>)>;

    fn taproot_witness(
        &self,
        cb: Option<&ControlBlock>,
        keysigs: HashMap<&KeyOrigin, TaprootKeySig>,
    ) -> Option<Witness>;
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        rename_all = "camelCase",
        bound(
            serialize = "S::Legacy: serde::Serialize, S::Compr: serde::Serialize, S::XOnly: \
                         serde::Serialize",
            deserialize = "S::Legacy: serde::Deserialize<'de>, S::Compr: serde::Deserialize<'de>, \
                           S::XOnly: serde::Deserialize<'de>"
        )
    )
)]
#[non_exhaustive]
pub enum StdDescr<S: DeriveSet = XpubDerivable> {
    #[from]
    Raw(Raw<S::Legacy>),

    #[from]
    Sh(Sh<S::Legacy>),

    #[from]
    Pkh(Pkh<S::Legacy>),

    #[from]
    ShMulti(ShMulti<S::Legacy>),

    #[from]
    ShSortedMulti(ShSortedMulti<S::Legacy>),

    #[from]
    Wpkh(Wpkh<S::Compr>),

    #[from]
    Wsh(Wsh<S::Compr>),

    #[from]
    WshMulti(WshMulti<S::Compr>),

    #[from]
    WshSortedMulti(WshSortedMulti<S::Compr>),

    #[from]
    ShWpkh(ShWpkh<S::Compr>),

    #[from]
    ShWsh(ShWsh<S::Compr>),

    #[from]
    TrKey(TrKey<S::XOnly>),

    #[from]
    TrMulti(TrMulti<S::XOnly>),

    #[from]
    TrSortedMulti(TrSortedMulti<S::XOnly>),

    #[from]
    TrTree(TrScript<S::XOnly>),
}

impl<S: DeriveSet> Derive<DerivedScript> for StdDescr<S> {
    fn default_keychain(&self) -> Keychain {
        match self {
            StdDescr::Raw(d) => d.default_keychain(),
            StdDescr::Pkh(d) => d.default_keychain(),
            StdDescr::Sh(d) => d.default_keychain(),
            StdDescr::ShMulti(d) => d.default_keychain(),
            StdDescr::ShSortedMulti(d) => d.default_keychain(),
            StdDescr::ShWpkh(d) => d.default_keychain(),
            StdDescr::ShWsh(d) => d.default_keychain(),
            StdDescr::Wpkh(d) => d.default_keychain(),
            StdDescr::Wsh(d) => d.default_keychain(),
            StdDescr::WshMulti(d) => d.default_keychain(),
            StdDescr::WshSortedMulti(d) => d.default_keychain(),
            StdDescr::TrKey(d) => d.default_keychain(),
            StdDescr::TrMulti(d) => d.default_keychain(),
            StdDescr::TrSortedMulti(d) => d.default_keychain(),
            StdDescr::TrTree(d) => d.default_keychain(),
        }
    }

    fn keychains(&self) -> BTreeSet<Keychain> {
        match self {
            StdDescr::Raw(d) => d.keychains(),
            StdDescr::Pkh(d) => d.keychains(),
            StdDescr::Sh(d) => d.keychains(),
            StdDescr::ShMulti(d) => d.keychains(),
            StdDescr::ShSortedMulti(d) => d.keychains(),
            StdDescr::ShWpkh(d) => d.keychains(),
            StdDescr::ShWsh(d) => d.keychains(),
            StdDescr::Wpkh(d) => d.keychains(),
            StdDescr::Wsh(d) => d.keychains(),
            StdDescr::WshMulti(d) => d.keychains(),
            StdDescr::WshSortedMulti(d) => d.keychains(),
            StdDescr::TrKey(d) => d.keychains(),
            StdDescr::TrMulti(d) => d.keychains(),
            StdDescr::TrSortedMulti(d) => d.keychains(),
            StdDescr::TrTree(d) => d.keychains(),
        }
    }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = DerivedScript> {
        match self {
            StdDescr::Raw(d) => d.derive(keychain, index).collect::<Vec<_>>().into_iter(),
            StdDescr::Pkh(d) => d.derive(keychain, index).collect::<Vec<_>>().into_iter(),
            StdDescr::Sh(d) => d.derive(keychain, index).collect::<Vec<_>>().into_iter(),
            StdDescr::ShMulti(d) => d.derive(keychain, index).collect::<Vec<_>>().into_iter(),
            StdDescr::ShSortedMulti(d) => d.derive(keychain, index).collect::<Vec<_>>().into_iter(),
            StdDescr::ShWpkh(d) => d.derive(keychain, index).collect::<Vec<_>>().into_iter(),
            StdDescr::ShWsh(d) => d.derive(keychain, index).collect::<Vec<_>>().into_iter(),
            StdDescr::Wpkh(d) => d.derive(keychain, index).collect::<Vec<_>>().into_iter(),
            StdDescr::Wsh(d) => d.derive(keychain, index).collect::<Vec<_>>().into_iter(),
            StdDescr::WshMulti(d) => d.derive(keychain, index).collect::<Vec<_>>().into_iter(),
            StdDescr::WshSortedMulti(d) => {
                d.derive(keychain, index).collect::<Vec<_>>().into_iter()
            }
            StdDescr::TrKey(d) => d.derive(keychain, index).collect::<Vec<_>>().into_iter(),
            StdDescr::TrMulti(d) => d.derive(keychain, index).collect::<Vec<_>>().into_iter(),
            StdDescr::TrSortedMulti(d) => d.derive(keychain, index).collect::<Vec<_>>().into_iter(),
            StdDescr::TrTree(d) => d.derive(keychain, index).collect::<Vec<_>>().into_iter(),
        }
    }
}

impl<K: DeriveSet<Legacy = K, Compr = K, XOnly = K> + DeriveLegacy + DeriveCompr + DeriveXOnly>
    Descriptor<K> for StdDescr<K>
where Self: Derive<DerivedScript>
{
    fn class(&self) -> SpkClass {
        match self {
            StdDescr::Raw(d) => d.class(),
            StdDescr::Pkh(d) => d.class(),
            StdDescr::Sh(d) => d.class(),
            StdDescr::ShMulti(d) => d.class(),
            StdDescr::ShSortedMulti(d) => d.class(),
            StdDescr::ShWpkh(d) => d.class(),
            StdDescr::ShWsh(d) => d.class(),
            StdDescr::Wpkh(d) => d.class(),
            StdDescr::Wsh(d) => d.class(),
            StdDescr::WshMulti(d) => d.class(),
            StdDescr::WshSortedMulti(d) => d.class(),
            StdDescr::TrKey(d) => d.class(),
            StdDescr::TrMulti(d) => d.class(),
            StdDescr::TrSortedMulti(d) => d.class(),
            StdDescr::TrTree(d) => d.class(),
        }
    }

    fn keys<'a>(&'a self) -> impl Iterator<Item = &'a K>
    where K: 'a {
        match self {
            StdDescr::Raw(d) => d.keys().collect::<Vec<_>>(),
            StdDescr::Pkh(d) => d.keys().collect::<Vec<_>>(),
            StdDescr::Sh(d) => d.keys().collect::<Vec<_>>(),
            StdDescr::ShMulti(d) => d.keys().collect::<Vec<_>>(),
            StdDescr::ShSortedMulti(d) => d.keys().collect::<Vec<_>>(),
            StdDescr::ShWpkh(d) => d.keys().collect::<Vec<_>>(),
            StdDescr::ShWsh(d) => d.keys().collect::<Vec<_>>(),
            StdDescr::Wpkh(d) => d.keys().collect::<Vec<_>>(),
            StdDescr::Wsh(d) => d.keys().collect::<Vec<_>>(),
            StdDescr::WshMulti(d) => d.keys().collect::<Vec<_>>(),
            StdDescr::WshSortedMulti(d) => d.keys().collect::<Vec<_>>(),
            StdDescr::TrKey(d) => d.keys().collect::<Vec<_>>(),
            StdDescr::TrMulti(d) => d.keys().collect::<Vec<_>>(),
            StdDescr::TrSortedMulti(d) => d.keys().collect::<Vec<_>>(),
            StdDescr::TrTree(d) => d.keys().collect::<Vec<_>>(),
        }
        .into_iter()
    }

    fn vars<'a>(&'a self) -> impl Iterator<Item = &'a ()>
    where (): 'a {
        iter::empty()
    }

    fn xpubs(&self) -> impl Iterator<Item = &XpubAccount> {
        match self {
            StdDescr::Raw(d) => d.xpubs().collect::<Vec<_>>(),
            StdDescr::Pkh(d) => d.xpubs().collect::<Vec<_>>(),
            StdDescr::Sh(d) => d.xpubs().collect::<Vec<_>>(),
            StdDescr::ShMulti(d) => d.xpubs().collect::<Vec<_>>(),
            StdDescr::ShSortedMulti(d) => d.xpubs().collect::<Vec<_>>(),
            StdDescr::ShWpkh(d) => d.xpubs().collect::<Vec<_>>(),
            StdDescr::ShWsh(d) => d.xpubs().collect::<Vec<_>>(),
            StdDescr::Wpkh(d) => d.xpubs().collect::<Vec<_>>(),
            StdDescr::Wsh(d) => d.xpubs().collect::<Vec<_>>(),
            StdDescr::WshMulti(d) => d.xpubs().collect::<Vec<_>>(),
            StdDescr::WshSortedMulti(d) => d.xpubs().collect::<Vec<_>>(),
            StdDescr::TrKey(d) => d.xpubs().collect::<Vec<_>>(),
            StdDescr::TrMulti(d) => d.xpubs().collect::<Vec<_>>(),
            StdDescr::TrSortedMulti(d) => d.xpubs().collect::<Vec<_>>(),
            StdDescr::TrTree(d) => d.xpubs().collect::<Vec<_>>(),
        }
        .into_iter()
    }

    fn legacy_keyset(&self, terminal: Terminal) -> IndexMap<LegacyPk, KeyOrigin> {
        match self {
            StdDescr::Raw(d) => d.legacy_keyset(terminal),
            StdDescr::Pkh(d) => d.legacy_keyset(terminal),
            StdDescr::Sh(d) => d.legacy_keyset(terminal),
            StdDescr::ShMulti(d) => d.legacy_keyset(terminal),
            StdDescr::ShSortedMulti(d) => d.legacy_keyset(terminal),
            StdDescr::ShWpkh(d) => d.legacy_keyset(terminal),
            StdDescr::ShWsh(d) => d.legacy_keyset(terminal),
            StdDescr::Wpkh(d) => d.legacy_keyset(terminal),
            StdDescr::Wsh(d) => d.legacy_keyset(terminal),
            StdDescr::WshMulti(d) => d.legacy_keyset(terminal),
            StdDescr::WshSortedMulti(d) => d.legacy_keyset(terminal),
            StdDescr::TrKey(d) => d.legacy_keyset(terminal),
            StdDescr::TrMulti(d) => d.legacy_keyset(terminal),
            StdDescr::TrSortedMulti(d) => d.legacy_keyset(terminal),
            StdDescr::TrTree(d) => d.legacy_keyset(terminal),
        }
    }

    fn xonly_keyset(&self, terminal: Terminal) -> IndexMap<XOnlyPk, TapDerivation> {
        match self {
            StdDescr::Raw(d) => d.xonly_keyset(terminal),
            StdDescr::Pkh(d) => d.xonly_keyset(terminal),
            StdDescr::Sh(d) => d.xonly_keyset(terminal),
            StdDescr::ShMulti(d) => d.xonly_keyset(terminal),
            StdDescr::ShSortedMulti(d) => d.xonly_keyset(terminal),
            StdDescr::ShWpkh(d) => d.xonly_keyset(terminal),
            StdDescr::ShWsh(d) => d.xonly_keyset(terminal),
            StdDescr::Wpkh(d) => d.xonly_keyset(terminal),
            StdDescr::Wsh(d) => d.xonly_keyset(terminal),
            StdDescr::WshMulti(d) => d.xonly_keyset(terminal),
            StdDescr::WshSortedMulti(d) => d.xonly_keyset(terminal),
            StdDescr::TrKey(d) => d.xonly_keyset(terminal),
            StdDescr::TrMulti(d) => d.xonly_keyset(terminal),
            StdDescr::TrSortedMulti(d) => d.xonly_keyset(terminal),
            StdDescr::TrTree(d) => d.xonly_keyset(terminal),
        }
    }

    fn legacy_witness(
        &self,
        keysigs: HashMap<&KeyOrigin, LegacyKeySig>,
        redeem_script: Option<RedeemScript>,
        witness_script: Option<WitnessScript>,
    ) -> Option<(SigScript, Option<Witness>)> {
        match self {
            StdDescr::Raw(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
            StdDescr::Pkh(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
            StdDescr::Sh(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
            StdDescr::ShMulti(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
            StdDescr::ShSortedMulti(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
            StdDescr::ShWpkh(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
            StdDescr::ShWsh(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
            StdDescr::Wpkh(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
            StdDescr::Wsh(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
            StdDescr::WshMulti(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
            StdDescr::WshSortedMulti(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
            StdDescr::TrKey(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
            StdDescr::TrMulti(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
            StdDescr::TrSortedMulti(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
            StdDescr::TrTree(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
        }
    }

    fn taproot_witness(
        &self,
        cb: Option<&ControlBlock>,
        keysigs: HashMap<&KeyOrigin, TaprootKeySig>,
    ) -> Option<Witness> {
        match self {
            StdDescr::Raw(d) => d.taproot_witness(cb, keysigs),
            StdDescr::Pkh(d) => d.taproot_witness(cb, keysigs),
            StdDescr::Sh(d) => d.taproot_witness(cb, keysigs),
            StdDescr::ShMulti(d) => d.taproot_witness(cb, keysigs),
            StdDescr::ShSortedMulti(d) => d.taproot_witness(cb, keysigs),
            StdDescr::ShWpkh(d) => d.taproot_witness(cb, keysigs),
            StdDescr::ShWsh(d) => d.taproot_witness(cb, keysigs),
            StdDescr::Wpkh(d) => d.taproot_witness(cb, keysigs),
            StdDescr::Wsh(d) => d.taproot_witness(cb, keysigs),
            StdDescr::WshMulti(d) => d.taproot_witness(cb, keysigs),
            StdDescr::WshSortedMulti(d) => d.taproot_witness(cb, keysigs),
            StdDescr::TrKey(d) => d.taproot_witness(cb, keysigs),
            StdDescr::TrMulti(d) => d.taproot_witness(cb, keysigs),
            StdDescr::TrSortedMulti(d) => d.taproot_witness(cb, keysigs),
            StdDescr::TrTree(d) => d.taproot_witness(cb, keysigs),
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
            StdDescr::Raw(d) => Display::fmt(d, f),
            StdDescr::Pkh(d) => Display::fmt(d, f),
            StdDescr::Sh(d) => Display::fmt(d, f),
            StdDescr::ShMulti(d) => Display::fmt(d, f),
            StdDescr::ShSortedMulti(d) => Display::fmt(d, f),
            StdDescr::ShWpkh(d) => Display::fmt(d, f),
            StdDescr::ShWsh(d) => Display::fmt(d, f),
            StdDescr::Wpkh(d) => Display::fmt(d, f),
            StdDescr::Wsh(d) => Display::fmt(d, f),
            StdDescr::WshMulti(d) => Display::fmt(d, f),
            StdDescr::WshSortedMulti(d) => Display::fmt(d, f),
            StdDescr::TrKey(d) => Display::fmt(d, f),
            StdDescr::TrMulti(d) => Display::fmt(d, f),
            StdDescr::TrSortedMulti(d) => Display::fmt(d, f),
            StdDescr::TrTree(d) => Display::fmt(d, f),
        }
    }
}
