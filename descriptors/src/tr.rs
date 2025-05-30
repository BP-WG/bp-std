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
use std::fmt::{self, Display, Formatter};
use std::iter;

use derive::{
    Derive, DeriveXOnly, DerivedScript, InternalPk, KeyOrigin, Keychain, LegacyPk, NormalIndex,
    RedeemScript, SigScript, TapDerivation, Terminal, Witness, WitnessScript, XOnlyPk, XpubAccount,
    XpubDerivable,
};
use indexmap::IndexMap;

use crate::{Descriptor, LegacyKeySig, SpkClass, TaprootKeySig};

#[derive(Clone, Eq, PartialEq, Hash, Debug, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(untagged))]
pub enum Tr<K: DeriveXOnly = XpubDerivable> {
    KeyOnly(TrKey<K>),
}

impl<K: DeriveXOnly> Tr<K> {
    pub fn as_internal_key(&self) -> &K {
        match self {
            Tr::KeyOnly(d) => d.as_internal_key(),
        }
    }
    pub fn into_internal_key(self) -> K {
        match self {
            Tr::KeyOnly(d) => d.into_internal_key(),
        }
    }
}

impl<K: DeriveXOnly> Derive<DerivedScript> for Tr<K> {
    fn default_keychain(&self) -> Keychain {
        match self {
            Tr::KeyOnly(d) => d.default_keychain(),
        }
    }

    fn keychains(&self) -> BTreeSet<Keychain> {
        match self {
            Tr::KeyOnly(d) => d.keychains(),
        }
    }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = DerivedScript> {
        match self {
            Tr::KeyOnly(d) => d.derive(keychain, index),
        }
    }
}

impl<K: DeriveXOnly> Descriptor<K> for Tr<K> {
    fn class(&self) -> SpkClass {
        match self {
            Tr::KeyOnly(d) => d.class(),
        }
    }

    fn keys<'a>(&'a self) -> impl Iterator<Item = &'a K>
    where K: 'a {
        match self {
            Tr::KeyOnly(d) => d.keys(),
        }
    }

    fn vars<'a>(&'a self) -> impl Iterator<Item = &'a ()>
    where (): 'a {
        match self {
            Tr::KeyOnly(d) => d.vars(),
        }
    }

    fn xpubs(&self) -> impl Iterator<Item = &XpubAccount> {
        match self {
            Tr::KeyOnly(d) => d.xpubs(),
        }
    }

    fn legacy_keyset(&self, terminal: Terminal) -> IndexMap<LegacyPk, KeyOrigin> {
        match self {
            Tr::KeyOnly(d) => d.legacy_keyset(terminal),
        }
    }

    fn xonly_keyset(&self, terminal: Terminal) -> IndexMap<XOnlyPk, TapDerivation> {
        match self {
            Tr::KeyOnly(d) => d.xonly_keyset(terminal),
        }
    }

    fn legacy_witness(
        &self,
        keysigs: HashMap<&KeyOrigin, LegacyKeySig>,
        redeem_script: Option<RedeemScript>,
        witness_script: Option<WitnessScript>,
    ) -> Option<(SigScript, Option<Witness>)> {
        match self {
            Tr::KeyOnly(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
        }
    }

    fn taproot_witness(&self, keysigs: HashMap<&KeyOrigin, TaprootKeySig>) -> Option<Witness> {
        match self {
            Tr::KeyOnly(d) => d.taproot_witness(keysigs),
        }
    }
}

impl<K: DeriveXOnly> Display for Tr<K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Tr::KeyOnly(d) => Display::fmt(d, f),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TrKey<K: DeriveXOnly = XpubDerivable>(K);

impl<K: DeriveXOnly> TrKey<K> {
    pub fn as_internal_key(&self) -> &K { &self.0 }
    pub fn into_internal_key(self) -> K { self.0 }
}

impl<K: DeriveXOnly> Derive<DerivedScript> for TrKey<K> {
    #[inline]
    fn default_keychain(&self) -> Keychain { self.0.default_keychain() }

    #[inline]
    fn keychains(&self) -> BTreeSet<Keychain> { self.0.keychains() }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = DerivedScript> {
        self.0.derive(keychain, index).map(|internal_key| {
            DerivedScript::TaprootKeyOnly(InternalPk::from_unchecked(internal_key))
        })
    }
}

impl<K: DeriveXOnly> Descriptor<K> for TrKey<K> {
    fn class(&self) -> SpkClass { SpkClass::P2tr }

    fn keys<'a>(&'a self) -> impl Iterator<Item = &'a K>
    where K: 'a {
        iter::once(&self.0)
    }
    fn vars<'a>(&'a self) -> impl Iterator<Item = &'a ()>
    where (): 'a {
        iter::empty()
    }
    fn xpubs(&self) -> impl Iterator<Item = &XpubAccount> { iter::once(self.0.xpub_spec()) }

    fn legacy_keyset(&self, _terminal: Terminal) -> IndexMap<LegacyPk, KeyOrigin> {
        IndexMap::new()
    }

    fn xonly_keyset(&self, terminal: Terminal) -> IndexMap<XOnlyPk, TapDerivation> {
        self.0
            .derive(terminal.keychain, terminal.index)
            .map(|key| {
                (
                    key,
                    TapDerivation::with_internal_pk(self.0.xpub_spec().origin().clone(), terminal),
                )
            })
            .collect()
    }

    fn legacy_witness(
        &self,
        _keysigs: HashMap<&KeyOrigin, LegacyKeySig>,
        _redeem_script: Option<RedeemScript>,
        _witness_script: Option<WitnessScript>,
    ) -> Option<(SigScript, Option<Witness>)> {
        None
    }

    fn taproot_witness(&self, keysigs: HashMap<&KeyOrigin, TaprootKeySig>) -> Option<Witness> {
        let our_origin = self.0.xpub_spec().origin();
        let keysig =
            keysigs.iter().find(|(origin, _)| our_origin.is_subset_of(origin)).map(|(_, ks)| ks)?;
        Some(Witness::from_consensus_stack([keysig.sig.to_vec()]))
    }
}

impl<K: DeriveXOnly> Display for TrKey<K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { write!(f, "tr({})", self.0) }
}

/*
pub struct TrScript<K: DeriveXOnly> {
    internal_key: K,
    tap_tree: TapTree<Policy<K>>,
}
*/
