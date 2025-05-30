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
use std::hash::Hash;
use std::iter;

use derive::{
    Derive, DeriveCompr, DerivedScript, KeyOrigin, Keychain, LegacyPk, NormalIndex, RedeemScript,
    ScriptPubkey, SigScript, TapDerivation, Terminal, WPubkeyHash, Witness, WitnessScript, XOnlyPk,
    XpubAccount, XpubDerivable,
};
use indexmap::IndexMap;

use crate::{Descriptor, LegacyKeySig, SpkClass, TaprootKeySig};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Eq, PartialEq, Hash, Debug, From)]
pub struct Wpkh<K: DeriveCompr = XpubDerivable>(K);

impl<K: DeriveCompr> Wpkh<K> {
    pub fn as_key(&self) -> &K { &self.0 }
    pub fn into_key(self) -> K { self.0 }
}

impl<K: DeriveCompr> Derive<DerivedScript> for Wpkh<K> {
    #[inline]
    fn default_keychain(&self) -> Keychain { self.0.default_keychain() }

    #[inline]
    fn keychains(&self) -> BTreeSet<Keychain> { self.0.keychains() }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = DerivedScript> {
        self.0
            .derive(keychain, index)
            .map(|key| DerivedScript::Bare(ScriptPubkey::p2wpkh(WPubkeyHash::from(key))))
    }
}

impl<K: DeriveCompr> Descriptor<K> for Wpkh<K> {
    fn class(&self) -> SpkClass { SpkClass::P2wpkh }

    fn keys<'a>(&'a self) -> impl Iterator<Item = &'a K>
    where K: 'a {
        iter::once(&self.0)
    }
    fn vars<'a>(&'a self) -> impl Iterator<Item = &'a ()>
    where (): 'a {
        iter::empty()
    }
    fn xpubs(&self) -> impl Iterator<Item = &XpubAccount> { iter::once(self.0.xpub_spec()) }

    fn legacy_keyset(&self, terminal: Terminal) -> IndexMap<LegacyPk, KeyOrigin> {
        self.0
            .derive(terminal.keychain, terminal.index)
            .map(|key| (key.into(), KeyOrigin::with(self.0.xpub_spec().origin().clone(), terminal)))
            .collect()
    }

    fn xonly_keyset(&self, _terminal: Terminal) -> IndexMap<XOnlyPk, TapDerivation> {
        IndexMap::new()
    }

    fn legacy_witness(
        &self,
        keysigs: HashMap<&KeyOrigin, LegacyKeySig>,
        _redeem_script: Option<RedeemScript>,
        _witness_script: Option<WitnessScript>,
    ) -> Option<(SigScript, Option<Witness>)> {
        let our_origin = self.0.xpub_spec().origin();
        let keysig =
            keysigs.iter().find(|(origin, _)| our_origin.is_subset_of(origin)).map(|(_, ks)| ks)?;
        let witness = Witness::from_consensus_stack([keysig.sig.to_vec(), keysig.key.to_vec()]);
        Some((empty!(), Some(witness)))
    }

    fn taproot_witness(&self, _keysigs: HashMap<&KeyOrigin, TaprootKeySig>) -> Option<Witness> {
        None
    }
}

impl<K: DeriveCompr> Display for Wpkh<K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { write!(f, "wpkh({})", self.0) }
}
