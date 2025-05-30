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
use std::{fmt, iter, vec};

use amplify::confinement::Confined;
use amplify::num::u4;
use derive::{
    CompressedPk, Derive, DeriveCompr, DeriveKey, DeriveLegacy, DerivedScript, KeyOrigin, Keychain,
    LegacyPk, NormalIndex, OpCode, RedeemScript, SigScript, TapDerivation, Terminal, Witness,
    WitnessScript, XOnlyPk, XkeyOrigin, XpubAccount, XpubDerivable,
};
use indexmap::IndexMap;

use crate::{Descriptor, LegacyKeySig, SpkClass, TaprootKeySig};

/// Representation of BIP-383 `multi` as it is used inside `sh`.
///
/// # Nota bene
///
/// The structure does not support 16-of-16 multisig (only 15-of-16 is possible).
/// The cost of the support will increase code multifold, so we just ignore this rare case.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ShMulti<K: DeriveLegacy = XpubDerivable> {
    pub threshold: u4,
    // TODO: Switch to an IndexSet when supported by amplify
    pub keys: Confined<Vec<K>, 1, 16>,
}

impl<K: DeriveLegacy> ShMulti<K> {
    pub fn key_count(&self) -> u8 { self.keys.len() as u8 }
    pub fn threshold(&self) -> u8 { self.threshold.into_u8() }
}

impl<K: DeriveLegacy> Derive<DerivedScript> for ShMulti<K> {
    #[inline]
    fn default_keychain(&self) -> Keychain { self.keys[0].default_keychain() }

    #[inline]
    fn keychains(&self) -> BTreeSet<Keychain> { self.keys[0].keychains() }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = DerivedScript> {
        let keychain = keychain.into();
        let index = index.into();
        let derived_set = derive(&self.keys, keychain, index).collect::<Vec<_>>();
        redeem_script(self.threshold, derived_set)
    }
}

impl<K: DeriveLegacy> Descriptor<K> for ShMulti<K>
where Self: Derive<DerivedScript>
{
    fn class(&self) -> SpkClass { SpkClass::P2sh }

    fn keys<'a>(&'a self) -> impl Iterator<Item = &'a K>
    where K: 'a {
        self.keys.iter()
    }
    fn vars<'a>(&'a self) -> impl Iterator<Item = &'a ()>
    where (): 'a {
        iter::empty()
    }
    fn xpubs(&self) -> impl Iterator<Item = &XpubAccount> { self.keys().map(|key| key.xpub_spec()) }

    fn legacy_keyset(&self, terminal: Terminal) -> IndexMap<LegacyPk, KeyOrigin> {
        legacy_keyset(&self.keys, terminal)
    }

    fn xonly_keyset(&self, _terminal: Terminal) -> IndexMap<XOnlyPk, TapDerivation> {
        IndexMap::new()
    }

    fn legacy_witness(
        &self,
        keysigs: HashMap<&KeyOrigin, LegacyKeySig>,
    ) -> Option<(SigScript, Witness)> {
        witness(&self.keys, keysigs)
    }

    fn taproot_witness(&self, _keysigs: HashMap<&KeyOrigin, TaprootKeySig>) -> Option<Witness> {
        None
    }
}

impl<S: DeriveLegacy> Display for ShMulti<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("sh(")?;
        fmt(self.threshold, self.keys(), f)?;
        f.write_str(")")
    }
}

/// Representation of BIP-383 `sortedmulti` as it is used inside `sh`.
///
/// # Nota bene
///
/// The structure does not support 16-of-16 multisig (only 15-of-16 is possible).
/// The cost of the support will increase code multifold, so we just ignore this rare case.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ShSortedMulti<K: DeriveLegacy = XpubDerivable> {
    pub threshold: u4,
    // TODO: Switch to an IndexSet when supported by amplify
    pub keys: Confined<Vec<K>, 1, 16>,
}

impl<K: DeriveLegacy> ShSortedMulti<K> {
    pub fn key_count(&self) -> u8 { self.keys.len() as u8 }
    pub fn threshold(&self) -> u8 { self.threshold.into_u8() }
}

impl<K: DeriveLegacy> Derive<DerivedScript> for ShSortedMulti<K> {
    #[inline]
    fn default_keychain(&self) -> Keychain { self.keys[0].default_keychain() }

    #[inline]
    fn keychains(&self) -> BTreeSet<Keychain> { self.keys[0].keychains() }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = DerivedScript> {
        let keychain = keychain.into();
        let index = index.into();
        // Use of BTreeSet performs key sorting
        let derived_set = derive(&self.keys, keychain, index).collect::<BTreeSet<_>>();
        redeem_script(self.threshold, derived_set)
    }
}

impl<K: DeriveLegacy> Descriptor<K> for ShSortedMulti<K>
where Self: Derive<DerivedScript>
{
    fn class(&self) -> SpkClass { SpkClass::P2sh }

    fn keys<'a>(&'a self) -> impl Iterator<Item = &'a K>
    where K: 'a {
        self.keys.iter()
    }
    fn vars<'a>(&'a self) -> impl Iterator<Item = &'a ()>
    where (): 'a {
        iter::empty()
    }
    fn xpubs(&self) -> impl Iterator<Item = &XpubAccount> { self.keys().map(|key| key.xpub_spec()) }

    fn legacy_keyset(&self, terminal: Terminal) -> IndexMap<LegacyPk, KeyOrigin> {
        legacy_keyset(&self.keys, terminal)
    }

    fn xonly_keyset(&self, _terminal: Terminal) -> IndexMap<XOnlyPk, TapDerivation> {
        IndexMap::new()
    }

    fn legacy_witness(
        &self,
        keysigs: HashMap<&KeyOrigin, LegacyKeySig>,
    ) -> Option<(SigScript, Witness)> {
        witness(&self.keys, keysigs)
    }

    fn taproot_witness(&self, _keysigs: HashMap<&KeyOrigin, TaprootKeySig>) -> Option<Witness> {
        None
    }
}

impl<S: DeriveLegacy> Display for ShSortedMulti<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("sh(sorted")?;
        fmt(self.threshold, self.keys(), f)?;
        f.write_str(")")
    }
}

/// Representation of BIP-383 `multi` as it is used inside `wsh`.
///
/// # Nota bene
///
/// The structure does not support 16-of-16 multisig (only 15-of-16 is possible).
/// The cost of the support will increase code multifold, so we just ignore this rare case.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WshMulti<K: DeriveCompr = XpubDerivable> {
    pub threshold: u4,
    // TODO: Switch to an IndexSet when supported by amplify
    pub keys: Confined<Vec<K>, 1, 16>,
}

impl<K: DeriveCompr> WshMulti<K> {
    pub fn key_count(&self) -> u8 { self.keys.len() as u8 }
    pub fn threshold(&self) -> u8 { self.threshold.into_u8() }
}

impl<K: DeriveCompr> Derive<DerivedScript> for WshMulti<K> {
    #[inline]
    fn default_keychain(&self) -> Keychain { self.keys[0].default_keychain() }

    #[inline]
    fn keychains(&self) -> BTreeSet<Keychain> { self.keys[0].keychains() }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = DerivedScript> {
        let keychain = keychain.into();
        let index = index.into();
        let derived_set = derive(&self.keys, keychain, index).collect::<Vec<_>>();
        witness_script(self.threshold, derived_set)
    }
}

impl<K: DeriveCompr> Descriptor<K> for WshMulti<K>
where Self: Derive<DerivedScript>
{
    fn class(&self) -> SpkClass { SpkClass::P2wsh }

    fn keys<'a>(&'a self) -> impl Iterator<Item = &'a K>
    where K: 'a {
        self.keys.iter()
    }
    fn vars<'a>(&'a self) -> impl Iterator<Item = &'a ()>
    where (): 'a {
        iter::empty()
    }
    fn xpubs(&self) -> impl Iterator<Item = &XpubAccount> { self.keys().map(|key| key.xpub_spec()) }

    fn legacy_keyset(&self, terminal: Terminal) -> IndexMap<LegacyPk, KeyOrigin> {
        legacy_keyset(self.keys(), terminal)
    }

    fn xonly_keyset(&self, _terminal: Terminal) -> IndexMap<XOnlyPk, TapDerivation> {
        IndexMap::new()
    }

    fn legacy_witness(
        &self,
        keysigs: HashMap<&KeyOrigin, LegacyKeySig>,
    ) -> Option<(SigScript, Witness)> {
        witness(self.keys(), keysigs)
    }

    fn taproot_witness(&self, _keysigs: HashMap<&KeyOrigin, TaprootKeySig>) -> Option<Witness> {
        None
    }
}

impl<S: DeriveCompr> Display for WshMulti<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("wsh(sorted")?;
        fmt(self.threshold, self.keys(), f)?;
        f.write_str(")")
    }
}

/// Representation of BIP-383 `sortedmulti` as it is used inside `wsh`.
///
/// # Nota bene
///
/// The structure does not support 16-of-16 multisig (only 15-of-16 is possible).
/// The cost of the support will increase code multifold, so we just ignore this rare case.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WshSortedMulti<K: DeriveCompr = XpubDerivable> {
    pub threshold: u4,
    // TODO: Switch to an IndexSet when supported by amplify
    pub keys: Confined<Vec<K>, 1, 16>,
}

impl<K: DeriveCompr> WshSortedMulti<K> {
    pub fn key_count(&self) -> u8 { self.keys.len() as u8 }
    pub fn threshold(&self) -> u8 { self.threshold.into_u8() }
}

impl<K: DeriveCompr> Derive<DerivedScript> for WshSortedMulti<K> {
    #[inline]
    fn default_keychain(&self) -> Keychain { self.keys[0].default_keychain() }

    #[inline]
    fn keychains(&self) -> BTreeSet<Keychain> { self.keys[0].keychains() }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = DerivedScript> {
        let keychain = keychain.into();
        let index = index.into();
        // Use of BTreeSet performs key sorting
        let derived_set = derive(&self.keys, keychain, index).collect::<BTreeSet<_>>();
        witness_script(self.threshold, derived_set)
    }
}

impl<K: DeriveCompr> Descriptor<K> for WshSortedMulti<K>
where Self: Derive<DerivedScript>
{
    fn class(&self) -> SpkClass { SpkClass::P2wsh }

    fn keys<'a>(&'a self) -> impl Iterator<Item = &'a K>
    where K: 'a {
        self.keys.iter()
    }
    fn vars<'a>(&'a self) -> impl Iterator<Item = &'a ()>
    where (): 'a {
        iter::empty()
    }
    fn xpubs(&self) -> impl Iterator<Item = &XpubAccount> { self.keys().map(|key| key.xpub_spec()) }

    fn legacy_keyset(&self, terminal: Terminal) -> IndexMap<LegacyPk, KeyOrigin> {
        legacy_keyset(self.keys(), terminal)
    }

    fn xonly_keyset(&self, _terminal: Terminal) -> IndexMap<XOnlyPk, TapDerivation> {
        IndexMap::new()
    }

    fn legacy_witness(
        &self,
        keysigs: HashMap<&KeyOrigin, LegacyKeySig>,
    ) -> Option<(SigScript, Witness)> {
        witness(self.keys(), keysigs)
    }

    fn taproot_witness(&self, _keysigs: HashMap<&KeyOrigin, TaprootKeySig>) -> Option<Witness> {
        None
    }
}

impl<S: DeriveCompr> Display for WshSortedMulti<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("wsh(sorted")?;
        fmt(self.threshold, self.keys(), f)?;
        f.write_str(")")
    }
}

// ------------------------------------------------------------------------------------------------

/// Check that all sigs match our keys
fn check_sigs<'a>(
    accounts: impl Iterator<Item = &'a XpubAccount>,
    keysigs: &HashMap<&'a KeyOrigin, LegacyKeySig>,
) -> bool {
    let set = accounts.map(XpubAccount::origin).map(XkeyOrigin::master_fp).collect::<BTreeSet<_>>();
    keysigs.keys().all(|origin| set.contains(&origin.master_fp()))
}

fn derive<'k, T, K: Derive<T> + 'k, I: IntoIterator<Item = &'k K>>(
    keys: I,
    keychain: Keychain,
    index: NormalIndex,
) -> impl Iterator<Item = T> + use<'k, T, K, I> {
    keys.into_iter()
        .map(move |xkey| xkey.derive(keychain, index).next().expect("no derivation found"))
}

fn redeem_script<I: IntoIterator<Item = LegacyPk>>(
    threshold: u4,
    keys: I,
) -> impl Iterator<Item = DerivedScript>
where
    I::IntoIter: ExactSizeIterator,
{
    let keys = keys.into_iter();
    let key_count = keys.len();

    let mut redeem_script = RedeemScript::with_capacity(key_count * 34 + 4);
    redeem_script.push_num(threshold.into_u8());
    for key in keys {
        redeem_script.push_slice(&key.serialize());
    }
    redeem_script.push_num(key_count as u8);
    redeem_script.push_opcode(OpCode::CheckMultiSig);

    iter::once(DerivedScript::Bip13(redeem_script))
}

fn witness_script<I: IntoIterator<Item = CompressedPk>>(
    threshold: u4,
    keys: I,
) -> impl Iterator<Item = DerivedScript>
where
    I::IntoIter: ExactSizeIterator,
{
    let keys = keys.into_iter();
    let key_count = keys.len();

    let mut witness_script = WitnessScript::with_capacity(key_count * 34 + 4);
    witness_script.push_num(threshold.into_u8());
    for key in keys {
        witness_script.push_slice(&key.serialize());
    }
    witness_script.push_num(key_count as u8);
    witness_script.push_opcode(OpCode::CheckMultiSig);

    iter::once(DerivedScript::Segwit(witness_script))
}

fn legacy_keyset<'k, T: Into<LegacyPk>, K: DeriveKey<T> + 'k, I: IntoIterator<Item = &'k K>>(
    keys: I,
    terminal: Terminal,
) -> IndexMap<LegacyPk, KeyOrigin> {
    keys.into_iter()
        .map(|xkey| {
            let key = xkey
                .derive(terminal.keychain, terminal.index)
                .next()
                .expect("multisig must derive one key per path");
            (key.into(), KeyOrigin::with(xkey.xpub_spec().origin().clone(), terminal))
        })
        .collect()
}

fn witness<'k, T, K: DeriveKey<T> + 'k, I: IntoIterator<Item = &'k K>>(
    keys: I,
    keysigs: HashMap<&'k KeyOrigin, LegacyKeySig>,
) -> Option<(SigScript, Witness)> {
    // Check that all sigs match our keys
    if !check_sigs(keys.into_iter().map(K::xpub_spec), &keysigs) {
        return None;
    }

    let mut stack = Vec::with_capacity(keysigs.len() + 1);
    for sig in keysigs.values() {
        stack.push(sig.sig.to_vec());
    }
    stack.push(vec![]);
    let witness = Witness::from_consensus_stack(stack);
    Some((empty!(), witness))
}

fn fmt<'k, K: Display + 'k>(
    threshold: u4,
    keys: impl IntoIterator<Item = &'k K>,
    f: &mut Formatter<'_>,
) -> fmt::Result {
    write!(f, "multi({}", threshold)?;
    for key in keys {
        write!(f, ",{key}")?;
    }
    f.write_str(")")
}
