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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use std::{fmt, iter, vec};

use amplify::confinement::ConfinedVec;
use amplify::num::u4;
use amplify::Wrapper;
use derive::{
    CompressedPk, ControlBlock, Derive, DeriveCompr, DeriveKey, DeriveLegacy, DerivedScript,
    KeyOrigin, Keychain, LegacyPk, NormalIndex, OpCode, RedeemScript, SigScript, TapDerivation,
    Terminal, Witness, WitnessScript, XOnlyPk, XpubAccount, XpubDerivable,
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
    pub keys: ConfinedVec<K, 1, 16>,
}

impl<K: DeriveLegacy> ShMulti<K> {
    pub fn new_checked(threshold: u8, keys: impl IntoIterator<Item = K>) -> Self {
        Self {
            threshold: u4::with(threshold),
            keys: ConfinedVec::from_iter_checked(keys),
        }
    }
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
        let redeem_script = redeem_script(self.threshold, derived_set);
        iter::once(DerivedScript::Bip13(redeem_script))
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
        legacy_keyset(&self.keys, terminal).collect()
    }

    fn xonly_keyset(&self, _terminal: Terminal) -> IndexMap<XOnlyPk, TapDerivation> {
        IndexMap::new()
    }

    fn legacy_witness(
        &self,
        mut keysigs: IndexMap<&KeyOrigin, LegacyKeySig>,
        redeem_script: Option<RedeemScript>,
        witness_script: Option<WitnessScript>,
    ) -> Option<(SigScript, Option<Witness>)> {
        if witness_script.is_some() {
            return None;
        }
        // Check that all sigs match our keys
        if !check_sigs(self.keys().map(K::xpub_spec), &keysigs) {
            return None;
        }

        // We need to put the sigs into the order that matches the ordering of the keys
        let keysigs = self.keys().filter_map(|key| {
            let xorigin = key.xpub_spec().origin();
            let index =
                keysigs.iter().position(|(origin, _)| &origin.to_account_origin() == xorigin)?;
            keysigs.shift_remove_index(index).map(|(_, keysig)| keysig)
        });

        Some(sig_script(keysigs, redeem_script?))
    }

    fn taproot_witness(
        &self,
        _cb: Option<&ControlBlock>,
        _keysigs: IndexMap<&KeyOrigin, TaprootKeySig>,
    ) -> Option<Witness> {
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
    pub keys: ConfinedVec<K, 1, 16>,
}

impl<K: DeriveLegacy> ShSortedMulti<K> {
    pub fn new_checked(threshold: u8, keys: impl IntoIterator<Item = K>) -> Self {
        Self {
            threshold: u4::with(threshold),
            keys: ConfinedVec::from_iter_checked(keys),
        }
    }
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
        let redeem_script = redeem_script(self.threshold, derived_set);
        iter::once(DerivedScript::Bip13(redeem_script))
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
        // BTreeMap here provides us with the key sorting
        legacy_keyset(&self.keys, terminal).collect::<BTreeMap<_, _>>().into_iter().collect()
    }

    fn xonly_keyset(&self, _terminal: Terminal) -> IndexMap<XOnlyPk, TapDerivation> {
        IndexMap::new()
    }

    fn legacy_witness(
        &self,
        keysigs: IndexMap<&KeyOrigin, LegacyKeySig>,
        redeem_script: Option<RedeemScript>,
        witness_script: Option<WitnessScript>,
    ) -> Option<(SigScript, Option<Witness>)> {
        if witness_script.is_some() {
            return None;
        }
        // Check that all sigs match our keys
        if !check_sigs(self.keys().map(K::xpub_spec), &keysigs) {
            return None;
        }
        // We need to put the sigs into the order that matches the ordering of the keys
        let sorted =
            keysigs.into_values().map(|keysig| (keysig.key, keysig)).collect::<BTreeMap<_, _>>();
        Some(sig_script(sorted.into_values(), redeem_script?))
    }

    fn taproot_witness(
        &self,
        _cb: Option<&ControlBlock>,
        _keysigs: IndexMap<&KeyOrigin, TaprootKeySig>,
    ) -> Option<Witness> {
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
    pub keys: ConfinedVec<K, 1, 16>,
}

impl<K: DeriveCompr> WshMulti<K> {
    pub fn new_checked(threshold: u8, keys: impl IntoIterator<Item = K>) -> Self {
        Self {
            threshold: u4::with(threshold),
            keys: ConfinedVec::from_iter_checked(keys),
        }
    }
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
        let witness_script =
            wsh_derive::<_, _, Vec<_>>(self.threshold, &self.keys, keychain, index);
        iter::once(DerivedScript::Segwit(witness_script))
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
        legacy_keyset(self.keys(), terminal).collect()
    }

    fn xonly_keyset(&self, _terminal: Terminal) -> IndexMap<XOnlyPk, TapDerivation> {
        IndexMap::new()
    }

    fn legacy_witness(
        &self,
        mut keysigs: IndexMap<&KeyOrigin, LegacyKeySig>,
        redeem_script: Option<RedeemScript>,
        witness_script: Option<WitnessScript>,
    ) -> Option<(SigScript, Option<Witness>)> {
        if redeem_script.is_some() {
            return None;
        }
        // Check that all sigs match our keys
        if !check_sigs(self.keys().map(K::xpub_spec), &keysigs) {
            return None;
        }
        // We need to put the sigs into the order that matches the ordering of the keys
        let keysigs = self.keys().filter_map(|key| {
            let xorigin = key.xpub_spec().origin();
            let index =
                keysigs.iter().position(|(origin, _)| &origin.to_account_origin() == xorigin)?;
            keysigs.shift_remove_index(index).map(|(_, keysig)| keysig)
        });
        Some(witness(keysigs, witness_script?))
    }

    fn taproot_witness(
        &self,
        _cb: Option<&ControlBlock>,
        _keysigs: IndexMap<&KeyOrigin, TaprootKeySig>,
    ) -> Option<Witness> {
        None
    }
}

impl<S: DeriveCompr> Display for WshMulti<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("wsh(")?;
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
    pub keys: ConfinedVec<K, 1, 16>,
}

impl<K: DeriveCompr> WshSortedMulti<K> {
    pub fn new_checked(threshold: u8, keys: impl IntoIterator<Item = K>) -> Self {
        Self {
            threshold: u4::with(threshold),
            keys: ConfinedVec::from_iter_checked(keys),
        }
    }
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
        let witness_script =
            wsh_derive::<_, _, BTreeSet<_>>(self.threshold, &self.keys, keychain, index);
        iter::once(DerivedScript::Segwit(witness_script))
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
        // BTreeMap here provides us with the key sorting
        legacy_keyset(&self.keys, terminal).collect::<BTreeMap<_, _>>().into_iter().collect()
    }

    fn xonly_keyset(&self, _terminal: Terminal) -> IndexMap<XOnlyPk, TapDerivation> {
        IndexMap::new()
    }

    fn legacy_witness(
        &self,
        keysigs: IndexMap<&KeyOrigin, LegacyKeySig>,
        redeem_script: Option<RedeemScript>,
        witness_script: Option<WitnessScript>,
    ) -> Option<(SigScript, Option<Witness>)> {
        if redeem_script.is_some() {
            return None;
        }
        // Check that all sigs match our keys
        if !check_sigs(self.keys().map(K::xpub_spec), &keysigs) {
            return None;
        }
        // We need to put the sigs into the order that matches the ordering of the keys
        let sorted =
            keysigs.into_values().map(|keysig| (keysig.key, keysig)).collect::<BTreeMap<_, _>>();
        Some(witness(sorted.into_values(), witness_script?))
    }

    fn taproot_witness(
        &self,
        _cb: Option<&ControlBlock>,
        _keysigs: IndexMap<&KeyOrigin, TaprootKeySig>,
    ) -> Option<Witness> {
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
/// Representation of BIP-383 `multi` as it is used inside `wsh` nested in `sh`.
///
/// # Nota bene
///
/// The structure does not support 16-of-16 multisig (only 15-of-16 is possible).
/// The cost of the support will increase code multifold, so we just ignore this rare case.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ShWshMulti<K: DeriveCompr = XpubDerivable> {
    pub threshold: u4,
    // TODO: Switch to an IndexSet when supported by amplify
    pub keys: ConfinedVec<K, 1, 16>,
}

impl<K: DeriveCompr> From<WshMulti<K>> for ShWshMulti<K> {
    fn from(d: WshMulti<K>) -> Self {
        Self {
            threshold: d.threshold,
            keys: d.keys,
        }
    }
}

impl<K: DeriveCompr> ShWshMulti<K> {
    pub fn new_checked(threshold: u8, keys: impl IntoIterator<Item = K>) -> Self {
        Self {
            threshold: u4::with(threshold),
            keys: ConfinedVec::from_iter_checked(keys),
        }
    }
    pub fn key_count(&self) -> u8 { self.keys.len() as u8 }
    pub fn threshold(&self) -> u8 { self.threshold.into_u8() }
    pub fn into_wsh(self) -> WshMulti<K> {
        WshMulti {
            threshold: self.threshold,
            keys: self.keys,
        }
    }
}

impl<K: DeriveCompr> Derive<DerivedScript> for ShWshMulti<K> {
    #[inline]
    fn default_keychain(&self) -> Keychain { self.keys[0].default_keychain() }

    #[inline]
    fn keychains(&self) -> BTreeSet<Keychain> { self.keys[0].keychains() }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = DerivedScript> {
        let witness_script =
            wsh_derive::<_, _, Vec<_>>(self.threshold, &self.keys, keychain, index);
        iter::once(DerivedScript::NestedScript(witness_script))
    }
}

impl<K: DeriveCompr> Descriptor<K> for ShWshMulti<K>
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
        legacy_keyset(self.keys(), terminal).collect()
    }

    fn xonly_keyset(&self, _terminal: Terminal) -> IndexMap<XOnlyPk, TapDerivation> {
        IndexMap::new()
    }

    fn legacy_witness(
        &self,
        mut keysigs: IndexMap<&KeyOrigin, LegacyKeySig>,
        redeem_script: Option<RedeemScript>,
        witness_script: Option<WitnessScript>,
    ) -> Option<(SigScript, Option<Witness>)> {
        redeem_script.as_ref()?;
        // Check that all sigs match our keys
        if !check_sigs(self.keys().map(K::xpub_spec), &keysigs) {
            return None;
        }
        // We need to put the sigs into the order that matches the ordering of the keys
        let keysigs = self.keys().filter_map(|key| {
            let xorigin = key.xpub_spec().origin();
            let index =
                keysigs.iter().position(|(origin, _)| &origin.to_account_origin() == xorigin)?;
            keysigs.shift_remove_index(index).map(|(_, keysig)| keysig)
        });

        let (_, witness) = witness(keysigs, witness_script?);
        let sig_script = SigScript::from_checked(redeem_script?.into_inner().into_vec());
        Some((sig_script, Some(witness?)))
    }

    fn taproot_witness(
        &self,
        _cb: Option<&ControlBlock>,
        _keysigs: IndexMap<&KeyOrigin, TaprootKeySig>,
    ) -> Option<Witness> {
        None
    }
}

impl<S: DeriveCompr> Display for ShWshMulti<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("sh(wsh(")?;
        fmt(self.threshold, self.keys(), f)?;
        f.write_str("))")
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
pub struct ShWshSortedMulti<K: DeriveCompr = XpubDerivable> {
    pub threshold: u4,
    // TODO: Switch to an IndexSet when supported by amplify
    pub keys: ConfinedVec<K, 1, 16>,
}

impl<K: DeriveCompr> ShWshSortedMulti<K> {
    pub fn new_checked(threshold: u8, keys: impl IntoIterator<Item = K>) -> Self {
        Self {
            threshold: u4::with(threshold),
            keys: ConfinedVec::from_iter_checked(keys),
        }
    }
    pub fn key_count(&self) -> u8 { self.keys.len() as u8 }
    pub fn threshold(&self) -> u8 { self.threshold.into_u8() }
}

impl<K: DeriveCompr> Derive<DerivedScript> for ShWshSortedMulti<K> {
    #[inline]
    fn default_keychain(&self) -> Keychain { self.keys[0].default_keychain() }

    #[inline]
    fn keychains(&self) -> BTreeSet<Keychain> { self.keys[0].keychains() }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = DerivedScript> {
        let witness_script =
            wsh_derive::<_, _, BTreeSet<_>>(self.threshold, &self.keys, keychain, index);
        iter::once(DerivedScript::NestedScript(witness_script))
    }
}

impl<K: DeriveCompr> Descriptor<K> for ShWshSortedMulti<K>
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
        // BTreeMap here provides us with the key sorting
        legacy_keyset(&self.keys, terminal).collect::<BTreeMap<_, _>>().into_iter().collect()
    }

    fn xonly_keyset(&self, _terminal: Terminal) -> IndexMap<XOnlyPk, TapDerivation> {
        IndexMap::new()
    }

    fn legacy_witness(
        &self,
        keysigs: IndexMap<&KeyOrigin, LegacyKeySig>,
        redeem_script: Option<RedeemScript>,
        witness_script: Option<WitnessScript>,
    ) -> Option<(SigScript, Option<Witness>)> {
        redeem_script.as_ref()?;
        // Check that all sigs match our keys
        if !check_sigs(self.keys().map(K::xpub_spec), &keysigs) {
            return None;
        }
        // We need to put the sigs into the order that matches the ordering of the keys
        let sorted =
            keysigs.into_values().map(|keysig| (keysig.key, keysig)).collect::<BTreeMap<_, _>>();

        let (_, witness) = witness(sorted.into_values(), witness_script?);
        let sig_script = SigScript::from_checked(redeem_script?.into_inner().into_vec());

        Some((sig_script, Some(witness?)))
    }

    fn taproot_witness(
        &self,
        _cb: Option<&ControlBlock>,
        _keysigs: IndexMap<&KeyOrigin, TaprootKeySig>,
    ) -> Option<Witness> {
        None
    }
}

impl<S: DeriveCompr> Display for ShWshSortedMulti<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("sh(wsh(sorted")?;
        fmt(self.threshold, self.keys(), f)?;
        f.write_str("))")
    }
}

// ------------------------------------------------------------------------------------------------

/// Check that all sigs match our keys
fn check_sigs<'a>(
    accounts: impl Iterator<Item = &'a XpubAccount>,
    keysigs: &IndexMap<&'a KeyOrigin, LegacyKeySig>,
) -> bool {
    let set = accounts.map(XpubAccount::origin).collect::<BTreeSet<_>>();
    keysigs.keys().all(|origin| set.contains(&origin.to_account_origin()))
}

fn derive<'k, T, K: Derive<T> + 'k, I: IntoIterator<Item = &'k K>>(
    keys: I,
    keychain: Keychain,
    index: NormalIndex,
) -> impl Iterator<Item = T> + use<'k, T, K, I> {
    keys.into_iter()
        .map(move |xkey| xkey.derive(keychain, index).next().expect("no derivation found"))
}

fn wsh_derive<'k, K, I, B>(
    threshold: u4,
    keys: I,
    keychain: impl Into<Keychain>,
    index: impl Into<NormalIndex>,
) -> WitnessScript
where
    K: DeriveCompr + 'k,
    I: IntoIterator<Item = &'k K>,
    B: FromIterator<CompressedPk> + IntoIterator<Item = CompressedPk>,
    <B::IntoIter as IntoIterator>::IntoIter: ExactSizeIterator,
{
    let keychain = keychain.into();
    let index = index.into();
    let derived_set = derive(keys, keychain, index).collect::<B>();
    witness_script(threshold, derived_set)
}

fn redeem_script<I: IntoIterator<Item = LegacyPk>>(threshold: u4, keys: I) -> RedeemScript
where I::IntoIter: ExactSizeIterator {
    let keys = keys.into_iter();
    let key_count = keys.len();

    let mut redeem_script = RedeemScript::with_capacity(key_count * 34 + 4);
    redeem_script.push_num(threshold.into_u8() as i64);
    for key in keys {
        redeem_script.push_slice(&key.serialize());
    }
    redeem_script.push_num(key_count as i64);
    redeem_script.push_opcode(OpCode::CheckMultiSig);

    redeem_script
}

fn witness_script<I: IntoIterator<Item = CompressedPk>>(threshold: u4, keys: I) -> WitnessScript
where I::IntoIter: ExactSizeIterator {
    let keys = keys.into_iter();
    let key_count = keys.len();

    let mut witness_script = WitnessScript::with_capacity(key_count * 34 + 4);
    witness_script.push_num(threshold.into_u8() as i64);
    for key in keys {
        witness_script.push_slice(&key.serialize());
    }
    witness_script.push_num(key_count as i64);
    witness_script.push_opcode(OpCode::CheckMultiSig);

    witness_script
}

fn legacy_keyset<'k, T: Into<LegacyPk>, K: DeriveKey<T> + 'k, I: IntoIterator<Item = &'k K>>(
    keys: I,
    terminal: Terminal,
) -> impl Iterator<Item = (LegacyPk, KeyOrigin)> + use<'k, T, K, I> {
    keys.into_iter().map(move |xkey| {
        let key = xkey
            .derive(terminal.keychain, terminal.index)
            .next()
            .expect("multisig must derive one key per path");
        (key.into(), KeyOrigin::with(xkey.xpub_spec().origin().clone(), terminal))
    })
}

fn sig_script(
    keysigs: impl Iterator<Item = LegacyKeySig>,
    redeem_script: RedeemScript,
) -> (SigScript, Option<Witness>) {
    let mut sig_script = SigScript::new();
    sig_script.push_num(0); // The infamous OP_CHECKMULTISIG bug
    for keysig in keysigs {
        sig_script.push_slice(&keysig.sig.to_vec());
    }
    sig_script.push_slice(redeem_script.as_ref());

    (sig_script, None)
}

fn witness(
    keysigs: impl Iterator<Item = LegacyKeySig>,
    witness_script: WitnessScript,
) -> (SigScript, Option<Witness>) {
    let mut stack = Vec::new();
    stack.push(vec![]); // The infamous OP_CHECKMULTISIG bug
    for keysig in keysigs {
        stack.push(keysig.sig.to_vec());
    }
    stack.push(witness_script.to_vec());
    let witness = Witness::from_consensus_stack(stack);
    (empty!(), Some(witness))
}

fn fmt<'k, K: Display + 'k>(
    threshold: u4,
    keys: impl IntoIterator<Item = &'k K>,
    f: &mut Formatter<'_>,
) -> fmt::Result {
    write!(f, "multi({threshold}")?;
    for key in keys {
        write!(f, ",{key}")?;
    }
    f.write_str(")")
}
