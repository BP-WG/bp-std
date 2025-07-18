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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};
use std::iter;

use amplify::confinement::ConfinedVec;
use derive::{
    ConsensusEncode, ControlBlock, Derive, DeriveXOnly, DerivedScript, InternalPk, KeyOrigin,
    Keychain, LeafScript, LegacyPk, NormalIndex, RedeemScript, SigScript, TapCode, TapDerivation,
    TapScript, TapTree, Terminal, Witness, WitnessScript, XOnlyPk, XpubAccount, XpubDerivable,
};
use indexmap::IndexMap;

use crate::{
    Descriptor, LegacyKeySig, ScriptDescr, ScriptItem, SpkClass, TaprootKeySig, WitnessItem,
};

#[derive(Clone, Eq, PartialEq, Hash, Debug, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(untagged))]
pub enum Tr<K: DeriveXOnly = XpubDerivable> {
    KeyOnly(TrKey<K>),
    Multi(TrMulti<K>),
    SortedMulti(TrSortedMulti<K>),
    Script(TrScript<K>),
}

impl<K: DeriveXOnly> Tr<K> {
    pub fn as_internal_key(&self) -> &K {
        match self {
            Tr::KeyOnly(d) => d.as_internal_key(),
            Tr::Multi(d) => d.as_internal_key(),
            Tr::SortedMulti(d) => d.as_internal_key(),
            Tr::Script(d) => d.as_internal_key(),
        }
    }
    pub fn into_internal_key(self) -> K {
        match self {
            Tr::KeyOnly(d) => d.into_internal_key(),
            Tr::Multi(d) => d.into_internal_key(),
            Tr::SortedMulti(d) => d.into_internal_key(),
            Tr::Script(d) => d.into_internal_key(),
        }
    }
}

impl<K: DeriveXOnly> Derive<DerivedScript> for Tr<K> {
    fn default_keychain(&self) -> Keychain {
        match self {
            Tr::KeyOnly(d) => d.default_keychain(),
            Tr::Multi(d) => d.default_keychain(),
            Tr::SortedMulti(d) => d.default_keychain(),
            Tr::Script(d) => d.default_keychain(),
        }
    }

    fn keychains(&self) -> BTreeSet<Keychain> {
        match self {
            Tr::KeyOnly(d) => d.keychains(),
            Tr::Multi(d) => d.keychains(),
            Tr::SortedMulti(d) => d.keychains(),
            Tr::Script(d) => d.keychains(),
        }
    }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = DerivedScript> {
        match self {
            Tr::KeyOnly(d) => d.derive(keychain, index).collect::<Vec<_>>(),
            Tr::Multi(d) => d.derive(keychain, index).collect::<Vec<_>>(),
            Tr::SortedMulti(d) => d.derive(keychain, index).collect::<Vec<_>>(),
            Tr::Script(d) => d.derive(keychain, index).collect::<Vec<_>>(),
        }
        .into_iter()
    }
}

impl<K: DeriveXOnly> Descriptor<K> for Tr<K> {
    fn class(&self) -> SpkClass {
        match self {
            Tr::KeyOnly(d) => d.class(),
            Tr::Multi(d) => d.class(),
            Tr::SortedMulti(d) => d.class(),
            Tr::Script(d) => d.class(),
        }
    }

    fn keys<'a>(&'a self) -> impl Iterator<Item = &'a K>
    where K: 'a {
        match self {
            Tr::KeyOnly(d) => d.keys().collect::<Vec<_>>(),
            Tr::Multi(d) => d.keys().collect::<Vec<_>>(),
            Tr::SortedMulti(d) => d.keys().collect::<Vec<_>>(),
            Tr::Script(d) => d.keys().collect::<Vec<_>>(),
        }
        .into_iter()
    }

    fn vars<'a>(&'a self) -> impl Iterator<Item = &'a ()>
    where (): 'a {
        match self {
            Tr::KeyOnly(d) => d.vars().collect::<Vec<_>>(),
            Tr::Multi(d) => d.vars().collect::<Vec<_>>(),
            Tr::SortedMulti(d) => d.vars().collect::<Vec<_>>(),
            Tr::Script(d) => d.vars().collect::<Vec<_>>(),
        }
        .into_iter()
    }

    fn xpubs(&self) -> impl Iterator<Item = &XpubAccount> {
        match self {
            Tr::KeyOnly(d) => d.xpubs().collect::<Vec<_>>(),
            Tr::Multi(d) => d.xpubs().collect::<Vec<_>>(),
            Tr::SortedMulti(d) => d.xpubs().collect::<Vec<_>>(),
            Tr::Script(d) => d.xpubs().collect::<Vec<_>>(),
        }
        .into_iter()
    }

    fn legacy_keyset(&self, terminal: Terminal) -> IndexMap<LegacyPk, KeyOrigin> {
        match self {
            Tr::KeyOnly(d) => d.legacy_keyset(terminal),
            Tr::Multi(d) => d.legacy_keyset(terminal),
            Tr::SortedMulti(d) => d.legacy_keyset(terminal),
            Tr::Script(d) => d.legacy_keyset(terminal),
        }
    }

    fn xonly_keyset(&self, terminal: Terminal) -> IndexMap<XOnlyPk, TapDerivation> {
        match self {
            Tr::KeyOnly(d) => d.xonly_keyset(terminal),
            Tr::Multi(d) => d.xonly_keyset(terminal),
            Tr::SortedMulti(d) => d.xonly_keyset(terminal),
            Tr::Script(d) => d.xonly_keyset(terminal),
        }
    }

    fn legacy_witness(
        &self,
        keysigs: IndexMap<&KeyOrigin, LegacyKeySig>,
        redeem_script: Option<RedeemScript>,
        witness_script: Option<WitnessScript>,
    ) -> Option<(SigScript, Option<Witness>)> {
        match self {
            Tr::KeyOnly(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
            Tr::Multi(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
            Tr::SortedMulti(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
            Tr::Script(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
        }
    }

    fn taproot_witness(
        &self,
        cb: Option<&ControlBlock>,
        keysigs: IndexMap<&KeyOrigin, TaprootKeySig>,
    ) -> Option<Witness> {
        match self {
            Tr::KeyOnly(d) => d.taproot_witness(cb, keysigs),
            Tr::Multi(d) => d.taproot_witness(cb, keysigs),
            Tr::SortedMulti(d) => d.taproot_witness(cb, keysigs),
            Tr::Script(d) => d.taproot_witness(cb, keysigs),
        }
    }
}

impl<K: DeriveXOnly> Display for Tr<K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Tr::KeyOnly(d) => Display::fmt(d, f),
            Tr::Multi(d) => Display::fmt(d, f),
            Tr::SortedMulti(d) => Display::fmt(d, f),
            Tr::Script(d) => Display::fmt(d, f),
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
        _keysigs: IndexMap<&KeyOrigin, LegacyKeySig>,
        _redeem_script: Option<RedeemScript>,
        _witness_script: Option<WitnessScript>,
    ) -> Option<(SigScript, Option<Witness>)> {
        None
    }

    fn taproot_witness(
        &self,
        cb: Option<&ControlBlock>,
        keysigs: IndexMap<&KeyOrigin, TaprootKeySig>,
    ) -> Option<Witness> {
        if cb.is_some() {
            // TrKey doesn't support script path spending
            return None;
        }
        let our_origin = self.0.xpub_spec().origin();
        let keysig =
            keysigs.iter().find(|(origin, _)| our_origin.is_subset_of(origin)).map(|(_, ks)| ks)?;
        Some(Witness::from_consensus_stack([keysig.sig.to_vec()]))
    }
}

impl<K: DeriveXOnly> Display for TrKey<K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { write!(f, "tr({})", self.0) }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TrMulti<K: DeriveXOnly> {
    pub internal_key: K,
    pub threshold: u16,
    pub script_keys: ConfinedVec<K, 1, 999>,
}

impl<K: DeriveXOnly> TrMulti<K> {
    pub fn as_internal_key(&self) -> &K { &self.internal_key }
    pub fn into_internal_key(self) -> K { self.internal_key }
}

impl<K: DeriveXOnly> Derive<DerivedScript> for TrMulti<K> {
    #[inline]
    fn default_keychain(&self) -> Keychain { self.internal_key.default_keychain() }

    #[inline]
    fn keychains(&self) -> BTreeSet<Keychain> { self.internal_key.keychains() }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = DerivedScript> {
        let keychain = keychain.into();
        let index = index.into();
        let internal_key =
            self.internal_key.derive(keychain, index).next().expect("no derivation found");

        let keys = self
            .script_keys
            .iter()
            .map(|xkey| xkey.derive(keychain, index).next().expect("no derivation found"));
        let tree = to_tap_tree(self.threshold, keys);
        iter::once(DerivedScript::TaprootScript(InternalPk::from_unchecked(internal_key), tree))
    }
}

impl<K: DeriveXOnly> Descriptor<K> for TrMulti<K> {
    fn class(&self) -> SpkClass { SpkClass::P2tr }

    fn keys<'a>(&'a self) -> impl Iterator<Item = &'a K>
    where K: 'a {
        iter::once(&self.internal_key).chain(&self.script_keys)
    }
    fn vars<'a>(&'a self) -> impl Iterator<Item = &'a ()>
    where (): 'a {
        iter::empty()
    }
    fn xpubs(&self) -> impl Iterator<Item = &XpubAccount> { self.keys().map(K::xpub_spec) }

    fn legacy_keyset(&self, _terminal: Terminal) -> IndexMap<LegacyPk, KeyOrigin> {
        IndexMap::new()
    }

    fn xonly_keyset(&self, terminal: Terminal) -> IndexMap<XOnlyPk, TapDerivation> {
        xonly_keyset(self.keys(), terminal).collect()
    }

    fn legacy_witness(
        &self,
        _keysigs: IndexMap<&KeyOrigin, LegacyKeySig>,
        _redeem_script: Option<RedeemScript>,
        _witness_script: Option<WitnessScript>,
    ) -> Option<(SigScript, Option<Witness>)> {
        None
    }

    fn taproot_witness(
        &self,
        cb: Option<&ControlBlock>,
        keysigs: IndexMap<&KeyOrigin, TaprootKeySig>,
    ) -> Option<Witness> {
        witness(&self.internal_key, self.threshold, cb, keysigs)
    }
}

impl<K: DeriveXOnly> Display for TrMulti<K>
where K: Display
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt(&self.internal_key, self.threshold, &self.script_keys, false, f)
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TrSortedMulti<K: DeriveXOnly> {
    pub internal_key: K,
    pub threshold: u16,
    pub script_keys: ConfinedVec<K, 1, 999>,
}

impl<K: DeriveXOnly> TrSortedMulti<K> {
    pub fn as_internal_key(&self) -> &K { &self.internal_key }
    pub fn into_internal_key(self) -> K { self.internal_key }
}

impl<K: DeriveXOnly> Derive<DerivedScript> for TrSortedMulti<K> {
    #[inline]
    fn default_keychain(&self) -> Keychain { self.internal_key.default_keychain() }

    #[inline]
    fn keychains(&self) -> BTreeSet<Keychain> { self.internal_key.keychains() }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = DerivedScript> {
        let keychain = keychain.into();
        let index = index.into();
        let internal_key =
            self.internal_key.derive(keychain, index).next().expect("no derivation found");

        let keys = self
            .script_keys
            .iter()
            .map(|xkey| xkey.derive(keychain, index).next().expect("no derivation found"))
            // Using BTreeSet here ensures the keys are sorted
            .collect::<BTreeSet<_>>();
        let tree = to_tap_tree(self.threshold, keys);
        iter::once(DerivedScript::TaprootScript(InternalPk::from_unchecked(internal_key), tree))
    }
}

impl<K: DeriveXOnly> Descriptor<K> for TrSortedMulti<K> {
    fn class(&self) -> SpkClass { SpkClass::P2tr }

    fn keys<'a>(&'a self) -> impl Iterator<Item = &'a K>
    where K: 'a {
        iter::once(&self.internal_key).chain(&self.script_keys)
    }
    fn vars<'a>(&'a self) -> impl Iterator<Item = &'a ()>
    where (): 'a {
        iter::empty()
    }
    fn xpubs(&self) -> impl Iterator<Item = &XpubAccount> { self.keys().map(K::xpub_spec) }

    fn legacy_keyset(&self, _terminal: Terminal) -> IndexMap<LegacyPk, KeyOrigin> {
        IndexMap::new()
    }

    fn xonly_keyset(&self, terminal: Terminal) -> IndexMap<XOnlyPk, TapDerivation> {
        // BTreeMap here provides us with the key sorting
        xonly_keyset(self.keys(), terminal).collect::<BTreeMap<_, _>>().into_iter().collect()
    }

    fn legacy_witness(
        &self,
        _keysigs: IndexMap<&KeyOrigin, LegacyKeySig>,
        _redeem_script: Option<RedeemScript>,
        _witness_script: Option<WitnessScript>,
    ) -> Option<(SigScript, Option<Witness>)> {
        None
    }

    fn taproot_witness(
        &self,
        cb: Option<&ControlBlock>,
        keysigs: IndexMap<&KeyOrigin, TaprootKeySig>,
    ) -> Option<Witness> {
        witness(&self.internal_key, self.threshold, cb, keysigs)
    }
}

impl<K: DeriveXOnly> Display for TrSortedMulti<K>
where K: Display
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt(&self.internal_key, self.threshold, &self.script_keys, true, f)
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TrScript<K: DeriveXOnly> {
    internal_key: K,
    tap_tree: TapTree<ScriptDescr<TapCode, K>>,
}

impl<K: DeriveXOnly> TrScript<K> {
    pub fn new(internal_key: K, tap_tree: TapTree<ScriptDescr<TapCode, K>>) -> TrScript<K> {
        Self {
            internal_key,
            tap_tree,
        }
    }
    pub fn as_internal_key(&self) -> &K { &self.internal_key }
    pub fn into_internal_key(self) -> K { self.internal_key }
}

impl<K: DeriveXOnly> Derive<DerivedScript> for TrScript<K> {
    #[inline]
    fn default_keychain(&self) -> Keychain { self.internal_key.default_keychain() }

    #[inline]
    fn keychains(&self) -> BTreeSet<Keychain> { self.internal_key.keychains() }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = DerivedScript> {
        let keychain = keychain.into();
        let index = index.into();
        let internal_key =
            self.internal_key.derive(keychain, index).next().expect("no derivation found");
        let tree = self
            .tap_tree
            .clone()
            .map(|script| script.derive(keychain, index).next().expect("no derivation found"));
        iter::once(DerivedScript::TaprootScript(InternalPk::from_unchecked(internal_key), tree))
    }
}

impl<K: DeriveXOnly> Descriptor<K> for TrScript<K> {
    fn class(&self) -> SpkClass { SpkClass::P2tr }

    fn keys<'a>(&'a self) -> impl Iterator<Item = &'a K>
    where K: 'a {
        let mut keys = set![&self.internal_key];
        for leaf in &self.tap_tree {
            keys.extend(leaf.script.keys());
        }
        keys.into_iter()
    }
    fn vars<'a>(&'a self) -> impl Iterator<Item = &'a ()>
    where (): 'a {
        iter::empty()
    }
    fn xpubs(&self) -> impl Iterator<Item = &XpubAccount> { self.keys().map(K::xpub_spec) }

    fn legacy_keyset(&self, _terminal: Terminal) -> IndexMap<LegacyPk, KeyOrigin> {
        IndexMap::new()
    }

    fn xonly_keyset(&self, terminal: Terminal) -> IndexMap<XOnlyPk, TapDerivation> {
        self.keys()
            .map(|xkey| {
                let key =
                    xkey.derive(terminal.keychain, terminal.index).next().expect("no key found");
                (key, TapDerivation::with_internal_pk(xkey.xpub_spec().origin().clone(), terminal))
            })
            .collect()
    }

    fn legacy_witness(
        &self,
        _keysigs: IndexMap<&KeyOrigin, LegacyKeySig>,
        _redeem_script: Option<RedeemScript>,
        _witness_script: Option<WitnessScript>,
    ) -> Option<(SigScript, Option<Witness>)> {
        None
    }

    fn taproot_witness(
        &self,
        cb: Option<&ControlBlock>,
        keysigs: IndexMap<&KeyOrigin, TaprootKeySig>,
    ) -> Option<Witness> {
        if let Some(cb) = cb {
            for leaf in &self.tap_tree {
                let descr = &leaf.script;
                let mut stack = vec![];
                let mut fail = false;
                for item in &descr.satisfaction {
                    match item {
                        WitnessItem::Signature(origin) => {
                            let Some(src) = keysigs.get(origin) else {
                                fail = true;
                                break;
                            };
                            stack.push(src.sig.to_vec());
                        }
                        WitnessItem::Data(data) => stack.push(data.clone()),
                    }
                }
                if fail {
                    continue;
                }
                let mut script = TapScript::new();
                for item in &descr.condition {
                    match item {
                        ScriptItem::Key(origin, _) => {
                            let derivation = origin.as_derivation();
                            let Some((_, src)) = keysigs
                                .iter()
                                .find(|(o, _)| o.as_derivation().starts_with(derivation))
                            else {
                                continue;
                            };
                            script.push_slice(&src.key.to_byte_array());
                        }
                        ScriptItem::Code(code) => {
                            for tapcode in code {
                                script.push_opcode(*tapcode);
                            }
                        }
                        ScriptItem::Data(fata) => script.push_slice(fata),
                    }
                }
                stack.push(script.to_vec());
                stack.push(cb.consensus_serialize());
                return Some(Witness::from_consensus_stack(stack));
            }
            None
        } else {
            let our_origin = self.internal_key.xpub_spec().origin();
            let keysig = keysigs
                .iter()
                .find(|(origin, _)| our_origin.is_subset_of(origin))
                .map(|(_, ks)| ks)?;
            Some(Witness::from_consensus_stack([keysig.sig.to_vec()]))
        }
    }
}

impl<K: DeriveXOnly> Display for TrScript<K>
where K: Display
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "tr({}, {})", self.internal_key, self.tap_tree)
    }
}

// ------------------------------------------------------------------------------------------------

fn to_tap_tree(
    threshold: u16,
    script_keys: impl IntoIterator<Item = XOnlyPk>,
) -> TapTree<LeafScript> {
    let mut tap_script = TapScript::new();
    for key in script_keys {
        tap_script.push_slice(&key.to_byte_array());
        tap_script.push_opcode(TapCode::CheckSigAdd);
    }
    tap_script.push_num(threshold as i64);
    tap_script.push_opcode(TapCode::NumEqual);
    TapTree::with_single_leaf(tap_script)
}

fn xonly_keyset<'k, K: DeriveXOnly + 'k, I: IntoIterator<Item = &'k K>>(
    keys: I,
    terminal: Terminal,
) -> impl Iterator<Item = (XOnlyPk, TapDerivation)> + use<'k, K, I> {
    keys.into_iter().map(move |xkey| {
        let key = xkey.derive(terminal.keychain, terminal.index).next().expect("no key found");
        (key, TapDerivation::with_internal_pk(xkey.xpub_spec().origin().clone(), terminal))
    })
}

fn witness<K: DeriveXOnly>(
    internal_key: &K,
    threshold: u16,
    cb: Option<&ControlBlock>,
    keysigs: IndexMap<&KeyOrigin, TaprootKeySig>,
) -> Option<Witness> {
    if let Some(cb) = cb {
        let mut stack = vec![];
        let mut tap_script = TapScript::new();
        for sig in keysigs.values() {
            stack.push(sig.sig.to_vec());
            tap_script.push_slice(&sig.key.to_byte_array());
            tap_script.push_opcode(TapCode::CheckSigAdd);
        }
        tap_script.push_num(threshold as i64);
        tap_script.push_opcode(TapCode::NumEqual);
        stack.push(tap_script.to_vec());
        stack.push(cb.consensus_serialize());
        Some(Witness::from_consensus_stack(stack))
    } else {
        let our_origin = internal_key.xpub_spec().origin();
        let keysig =
            keysigs.iter().find(|(origin, _)| our_origin.is_subset_of(origin)).map(|(_, ks)| ks)?;
        Some(Witness::from_consensus_stack([keysig.sig.to_vec()]))
    }
}

fn fmt<'k, K: Display + 'k>(
    internal_key: &'k K,
    threshold: u16,
    keys: impl IntoIterator<Item = &'k K>,
    sorted: bool,
    f: &mut Formatter<'_>,
) -> fmt::Result {
    write!(f, "tr({internal_key},")?;
    if sorted {
        f.write_str("sorted")?;
    }
    write!(f, "multi_a({threshold}")?;
    for key in keys {
        write!(f, ",{key}")?;
    }
    f.write_str("))")
}
