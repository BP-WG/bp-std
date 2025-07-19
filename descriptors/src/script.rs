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

use std::collections::BTreeSet;
use std::fmt::{self, Display, Formatter, Write};
use std::hash::Hash;
use std::iter;

use amplify::confinement::Collection;
use amplify::hex::ToHex;
use amplify::Wrapper;
use derive::{
    ControlBlock, Derive, DeriveCompr, DeriveLegacy, DeriveSet, DeriveXOnly, DerivedScript,
    KeyOrigin, Keychain, LeafScript, LegacyPk, NormalIndex, OpCode, RedeemScript, ScriptPubkey,
    SigScript, TapCode, TapDerivation, TapScript, Terminal, Witness, WitnessScript, XOnlyPk,
    XkeyOrigin, XpubAccount, XpubDerivable,
};
use indexmap::IndexMap;

use crate::{
    Descriptor, LegacyKeySig, ShMulti, ShSortedMulti, ShWpkh, ShWshMulti, ShWshSortedMulti,
    SpkClass, TaprootKeySig,
};

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ScriptItem<S, K> {
    Key(XkeyOrigin, K),
    Code(Vec<S>),
    Data(Vec<u8>),
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum WitnessItem {
    Signature(KeyOrigin),
    Data(Vec<u8>),
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ScriptDescr<S, K> {
    pub condition: Vec<ScriptItem<S, K>>,
    pub satisfaction: Vec<WitnessItem>,
}

impl<S, K: Eq + Hash> ScriptDescr<S, K> {
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        let mut keys = set![];
        for item in &self.condition {
            if let ScriptItem::Key(_, key) = item {
                keys.push(key);
            }
        }
        keys.into_iter()
    }
}

impl<K: DeriveLegacy> Derive<RedeemScript> for ScriptDescr<OpCode, K> {
    fn default_keychain(&self) -> Keychain {
        self.keys().next().map(|k| k.default_keychain()).unwrap_or_else(|| {
            *self.keychains().first().expect("at least one keychain must be defined")
        })
    }

    fn keychains(&self) -> BTreeSet<Keychain> {
        self.keys().next().map(|k| k.keychains()).unwrap_or(bset![Keychain::OUTER, Keychain::INNER])
    }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = RedeemScript> {
        let keychain = keychain.into();
        let index = index.into();
        let mut script = RedeemScript::new();
        for item in &self.condition {
            match item {
                ScriptItem::Key(_, xkey) => {
                    let key =
                        xkey.derive(keychain, index).next().expect("xkey derivation is empty");
                    script.push_slice(&key.serialize());
                }
                ScriptItem::Code(code) => {
                    for tapcode in code {
                        script.push_opcode(*tapcode);
                    }
                }
                ScriptItem::Data(fata) => script.push_slice(fata),
            }
        }
        iter::once(script)
    }
}

impl<K: DeriveCompr> Derive<WitnessScript> for ScriptDescr<OpCode, K> {
    fn default_keychain(&self) -> Keychain {
        self.keys().next().map(|k| k.default_keychain()).unwrap_or_else(|| {
            *self.keychains().first().expect("at least one keychain must be defined")
        })
    }

    fn keychains(&self) -> BTreeSet<Keychain> {
        self.keys().next().map(|k| k.keychains()).unwrap_or(bset![Keychain::OUTER, Keychain::INNER])
    }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = WitnessScript> {
        let keychain = keychain.into();
        let index = index.into();
        let mut script = WitnessScript::new();
        for item in &self.condition {
            match item {
                ScriptItem::Key(_, xkey) => {
                    let key =
                        xkey.derive(keychain, index).next().expect("xkey derivation is empty");
                    script.push_slice(&key.serialize());
                }
                ScriptItem::Code(code) => {
                    for tapcode in code {
                        script.push_opcode(*tapcode);
                    }
                }
                ScriptItem::Data(fata) => script.push_slice(fata),
            }
        }
        iter::once(script)
    }
}

impl<K: DeriveXOnly> Derive<LeafScript> for ScriptDescr<TapCode, K> {
    fn default_keychain(&self) -> Keychain {
        self.keys().next().map(|k| k.default_keychain()).unwrap_or_else(|| {
            *self.keychains().first().expect("at least one keychain must be defined")
        })
    }

    fn keychains(&self) -> BTreeSet<Keychain> {
        self.keys().next().map(|k| k.keychains()).unwrap_or(bset![Keychain::OUTER, Keychain::INNER])
    }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = LeafScript> {
        let keychain = keychain.into();
        let index = index.into();
        let mut tap_script = TapScript::new();
        for item in &self.condition {
            match item {
                ScriptItem::Key(_, xkey) => {
                    let key =
                        xkey.derive(keychain, index).next().expect("xkey derivation is empty");
                    tap_script.push_slice(&key.to_byte_array());
                }
                ScriptItem::Code(code) => {
                    for tapcode in code {
                        tap_script.push_opcode(*tapcode);
                    }
                }
                ScriptItem::Data(fata) => tap_script.push_slice(fata),
            }
        }
        iter::once(tap_script.into())
    }
}

impl<S: Display, K: Display> Display for ScriptDescr<S, K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for item in &self.condition {
            if first {
                f.write_char(' ')?;
            }
            match item {
                ScriptItem::Key(_, key) => Display::fmt(key, f)?,
                ScriptItem::Code(code) => {
                    for opcode in code {
                        write!(f, "{opcode}")?;
                    }
                }
                ScriptItem::Data(data) => {
                    write!(f, "<{}>", data.to_hex())?;
                }
            }
            first = false
        }
        Ok(())
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Eq, PartialEq, Hash, Debug, From)]
pub struct Raw<K: DeriveLegacy = XpubDerivable>(ScriptDescr<OpCode, K>);

impl<K: DeriveLegacy> Derive<DerivedScript> for Raw<K> {
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
            .map(|redeem_script| ScriptPubkey::from_checked(redeem_script.to_vec()))
            .map(DerivedScript::Bare)
    }
}

impl<K: DeriveLegacy> Descriptor<K> for Raw<K> {
    fn class(&self) -> SpkClass { SpkClass::Bare }

    fn keys<'a>(&'a self) -> impl Iterator<Item = &'a K>
    where K: 'a {
        self.0.keys()
    }
    fn vars<'a>(&'a self) -> impl Iterator<Item = &'a ()>
    where (): 'a {
        iter::empty()
    }
    fn xpubs(&self) -> impl Iterator<Item = &XpubAccount> { self.keys().map(K::xpub_spec) }

    fn legacy_keyset(&self, terminal: Terminal) -> IndexMap<LegacyPk, KeyOrigin> {
        self.keys()
            .map(|xkey| {
                let key = xkey
                    .derive(terminal.keychain, terminal.index)
                    .next()
                    .expect("xkey derivation is empty");
                (key, KeyOrigin::with(xkey.xpub_spec().origin().clone(), terminal))
            })
            .collect()
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
        debug_assert!(redeem_script.is_none(), "redeemScript in Wsh descriptor must is empty");
        let mut stack = vec![];
        for item in &self.0.satisfaction {
            match item {
                WitnessItem::Signature(origin) => {
                    let Some(src) = keysigs.get(origin) else {
                        break;
                    };
                    stack.push(src.sig.to_vec());
                }
                WitnessItem::Data(data) => stack.push(data.clone()),
            }
        }
        stack.push(witness_script?.into_inner().into_vec());
        Some((SigScript::new(), Some(Witness::from_consensus_stack(stack))))
    }

    fn taproot_witness(
        &self,
        _cb: Option<&ControlBlock>,
        _keysigs: IndexMap<&KeyOrigin, TaprootKeySig>,
    ) -> Option<Witness> {
        None
    }
}

impl<K: DeriveLegacy> Display for Raw<K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { write!(f, "raw({})", self.0) }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        rename_all = "camelCase",
        bound(
            serialize = "S::Legacy: serde::Serialize, S::Compr: serde::Serialize",
            deserialize = "S::Legacy: serde::Deserialize<'de>, S::Compr: serde::Deserialize<'de>"
        )
    )
)]
#[non_exhaustive]
pub enum Sh<S: DeriveSet = XpubDerivable> {
    #[from]
    ShScript(ShScript<S::Legacy>),

    #[from]
    ShMulti(ShMulti<S::Legacy>),

    #[from]
    ShSortedMulti(ShSortedMulti<S::Legacy>),

    #[from]
    WshScript(ShWshScript<S::Compr>),

    #[from]
    WshMulti(ShWshMulti<S::Compr>),

    #[from]
    WshSortedMulti(ShWshSortedMulti<S::Compr>),

    #[from]
    Wpkh(ShWpkh<S::Compr>),
}

impl<S: DeriveSet> From<ShWsh<S::Compr>> for Sh<S> {
    fn from(d: ShWsh<S::Compr>) -> Self {
        match d {
            ShWsh::Script(d) => Self::WshScript(d),
            ShWsh::Multi(d) => Self::WshMulti(d),
            ShWsh::SortedMulti(d) => Self::WshSortedMulti(d),
        }
    }
}

impl<S: DeriveSet> Derive<DerivedScript> for Sh<S> {
    fn default_keychain(&self) -> Keychain {
        match self {
            Sh::ShScript(d) => d.default_keychain(),
            Sh::ShMulti(d) => d.default_keychain(),
            Sh::ShSortedMulti(d) => d.default_keychain(),
            Sh::Wpkh(d) => d.default_keychain(),
            Sh::WshScript(d) => d.default_keychain(),
            Sh::WshMulti(d) => d.default_keychain(),
            Sh::WshSortedMulti(d) => d.default_keychain(),
        }
    }

    fn keychains(&self) -> BTreeSet<Keychain> {
        match self {
            Sh::ShScript(d) => d.keychains(),
            Sh::ShMulti(d) => d.keychains(),
            Sh::ShSortedMulti(d) => d.keychains(),
            Sh::Wpkh(d) => d.keychains(),
            Sh::WshScript(d) => d.keychains(),
            Sh::WshMulti(d) => d.keychains(),
            Sh::WshSortedMulti(d) => d.keychains(),
        }
    }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = DerivedScript> {
        match self {
            Sh::ShScript(d) => d.derive(keychain, index).collect::<Vec<_>>().into_iter(),
            Sh::ShMulti(d) => d.derive(keychain, index).collect::<Vec<_>>().into_iter(),
            Sh::ShSortedMulti(d) => d.derive(keychain, index).collect::<Vec<_>>().into_iter(),
            Sh::Wpkh(d) => d.derive(keychain, index).collect::<Vec<_>>().into_iter(),
            Sh::WshScript(d) => d.derive(keychain, index).collect::<Vec<_>>().into_iter(),
            Sh::WshMulti(d) => d.derive(keychain, index).collect::<Vec<_>>().into_iter(),
            Sh::WshSortedMulti(d) => d.derive(keychain, index).collect::<Vec<_>>().into_iter(),
        }
    }
}

impl<K: DeriveSet<Legacy = K, Compr = K> + DeriveLegacy + DeriveCompr> Descriptor<K> for Sh<K>
where Self: Derive<DerivedScript>
{
    fn class(&self) -> SpkClass {
        match self {
            Sh::ShScript(d) => d.class(),
            Sh::ShMulti(d) => d.class(),
            Sh::ShSortedMulti(d) => d.class(),
            Sh::Wpkh(d) => d.class(),
            Sh::WshScript(d) => d.class(),
            Sh::WshMulti(d) => d.class(),
            Sh::WshSortedMulti(d) => d.class(),
        }
    }

    fn keys<'a>(&'a self) -> impl Iterator<Item = &'a K>
    where K: 'a {
        match self {
            Sh::ShScript(d) => d.keys().collect::<Vec<_>>(),
            Sh::ShMulti(d) => d.keys().collect::<Vec<_>>(),
            Sh::ShSortedMulti(d) => d.keys().collect::<Vec<_>>(),
            Sh::Wpkh(d) => d.keys().collect::<Vec<_>>(),
            Sh::WshScript(d) => d.keys().collect::<Vec<_>>(),
            Sh::WshMulti(d) => d.keys().collect::<Vec<_>>(),
            Sh::WshSortedMulti(d) => d.keys().collect::<Vec<_>>(),
        }
        .into_iter()
    }

    fn vars<'a>(&'a self) -> impl Iterator<Item = &'a ()>
    where (): 'a {
        iter::empty()
    }

    fn xpubs(&self) -> impl Iterator<Item = &XpubAccount> {
        match self {
            Sh::ShScript(d) => d.xpubs().collect::<Vec<_>>(),
            Sh::ShMulti(d) => d.xpubs().collect::<Vec<_>>(),
            Sh::ShSortedMulti(d) => d.xpubs().collect::<Vec<_>>(),
            Sh::Wpkh(d) => d.xpubs().collect::<Vec<_>>(),
            Sh::WshScript(d) => d.xpubs().collect::<Vec<_>>(),
            Sh::WshMulti(d) => d.xpubs().collect::<Vec<_>>(),
            Sh::WshSortedMulti(d) => d.xpubs().collect::<Vec<_>>(),
        }
        .into_iter()
    }

    fn legacy_keyset(&self, terminal: Terminal) -> IndexMap<LegacyPk, KeyOrigin> {
        match self {
            Sh::ShScript(d) => d.legacy_keyset(terminal),
            Sh::ShMulti(d) => d.legacy_keyset(terminal),
            Sh::ShSortedMulti(d) => d.legacy_keyset(terminal),
            Sh::Wpkh(d) => d.legacy_keyset(terminal),
            Sh::WshScript(d) => d.legacy_keyset(terminal),
            Sh::WshMulti(d) => d.legacy_keyset(terminal),
            Sh::WshSortedMulti(d) => d.legacy_keyset(terminal),
        }
    }

    fn xonly_keyset(&self, terminal: Terminal) -> IndexMap<XOnlyPk, TapDerivation> {
        match self {
            Sh::ShScript(d) => d.xonly_keyset(terminal),
            Sh::ShMulti(d) => d.xonly_keyset(terminal),
            Sh::ShSortedMulti(d) => d.xonly_keyset(terminal),
            Sh::Wpkh(d) => d.xonly_keyset(terminal),
            Sh::WshScript(d) => d.xonly_keyset(terminal),
            Sh::WshMulti(d) => d.xonly_keyset(terminal),
            Sh::WshSortedMulti(d) => d.xonly_keyset(terminal),
        }
    }

    fn legacy_witness(
        &self,
        keysigs: IndexMap<&KeyOrigin, LegacyKeySig>,
        redeem_script: Option<RedeemScript>,
        witness_script: Option<WitnessScript>,
    ) -> Option<(SigScript, Option<Witness>)> {
        match self {
            Sh::ShScript(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
            Sh::ShMulti(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
            Sh::ShSortedMulti(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
            Sh::Wpkh(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
            Sh::WshScript(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
            Sh::WshMulti(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
            Sh::WshSortedMulti(d) => d.legacy_witness(keysigs, redeem_script, witness_script),
        }
    }

    fn taproot_witness(
        &self,
        cb: Option<&ControlBlock>,
        keysigs: IndexMap<&KeyOrigin, TaprootKeySig>,
    ) -> Option<Witness> {
        match self {
            Sh::ShScript(d) => d.taproot_witness(cb, keysigs),
            Sh::ShMulti(d) => d.taproot_witness(cb, keysigs),
            Sh::ShSortedMulti(d) => d.taproot_witness(cb, keysigs),
            Sh::Wpkh(d) => d.taproot_witness(cb, keysigs),
            Sh::WshScript(d) => d.taproot_witness(cb, keysigs),
            Sh::WshMulti(d) => d.taproot_witness(cb, keysigs),
            Sh::WshSortedMulti(d) => d.taproot_witness(cb, keysigs),
        }
    }
}

impl<S: DeriveSet> Display for Sh<S>
where
    S::Legacy: Display,
    S::Compr: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Sh::ShScript(d) => Display::fmt(d, f),
            Sh::ShMulti(d) => Display::fmt(d, f),
            Sh::ShSortedMulti(d) => Display::fmt(d, f),
            Sh::Wpkh(d) => Display::fmt(d, f),
            Sh::WshScript(d) => Display::fmt(d, f),
            Sh::WshMulti(d) => Display::fmt(d, f),
            Sh::WshSortedMulti(d) => Display::fmt(d, f),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(untagged))]
pub enum ShWsh<K: DeriveCompr = XpubDerivable> {
    #[from]
    Script(ShWshScript<K>),

    #[from]
    Multi(ShWshMulti<K>),

    #[from]
    SortedMulti(ShWshSortedMulti<K>),
}

impl<K: DeriveCompr> Derive<DerivedScript> for ShWsh<K> {
    fn default_keychain(&self) -> Keychain {
        match self {
            Self::Script(d) => d.default_keychain(),
            Self::Multi(d) => d.default_keychain(),
            Self::SortedMulti(d) => d.default_keychain(),
        }
    }

    fn keychains(&self) -> BTreeSet<Keychain> {
        match self {
            Self::Script(d) => d.keychains(),
            Self::Multi(d) => d.keychains(),
            Self::SortedMulti(d) => d.keychains(),
        }
    }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = DerivedScript> {
        let convert = |script| match script {
            DerivedScript::Segwit(s) => DerivedScript::NestedScript(s),
            _ => unreachable!(),
        };
        match self {
            Self::Script(d) => d.derive(keychain, index).map(convert).collect::<Vec<_>>(),
            Self::Multi(d) => d.derive(keychain, index).map(convert).collect::<Vec<_>>(),
            Self::SortedMulti(d) => d.derive(keychain, index).map(convert).collect::<Vec<_>>(),
        }
        .into_iter()
    }
}

impl<K: DeriveCompr> Descriptor<K> for ShWsh<K> {
    fn class(&self) -> SpkClass { SpkClass::P2sh }

    fn keys<'a>(&'a self) -> impl Iterator<Item = &'a K>
    where K: 'a {
        match self {
            Self::Script(d) => d.keys().collect::<Vec<_>>(),
            Self::Multi(d) => d.keys().collect::<Vec<_>>(),
            Self::SortedMulti(d) => d.keys().collect::<Vec<_>>(),
        }
        .into_iter()
    }

    fn vars<'a>(&'a self) -> impl Iterator<Item = &'a ()>
    where (): 'a {
        match self {
            Self::Script(d) => d.vars().collect::<Vec<_>>(),
            Self::Multi(d) => d.vars().collect::<Vec<_>>(),
            Self::SortedMulti(d) => d.vars().collect::<Vec<_>>(),
        }
        .into_iter()
    }

    fn xpubs(&self) -> impl Iterator<Item = &XpubAccount> {
        match self {
            Self::Script(d) => d.xpubs().collect::<Vec<_>>(),
            Self::Multi(d) => d.xpubs().collect::<Vec<_>>(),
            Self::SortedMulti(d) => d.xpubs().collect::<Vec<_>>(),
        }
        .into_iter()
    }

    fn legacy_keyset(&self, terminal: Terminal) -> IndexMap<LegacyPk, KeyOrigin> {
        match self {
            Self::Script(d) => d.legacy_keyset(terminal),
            Self::Multi(d) => d.legacy_keyset(terminal),
            Self::SortedMulti(d) => d.legacy_keyset(terminal),
        }
    }

    fn xonly_keyset(&self, terminal: Terminal) -> IndexMap<XOnlyPk, TapDerivation> {
        match self {
            Self::Script(d) => d.xonly_keyset(terminal),
            Self::Multi(d) => d.xonly_keyset(terminal),
            Self::SortedMulti(d) => d.xonly_keyset(terminal),
        }
    }

    fn legacy_witness(
        &self,
        keysigs: IndexMap<&KeyOrigin, LegacyKeySig>,
        redeem_script: Option<RedeemScript>,
        witness_script: Option<WitnessScript>,
    ) -> Option<(SigScript, Option<Witness>)> {
        match self {
            Self::Script(d) => d.legacy_witness(keysigs, redeem_script.clone(), witness_script),
            Self::Multi(d) => d.legacy_witness(keysigs, redeem_script.clone(), witness_script),
            Self::SortedMulti(d) => {
                d.legacy_witness(keysigs, redeem_script.clone(), witness_script)
            }
        }
    }

    fn taproot_witness(
        &self,
        cb: Option<&ControlBlock>,
        keysigs: IndexMap<&KeyOrigin, TaprootKeySig>,
    ) -> Option<Witness> {
        match self {
            Self::Script(d) => d.taproot_witness(cb, keysigs),
            Self::Multi(d) => d.taproot_witness(cb, keysigs),
            Self::SortedMulti(d) => d.taproot_witness(cb, keysigs),
        }
    }
}

impl<K: DeriveCompr> Display for ShWsh<K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Script(d) => Display::fmt(d, f),
            Self::Multi(d) => Display::fmt(d, f),
            Self::SortedMulti(d) => Display::fmt(d, f),
        }
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Eq, PartialEq, Hash, Debug, From)]
pub struct ShScript<K: DeriveLegacy = XpubDerivable>(ScriptDescr<OpCode, K>);

impl<K: DeriveLegacy> Derive<DerivedScript> for ShScript<K> {
    #[inline]
    fn default_keychain(&self) -> Keychain { self.0.default_keychain() }

    #[inline]
    fn keychains(&self) -> BTreeSet<Keychain> { self.0.keychains() }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = DerivedScript> {
        self.0.derive(keychain, index).map(DerivedScript::Bip13)
    }
}

impl<K: DeriveLegacy> Descriptor<K> for ShScript<K> {
    fn class(&self) -> SpkClass { SpkClass::P2sh }

    fn keys<'a>(&'a self) -> impl Iterator<Item = &'a K>
    where K: 'a {
        self.0.keys()
    }
    fn vars<'a>(&'a self) -> impl Iterator<Item = &'a ()>
    where (): 'a {
        iter::empty()
    }
    fn xpubs(&self) -> impl Iterator<Item = &XpubAccount> { self.keys().map(K::xpub_spec) }

    fn legacy_keyset(&self, terminal: Terminal) -> IndexMap<LegacyPk, KeyOrigin> {
        self.keys()
            .map(|xkey| {
                let key = xkey
                    .derive(terminal.keychain, terminal.index)
                    .next()
                    .expect("xkey derivation is empty");
                (key, KeyOrigin::with(xkey.xpub_spec().origin().clone(), terminal))
            })
            .collect()
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
        debug_assert!(redeem_script.is_none(), "redeemScript in Wsh descriptor must is empty");
        let mut stack = vec![];
        for item in &self.0.satisfaction {
            match item {
                WitnessItem::Signature(origin) => {
                    let Some(src) = keysigs.get(origin) else {
                        break;
                    };
                    stack.push(src.sig.to_vec());
                }
                WitnessItem::Data(data) => stack.push(data.clone()),
            }
        }
        stack.push(witness_script?.into_inner().into_vec());
        Some((SigScript::new(), Some(Witness::from_consensus_stack(stack))))
    }

    fn taproot_witness(
        &self,
        _cb: Option<&ControlBlock>,
        _keysigs: IndexMap<&KeyOrigin, TaprootKeySig>,
    ) -> Option<Witness> {
        None
    }
}

impl<K: DeriveLegacy> Display for ShScript<K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { write!(f, "sh({})", self.0) }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Eq, PartialEq, Hash, Debug, From)]
pub struct WshScript<K: DeriveCompr = XpubDerivable>(ScriptDescr<OpCode, K>);

impl<K: DeriveCompr> Derive<DerivedScript> for WshScript<K> {
    #[inline]
    fn default_keychain(&self) -> Keychain { self.0.default_keychain() }

    #[inline]
    fn keychains(&self) -> BTreeSet<Keychain> { self.0.keychains() }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = DerivedScript> {
        self.0.derive(keychain, index).map(DerivedScript::Segwit)
    }
}

impl<K: DeriveCompr> Descriptor<K> for WshScript<K> {
    fn class(&self) -> SpkClass { SpkClass::P2wsh }

    fn keys<'a>(&'a self) -> impl Iterator<Item = &'a K>
    where K: 'a {
        self.0.keys()
    }
    fn vars<'a>(&'a self) -> impl Iterator<Item = &'a ()>
    where (): 'a {
        iter::empty()
    }
    fn xpubs(&self) -> impl Iterator<Item = &XpubAccount> { self.keys().map(K::xpub_spec) }

    fn legacy_keyset(&self, terminal: Terminal) -> IndexMap<LegacyPk, KeyOrigin> {
        self.keys()
            .map(|xkey| {
                let key = xkey
                    .derive(terminal.keychain, terminal.index)
                    .next()
                    .expect("xkey derivation is empty");
                (key.into(), KeyOrigin::with(xkey.xpub_spec().origin().clone(), terminal))
            })
            .collect()
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

        let mut stack = vec![];
        for item in &self.0.satisfaction {
            match item {
                WitnessItem::Signature(origin) => {
                    let Some(src) = keysigs.get(origin) else {
                        break;
                    };
                    stack.push(src.sig.to_vec());
                }
                WitnessItem::Data(data) => stack.push(data.clone()),
            }
        }
        stack.push(witness_script?.into_inner().into_vec());
        Some((SigScript::new(), Some(Witness::from_consensus_stack(stack))))
    }

    fn taproot_witness(
        &self,
        _cb: Option<&ControlBlock>,
        _keysigs: IndexMap<&KeyOrigin, TaprootKeySig>,
    ) -> Option<Witness> {
        None
    }
}

impl<K: DeriveCompr> Display for WshScript<K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { write!(f, "wsh({})", self.0) }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Eq, PartialEq, Hash, Debug, From)]
pub struct ShWshScript<K: DeriveCompr = XpubDerivable>(ScriptDescr<OpCode, K>);

impl<K: DeriveCompr> Derive<DerivedScript> for ShWshScript<K> {
    #[inline]
    fn default_keychain(&self) -> Keychain { self.0.default_keychain() }

    #[inline]
    fn keychains(&self) -> BTreeSet<Keychain> { self.0.keychains() }

    fn derive(
        &self,
        keychain: impl Into<Keychain>,
        index: impl Into<NormalIndex>,
    ) -> impl Iterator<Item = DerivedScript> {
        self.0.derive(keychain, index).map(DerivedScript::NestedScript)
    }
}

impl<K: DeriveCompr> Descriptor<K> for ShWshScript<K> {
    fn class(&self) -> SpkClass { SpkClass::P2sh }

    fn keys<'a>(&'a self) -> impl Iterator<Item = &'a K>
    where K: 'a {
        self.0.keys()
    }
    fn vars<'a>(&'a self) -> impl Iterator<Item = &'a ()>
    where (): 'a {
        iter::empty()
    }
    fn xpubs(&self) -> impl Iterator<Item = &XpubAccount> { self.keys().map(K::xpub_spec) }

    fn legacy_keyset(&self, terminal: Terminal) -> IndexMap<LegacyPk, KeyOrigin> {
        self.keys()
            .map(|xkey| {
                let key = xkey
                    .derive(terminal.keychain, terminal.index)
                    .next()
                    .expect("xkey derivation is empty");
                (key.into(), KeyOrigin::with(xkey.xpub_spec().origin().clone(), terminal))
            })
            .collect()
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
        if redeem_script.is_none() {
            return None;
        }

        let mut stack = vec![];
        for item in &self.0.satisfaction {
            match item {
                WitnessItem::Signature(origin) => {
                    let Some(src) = keysigs.get(origin) else {
                        break;
                    };
                    stack.push(src.sig.to_vec());
                }
                WitnessItem::Data(data) => stack.push(data.clone()),
            }
        }
        stack.push(witness_script?.into_inner().into_vec());

        let sig_script = SigScript::from_checked(redeem_script?.into_inner().into_vec());
        Some((sig_script, Some(Witness::from_consensus_stack(stack))))
    }

    fn taproot_witness(
        &self,
        _cb: Option<&ControlBlock>,
        _keysigs: IndexMap<&KeyOrigin, TaprootKeySig>,
    ) -> Option<Witness> {
        None
    }
}

impl<K: DeriveCompr> Display for ShWshScript<K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { write!(f, "sh(wsh({}))", self.0) }
}
