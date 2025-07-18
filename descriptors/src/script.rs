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
    ControlBlock, Derive, DeriveCompr, DeriveLegacy, DeriveXOnly, DerivedScript, KeyOrigin,
    Keychain, LeafScript, LegacyPk, NormalIndex, OpCode, RedeemScript, ScriptPubkey, SigScript,
    TapCode, TapDerivation, TapScript, Terminal, Witness, WitnessScript, XOnlyPk, XkeyOrigin,
    XpubAccount, XpubDerivable,
};
use indexmap::IndexMap;

use crate::{Descriptor, LegacyKeySig, SpkClass, TaprootKeySig};

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

impl<K: DeriveCompr> Display for WshScript<K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { write!(f, "wsh({})", self.0) }
}
