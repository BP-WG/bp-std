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
use derive::{
    Derive, DeriveCompr, DeriveLegacy, DeriveXOnly, KeyOrigin, Keychain, LeafScript, NormalIndex,
    OpCode, RedeemScript, TapCode, TapScript, WitnessScript, XkeyOrigin,
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
        iter::once(script.into())
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
        iter::once(script.into())
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
                        write!(f, "{}", opcode)?;
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
