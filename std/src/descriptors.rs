// Modern, minimalistic & standard-compliant cold wallet library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2020-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2020-2023 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2020-2023 Dr Maxim Orlovsky. All rights reserved.
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

use bc::ScriptPubkey;

use crate::{Derive, DeriveSet, DeriveXOnly, NormalIndex, XpubDescriptor};

pub trait Descriptor<K, V = ()> {
    type KeyIter<'k>: Iterator<Item = &'k K>
    where
        Self: 'k,
        K: 'k;

    type VarIter<'v>: Iterator<Item = &'v V>
    where
        Self: 'v,
        V: 'v;

    fn keys(&self) -> Self::KeyIter<'_>;
    fn vars(&self) -> Self::VarIter<'_>;
}

pub trait KeyTranslate<K, V = ()>: Descriptor<K, V> {
    type Dest<K2>: Descriptor<K2, V>;
    fn translate<K2>(&self, f: impl Fn(K) -> K2) -> Self::Dest<K2>;
}

pub trait VarResolve<K, V>: Descriptor<K, V> {
    type Dest<V2>: Descriptor<K, V2>;
    fn translate<V2>(&self, f: impl Fn(V) -> V2) -> Self::Dest<V2>;
}

#[cfg_attr(
    feature = "serde",
    cfg_eval,
    serde_as,
    derive(Serialize, Deserialize),
    serde(
        crate = "serde_crate",
        bound(
            serialize = "K: std::fmt::Display",
            deserialize = "K: std::str::FromStr, K::Err: std::fmt::Display"
        )
    )
)]
#[derive(Clone, Eq, PartialEq, Hash, Debug, From)]
pub struct TrKey<K: DeriveXOnly = XpubDescriptor>(
    #[cfg_attr(feature = "serde", serde_as(as = "serde_with::DisplayFromStr"))] K,
);

impl<K: DeriveXOnly> TrKey<K> {
    pub fn as_internal_key(&self) -> &K { &self.0 }
    pub fn into_internal_key(self) -> K { self.0 }
}

/*
pub struct TrScript<K: DeriveXOnly> {
    internal_key: K,
    tap_tree: TapTree<Policy<K>>,
}
*/

impl<K: DeriveXOnly> Derive<ScriptPubkey> for TrKey<K> {
    fn derive(
        &self,
        keychain: impl Into<NormalIndex>,
        index: impl Into<NormalIndex>,
    ) -> ScriptPubkey {
        let internal_key = self.0.derive(keychain, index);
        ScriptPubkey::p2tr_key_only(internal_key)
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        crate = "serde_crate",
        rename_all = "camelCase",
        bound(
            serialize = "S::XOnly: std::fmt::Display",
            deserialize = "S::XOnly: std::str::FromStr, <S::XOnly as std::str::FromStr>::Err: \
                           std::fmt::Display"
        )
    )
)]
pub enum DescriptorStd<S: DeriveSet = XpubDescriptor> {
    #[from]
    TrKey(TrKey<S::XOnly>),
}

impl<S: DeriveSet> Derive<ScriptPubkey> for DescriptorStd<S> {
    fn derive(
        &self,
        keychain: impl Into<NormalIndex>,
        index: impl Into<NormalIndex>,
    ) -> ScriptPubkey {
        match self {
            DescriptorStd::TrKey(d) => d.derive(keychain, index),
        }
    }
}
