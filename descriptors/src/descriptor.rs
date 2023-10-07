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

use std::ops::Range;
use std::{iter, vec};

use bpstd::{
    CompressedPk, Derive, DeriveCompr, DeriveScripts, DeriveSet, DeriveXOnly, DerivedScript,
    KeyOrigin, NormalIndex, TapDerivation, TaprootPk, Terminal, XpubDerivable, XpubSpec,
};
use indexmap::IndexMap;

use crate::{TrKey, Wpkh};

pub trait Descriptor<K = XpubDerivable, V = ()>: DeriveScripts {
    type KeyIter<'k>: Iterator<Item = &'k K>
    where
        Self: 'k,
        K: 'k;

    type VarIter<'v>: Iterator<Item = &'v V>
    where
        Self: 'v,
        V: 'v;

    type XpubIter<'x>: Iterator<Item = &'x XpubSpec>
    where Self: 'x;

    fn keys(&self) -> Self::KeyIter<'_>;
    fn vars(&self) -> Self::VarIter<'_>;
    fn xpubs(&self) -> Self::XpubIter<'_>;

    fn compr_keyset(&self, terminal: Terminal) -> IndexMap<CompressedPk, KeyOrigin>;
    fn xonly_keyset(&self, terminal: Terminal) -> IndexMap<TaprootPk, TapDerivation>;
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        crate = "serde_crate",
        rename_all = "camelCase",
        bound(
            serialize = "S::Compr: serde::Serialize, S::XOnly: serde::Serialize",
            deserialize = "S::Compr: serde::Deserialize<'de>, S::XOnly: serde::Deserialize<'de>"
        )
    )
)]
pub enum DescriptorStd<S: DeriveSet = XpubDerivable> {
    #[from]
    Wpkh(Wpkh<S::Compr>),

    #[from]
    TrKey(TrKey<S::XOnly>),
}

impl<S: DeriveSet> Derive<DerivedScript> for DescriptorStd<S> {
    fn keychains(&self) -> Range<u8> {
        match self {
            DescriptorStd::Wpkh(d) => d.keychains(),
            DescriptorStd::TrKey(d) => d.keychains(),
        }
    }

    fn derive(&self, keychain: u8, index: impl Into<NormalIndex>) -> DerivedScript {
        match self {
            DescriptorStd::Wpkh(d) => d.derive(keychain, index),
            DescriptorStd::TrKey(d) => d.derive(keychain, index),
        }
    }
}

impl<K: DeriveSet<Compr = K, XOnly = K> + DeriveCompr + DeriveXOnly> Descriptor<K>
    for DescriptorStd<K>
where Self: Derive<DerivedScript>
{
    type KeyIter<'k> = vec::IntoIter<&'k K> where Self: 'k, K: 'k;
    type VarIter<'v> = iter::Empty<&'v ()> where Self: 'v, (): 'v;
    type XpubIter<'x> = vec::IntoIter<&'x XpubSpec> where Self: 'x;

    fn keys(&self) -> Self::KeyIter<'_> {
        match self {
            DescriptorStd::Wpkh(d) => d.keys().collect::<Vec<_>>(),
            DescriptorStd::TrKey(d) => d.keys().collect::<Vec<_>>(),
        }
        .into_iter()
    }

    fn vars(&self) -> Self::VarIter<'_> { iter::empty() }

    fn xpubs(&self) -> Self::XpubIter<'_> {
        match self {
            DescriptorStd::Wpkh(d) => d.xpubs().collect::<Vec<_>>(),
            DescriptorStd::TrKey(d) => d.xpubs().collect::<Vec<_>>(),
        }
        .into_iter()
    }

    fn compr_keyset(&self, terminal: Terminal) -> IndexMap<CompressedPk, KeyOrigin> {
        match self {
            DescriptorStd::Wpkh(d) => d.compr_keyset(terminal),
            DescriptorStd::TrKey(d) => d.compr_keyset(terminal),
        }
    }

    fn xonly_keyset(&self, terminal: Terminal) -> IndexMap<TaprootPk, TapDerivation> {
        match self {
            DescriptorStd::Wpkh(d) => d.xonly_keyset(terminal),
            DescriptorStd::TrKey(d) => d.xonly_keyset(terminal),
        }
    }
}
