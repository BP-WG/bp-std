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

pub struct TrKey<K: DeriveXOnly = XpubDescriptor>(K);

/*
pub struct TrScript<K: DeriveXOnly> {
    internal_key: K,
    tap_tree: TapTree<Policy<K>>,
}
*/

impl<K: DeriveXOnly> Derive<ScriptPubkey> for TrKey<K> {
    fn derive(
        &self,
        change: impl Into<NormalIndex>,
        index: impl Into<NormalIndex>,
    ) -> ScriptPubkey {
        let internal_key = self.0.derive(change, index);
        ScriptPubkey::p2tr_key_only(internal_key)
    }
}

pub enum DescriptorStd<S: DeriveSet = XpubDescriptor> {
    TrKey(TrKey<S::XOnly>),
}

impl<S: DeriveSet> Derive<ScriptPubkey> for DescriptorStd<S> {
    fn derive(
        &self,
        change: impl Into<NormalIndex>,
        index: impl Into<NormalIndex>,
    ) -> ScriptPubkey {
        match self {
            DescriptorStd::TrKey(d) => d.derive(change, index),
        }
    }
}
