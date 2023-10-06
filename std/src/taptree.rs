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

use std::ops::Deref;
use std::{slice, vec};

use amplify::num::u7;
use bc::{LeafScript, TapScript};
use commit_verify::mpc::MerkleBuoy;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Error, From)]
pub enum InvalidTree {
    #[from]
    #[display(doc_comments)]
    Unfinalized(UnfinalizedTree),

    #[from(FinalizedTree)]
    #[display("tap tree contains too many script leafs which doesn't fit a single Merkle tree")]
    MountainRange,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display("can't add more leafs to an already finalized tap tree")]
pub struct FinalizedTree;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(
    "unfinalized tap tree containing leafs at level {0} which can't commit into a single Merkle \
     root"
)]
pub struct UnfinalizedTree(pub u7);

#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct TapTreeBuilder {
    leafs: Vec<LeafInfo>,
    buoy: MerkleBuoy<u7>,
    finalized: bool,
}

impl TapTreeBuilder {
    pub fn new() -> Self { Self::default() }

    pub fn is_finalized(&self) -> bool { self.finalized }

    pub fn push_leaf(&mut self, leaf: LeafInfo) -> Result<bool, FinalizedTree> {
        if self.finalized {
            return Err(FinalizedTree);
        }
        let depth = leaf.depth;
        self.leafs.push(leaf);
        if self.buoy.push(depth) {
            self.finalized = true
        }
        Ok(self.finalized)
    }

    pub fn finish(self) -> Result<TapTree, UnfinalizedTree> {
        if !self.finalized {
            return Err(UnfinalizedTree(self.buoy.level()));
        }
        Ok(TapTree(self.leafs))
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Default)]
#[cfg_attr(feature = "serde", derive(Serialize), serde(crate = "serde_crate", transparent))]
pub struct TapTree(Vec<LeafInfo>);

impl Deref for TapTree {
    type Target = Vec<LeafInfo>;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl IntoIterator for TapTree {
    type Item = LeafInfo;
    type IntoIter = vec::IntoIter<LeafInfo>;

    fn into_iter(self) -> Self::IntoIter { self.0.into_iter() }
}

impl<'a> IntoIterator for &'a TapTree {
    type Item = &'a LeafInfo;
    type IntoIter = slice::Iter<'a, LeafInfo>;

    fn into_iter(self) -> Self::IntoIter { self.0.iter() }
}

impl TapTree {
    pub fn from_leafs(leafs: impl IntoIterator<Item = LeafInfo>) -> Result<Self, InvalidTree> {
        let mut builder = TapTreeBuilder::new();
        for leaf in leafs {
            builder.push_leaf(leaf)?;
        }
        builder.finish().map_err(InvalidTree::from)
    }

    pub fn from_builder(builder: TapTreeBuilder) -> Result<Self, UnfinalizedTree> {
        builder.finish()
    }

    pub fn into_vec(self) -> Vec<LeafInfo> { self.0 }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct LeafInfo {
    pub depth: u7,
    pub script: LeafScript,
}

impl LeafInfo {
    pub fn tap_script(depth: u7, script: TapScript) -> Self {
        LeafInfo {
            depth,
            script: LeafScript::from_tap_script(script),
        }
    }
}
