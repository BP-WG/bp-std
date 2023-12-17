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
use bc::{
    ControlBlock, InternalPk, LeafScript, OutputPk, Parity, TapLeafHash, TapMerklePath,
    TapNodeHash, TapScript,
};
use commit_verify::merkle::MerkleBuoy;

use crate::{KeyOrigin, Terminal, XpubOrigin};

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

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            leafs: Vec::with_capacity(capacity),
            buoy: zero!(),
            finalized: false,
        }
    }

    pub fn is_finalized(&self) -> bool { self.finalized }

    pub fn push_leaf(&mut self, leaf: LeafInfo) -> Result<bool, FinalizedTree> {
        if self.finalized {
            return Err(FinalizedTree);
        }
        let depth = leaf.depth;
        self.leafs.push(leaf);
        self.buoy.push(depth);
        if self.buoy.level() == u7::ZERO {
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

/// Non-empty taproot script tree.
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
    pub fn with_single_leaf(leaf: impl Into<LeafScript>) -> TapTree {
        Self(vec![LeafInfo {
            depth: u7::ZERO,
            script: leaf.into(),
        }])
    }

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

    pub fn merkle_root(&self) -> TapNodeHash {
        // TODO: implement TapTree::merkle_root
        todo!()
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

#[derive(Getters, Clone, Eq, PartialEq, Debug)]
#[getter(as_copy)]
pub struct ControlBlockFactory {
    internal_pk: InternalPk,
    output_pk: OutputPk,
    parity: Parity,
    merkle_root: TapNodeHash,

    #[getter(skip)]
    merkle_path: TapMerklePath,
    #[getter(skip)]
    remaining_leaves: Vec<LeafInfo>,
}

impl ControlBlockFactory {
    #[inline]
    pub fn with(internal_pk: InternalPk, tap_tree: TapTree) -> Self {
        let merkle_root = tap_tree.merkle_root();
        let (output_pk, parity) = internal_pk.to_output_pk(Some(merkle_root));
        ControlBlockFactory {
            internal_pk,
            output_pk,
            parity,
            merkle_root,
            merkle_path: empty!(),
            remaining_leaves: tap_tree.into_vec(),
        }
    }

    #[inline]
    pub fn into_remaining_leaves(self) -> Vec<LeafInfo> { self.remaining_leaves }
}

impl Iterator for ControlBlockFactory {
    type Item = (ControlBlock, LeafScript);

    fn next(&mut self) -> Option<Self::Item> {
        let leaf = self.remaining_leaves.pop()?;
        let leaf_script = leaf.script;
        let control_block = ControlBlock::with(
            leaf_script.version,
            self.internal_pk,
            self.parity,
            self.merkle_path.clone(),
        );
        Some((control_block, leaf_script))
    }
}

/// A compact size unsigned integer representing the number of leaf hashes, followed by a list
/// of leaf hashes, followed by the 4 byte master key fingerprint concatenated with the
/// derivation path of the public key. The derivation path is represented as 32-bit little
/// endian unsigned integer indexes concatenated with each other. Public keys are those needed
/// to spend this output. The leaf hashes are of the leaves which involve this public key. The
/// internal key does not have leaf hashes, so can be indicated with a hashes len of 0.
/// Finalizers should remove this field after `PSBT_IN_FINAL_SCRIPTWITNESS` is constructed.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct TapDerivation {
    pub leaf_hashes: Vec<TapLeafHash>,
    pub origin: KeyOrigin,
}

impl TapDerivation {
    pub fn with_internal_pk(xpub_origin: XpubOrigin, terminal: Terminal) -> Self {
        let origin = KeyOrigin::with(xpub_origin, terminal);
        TapDerivation {
            leaf_hashes: empty!(),
            origin,
        }
    }
}
