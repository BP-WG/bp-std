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

use std::fmt::{self, Display, Formatter, Write};
use std::ops::Deref;
use std::{slice, vec};

use amplify::num::u7;
use crate::amplify::ByteArray;

use bc::{
    ControlBlock, InternalPk, LeafScript, OutputPk, Parity, TapBranchHash, TapLeafHash,
    TapMerklePath, TapNodeHash, TapScript,
};
use commit_verify::merkle::MerkleBuoy;

use crate::{KeyOrigin, Terminal, XkeyOrigin};

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Error, From)]
pub enum InvalidTree {
    #[from]
    #[display(doc_comments)]
    Unfinalized(UnfinalizedTree),

    #[from(FinalizedTree)]
    #[display("tap tree contains too many script leaves which doesn't fit a single Merkle tree")]
    MountainRange,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display("can't add more leaves to an already finalized tap tree")]
pub struct FinalizedTree;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(
    "unfinalized tap tree containing leaves at level {0} which can't commit into a single Merkle \
     root"
)]
pub struct UnfinalizedTree(pub u7);

#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct TapTreeBuilder<L = LeafScript> {
    leaves: Vec<LeafInfo<L>>,
    buoy: MerkleBuoy<u7>,
    finalized: bool,
}

impl<L> TapTreeBuilder<L> {
    pub fn new() -> Self {
        Self {
            leaves: none!(),
            buoy: default!(),
            finalized: false,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            leaves: Vec::with_capacity(capacity),
            buoy: zero!(),
            finalized: false,
        }
    }

    pub fn is_finalized(&self) -> bool { self.finalized }

    pub fn with_leaf(mut self, leaf: LeafInfo<L>) -> Result<Self, FinalizedTree> {
        self.push_leaf(leaf)?;
        Ok(self)
    }

    pub fn push_leaf(&mut self, leaf: LeafInfo<L>) -> Result<bool, FinalizedTree> {
        if self.finalized {
            return Err(FinalizedTree);
        }
        let depth = leaf.depth;
        self.leaves.push(leaf);
        self.buoy.push(depth);
        if self.buoy.level() == u7::ZERO {
            self.finalized = true
        }
        Ok(self.finalized)
    }

    pub fn finish(self) -> Result<TapTree<L>, UnfinalizedTree> {
        if !self.finalized {
            return Err(UnfinalizedTree(self.buoy.level()));
        }
        Ok(TapTree(self.leaves))
    }
}

/// Non-empty taproot script tree.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(transparent)
)]
pub struct TapTree<L = LeafScript>(Vec<LeafInfo<L>>);

impl<L> Deref for TapTree<L> {
    type Target = Vec<LeafInfo<L>>;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl<L> IntoIterator for TapTree<L> {
    type Item = LeafInfo<L>;
    type IntoIter = vec::IntoIter<LeafInfo<L>>;

    fn into_iter(self) -> Self::IntoIter { self.0.into_iter() }
}

impl<'a, L> IntoIterator for &'a TapTree<L> {
    type Item = &'a LeafInfo<L>;
    type IntoIter = slice::Iter<'a, LeafInfo<L>>;

    fn into_iter(self) -> Self::IntoIter { self.0.iter() }
}

impl TapTree {
    pub fn with_single_leaf(leaf: impl Into<LeafScript>) -> TapTree {
        Self(vec![LeafInfo {
            depth: u7::ZERO,
            script: leaf.into(),
        }])
    }

    pub fn merkle_root(&self) -> TapNodeHash {
        let mut stack: Vec<(u7, TapNodeHash)> = Vec::new();

        for leaf in &self.0 {
            let leaf_hash: TapNodeHash = TapLeafHash::with_leaf_script(&leaf.script).into();
            let depth = leaf.depth;
            stack.push((depth, leaf_hash));

            while stack.len() >= 2 {
                let len = stack.len();
                let (d1, _) = stack[len - 1];
                let (d2, _) = stack[len - 2];
                if d1 != d2 {
                    break;
                }

                let (_, right) = stack.pop().unwrap();
                let (_, left) = stack.pop().unwrap();
                let parent_depth = d1 - u7::ONE;
                let parent_hash = if left.to_byte_array() < right.to_byte_array() {
                    TapBranchHash::with_nodes(left, right).into()
                } else {
                    TapBranchHash::with_nodes(right, left).into()
                };

                stack.push((parent_depth, parent_hash));
            }
        }

        debug_assert!(
            stack.len() == 1 && stack[0].0 == u7::ZERO,
            "invalid tap tree: unbalanced leaves"
        );
        stack[0].1
    }

    /// Returns the script path of leaf `index` (only sibling branch hashes are included)
    pub fn merkle_path(&self, index: usize) -> TapMerklePath {
        // [BUG 修复] 栈中存储的路径向量类型从 Vec<TapBranchHash> 改为 Vec<TapNodeHash>
        let mut stack: Vec<(u7, TapNodeHash, Vec<TapNodeHash>, bool)> = Vec::new();

        for (i, leaf) in self.0.iter().enumerate() {
            let leaf_hash: TapNodeHash = TapLeafHash::with_leaf_script(&leaf.script).into();
            let is_target = i == index;
            stack.push((leaf.depth, leaf_hash, Vec::new(), is_target));

            while stack.len() >= 2 && stack[stack.len() - 1].0 == stack[stack.len() - 2].0 {
                let (depth, hr, mut path_r, target_r) = stack.pop().unwrap();
                let (_, hl, mut path_l, target_l) = stack.pop().unwrap();

                let parent_hash: TapNodeHash = TapBranchHash::with_nodes(hl, hr).into();
                let parent_depth = depth - u7::ONE;

                // [BUG 修复] 将兄弟节点的哈希 (TapNodeHash) 存入路径，而不是父节点的分支哈希
                if target_l {
                    path_l.push(hr);
                }
                if target_r {
                    path_r.push(hl);
                }

                let parent_target = target_l || target_r;
                let parent_path = if target_l { path_l } else { path_r };

                stack.push((parent_depth, parent_hash, parent_path, parent_target));
            }
        }

        debug_assert!(stack.len() == 1, "unbalanced tap tree");
        let (_d, _h, path, _t) = stack.pop().unwrap();
        // 现在 path 是 Vec<TapNodeHash>，可以成功创建 TapMerklePath
        TapMerklePath::try_from(path).expect("path length within [0..128]")
    }
}

impl<L> TapTree<L> {
    pub fn from_leaves(leaves: impl IntoIterator<Item = LeafInfo<L>>) -> Result<Self, InvalidTree> {
        let mut builder = TapTreeBuilder::<L>::new();
        for leaf in leaves {
            builder.push_leaf(leaf)?;
        }
        builder.finish().map_err(InvalidTree::from)
    }

    pub fn from_builder(builder: TapTreeBuilder<L>) -> Result<Self, UnfinalizedTree> {
        builder.finish()
    }

    pub fn into_vec(self) -> Vec<LeafInfo<L>> { self.0 }

    pub fn map<M>(self, f: impl Fn(L) -> M) -> TapTree<M> {
        TapTree(
            self.into_iter()
                .map(|leaf| LeafInfo {
                    depth:  leaf.depth,
                    script: f(leaf.script),
                })
                .collect(),
        )
    }
}

impl<L: Display> Display for TapTree<L> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut buoy = MerkleBuoy::<u7>::default();
        let mut depth = u7::ZERO;

        for leaf in &self.0 {
            for _ in depth.into_u8()..leaf.depth.into_u8() {
                f.write_char('{')?;
            }
            buoy.push(leaf.depth);
            if depth == leaf.depth {
                f.write_char(',')?;
            }
            depth = leaf.depth;
            for _ in buoy.level().into_u8()..depth.into_u8() {
                f.write_char('}')?;
            }
            debug_assert_ne!(buoy.level(), u7::ZERO);
        }

        debug_assert_eq!(buoy.level(), u7::ZERO);
        Ok(())
    }
}

#[cfg(test)]
mod taptree_tests {
    use super::*; // TapTree, merkle_root, merkle_path
    use amplify::num::u7;
    use std::convert::TryFrom;
    use bc::{TapBranchHash, TapLeafHash, TapNodeHash, TapMerklePath, TapScript, TapCode};

    /// Construct a LeafInfo<LeafScript>: Use TapScript + TapCode
    fn make_leaf(depth: u7, ops: &[TapCode]) -> LeafInfo<LeafScript> {
        let mut ts = TapScript::new();
        for &op in ops {
            ts.push_opcode(op);
        }
        LeafInfo::tap_script(depth, ts)
    }

    #[test]
    fn single_leaf_merkle() {
                // Test with PushNum1
                let leaf = make_leaf(u7::ZERO, &[TapCode::PushNum1]);
        let tree = TapTree(vec![leaf.clone()]);

        let expected = TapNodeHash::from(TapLeafHash::with_leaf_script(&leaf.script));
        assert_eq!(tree.merkle_root(), expected);

        let empty = TapMerklePath::try_from(vec![]).unwrap();
        assert_eq!(tree.merkle_path(0), empty);
    }

    #[test]
    fn two_leaves_merkle_and_path() {
        let depth = u7::ONE;
                // The first leaf uses PushNum1, the second leaf uses PushNum2
                let l0 = make_leaf(depth, &[TapCode::PushNum1]);
                let l1 = make_leaf(depth, &[TapCode::PushNum2]);
        let tree = TapTree(vec![l0.clone(), l1.clone()]);

        let h0: TapNodeHash = TapLeafHash::with_leaf_script(&l0.script).into();
        let h1: TapNodeHash = TapLeafHash::with_leaf_script(&l1.script).into();
        let branch = TapBranchHash::with_nodes(h0, h1);
        let expected_root: TapNodeHash = branch.clone().into();
        assert_eq!(tree.merkle_root(), expected_root);

                let p0 = TapMerklePath::try_from(vec![branch.clone()]).unwrap();
        // The sibling path of leaf 0
                let p1 = TapMerklePath::try_from(vec![branch]).unwrap();
        // The sibling path of leaf 1
        assert_eq!(tree.merkle_path(0), p0);
        assert_eq!(tree.merkle_path(1), p1);
    }

    #[test]
    fn unbalanced_tree_merkle_and_path() {
        // Three-leaf imbalance：depth=[2,2,1]
        let d2 = u7::try_from(2u8).unwrap();
        let d1 = u7::ONE;
                // 前两叶都用 PushNum1，第三叶用 PushNum2
                let l0 = make_leaf(d2, &[TapCode::PushNum1]);
                let l1 = make_leaf(d2, &[TapCode::PushNum1]);
                let l2 = make_leaf(d1, &[TapCode::PushNum2]);
        let tree = TapTree(vec![l0.clone(), l1.clone(), l2.clone()]);

        let h0: TapNodeHash = TapLeafHash::with_leaf_script(&l0.script).into();
        let h1: TapNodeHash = TapLeafHash::with_leaf_script(&l1.script).into();
        let h2: TapNodeHash = TapLeafHash::with_leaf_script(&l2.script).into();
        let branch1 = TapBranchHash::with_nodes(h0, h1);
        let node1: TapNodeHash = branch1.clone().into();
        let branch2 = TapBranchHash::with_nodes(node1, h2);

        let expected_root: TapNodeHash = branch2.clone().into();
        assert_eq!(tree.merkle_root(), expected_root);

                let p01 = TapMerklePath::try_from(vec![branch1.clone(), branch2.clone()]).unwrap();
                let p2  = TapMerklePath::try_from(vec![branch2]).unwrap();

        assert_eq!(tree.merkle_path(0), p01);
        assert_eq!(tree.merkle_path(1), p01);
        assert_eq!(tree.merkle_path(2), p2);
    }
}




#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct LeafInfo<L = LeafScript> {
    pub depth: u7,
    pub script: L,
}

impl LeafInfo<LeafScript> {
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
    merkle_paths:  Vec<TapMerklePath>,
    #[getter(skip)]
    remaining:     Vec<LeafInfo<LeafScript>>,
}

impl ControlBlockFactory {
    #[inline]
    pub fn with(internal_pk: InternalPk, tap_tree: TapTree<LeafScript>) -> Self {
        let merkle_root = tap_tree.merkle_root();
        let (output_pk, parity) = internal_pk.to_output_pk(Some(merkle_root));
        let remaining_leaves = tap_tree.clone().into_vec();
        let merkle_paths = (0 .. remaining_leaves.len())
            .map(|i| tap_tree.merkle_path(i))
            .collect();
        ControlBlockFactory {
            internal_pk,
            output_pk,
            parity,
            merkle_root,
            merkle_paths,
            remaining: remaining_leaves,
        }
    }

    #[inline]
    pub fn into_remaining_leaves(self) -> Vec<LeafInfo> { self.remaining }
}

impl Iterator for ControlBlockFactory {
    type Item = (ControlBlock, LeafScript);
    fn next(&mut self) -> Option<Self::Item> {
        // Pop leaf and its path together
        let leaf = self.remaining.pop()?;
        let path = self.merkle_paths.pop()?;
        let leaf_script = leaf.script;
        // Build control block with the correct path
        let control_block = ControlBlock::with(
            leaf_script.version,
            self.internal_pk,
            self.parity,
            path,
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct TapDerivation {
    pub leaf_hashes: Vec<TapLeafHash>,
    pub origin: KeyOrigin,
}

impl TapDerivation {
    pub fn with_internal_pk(xpub_origin: XkeyOrigin, terminal: Terminal) -> Self {
        let origin = KeyOrigin::with(xpub_origin, terminal);
        TapDerivation {
            leaf_hashes: empty!(),
            origin,
        }
    }
}



#[cfg(test)]
mod control_block_factory_tests {
    use super::*; // ControlBlockFactory
    use amplify::num::u7;
    use std::convert::TryFrom;
    use crate::taptree::TapTree;
    use bc::{InternalPk, LeafVer, ScriptBytes, TapBranchHash, TapLeafHash, TapNodeHash};

    /// Fixed X-only pubkey (32×0x02)
    fn dummy_internal_pk() -> InternalPk {
        InternalPk::from_byte_array([0x02u8; 32]).unwrap()
    }

    #[test]
    fn factory_preserves_paths_and_versions() {
        let depth = u7::ONE;
        let leaves: Vec<LeafInfo<LeafScript>> = vec![
            LeafInfo {
                script: LeafScript::new(
                    LeafVer::from_consensus_u8(0xc0).unwrap(),
                    ScriptBytes::try_from(vec![10]).unwrap(),
                ),
                depth,
            },
            LeafInfo {
                script: LeafScript::new(
                    LeafVer::from_consensus_u8(0xc0).unwrap(),
                    ScriptBytes::try_from(vec![20]).unwrap(),
                ),
                depth,
            },
        ];
        let clone_leaves = leaves.clone();

        // Constructing factory and collecting
        let items: Vec<_> =
            ControlBlockFactory::with(dummy_internal_pk(), TapTree(leaves)).collect();
        assert_eq!(items.len(), clone_leaves.len());

        // Hand-Calculated Root Hash
        let h0 = TapLeafHash::with_leaf_script(&clone_leaves[0].script).into();
        let h1 = TapLeafHash::with_leaf_script(&clone_leaves[1].script).into();
        let branch = TapBranchHash::with_nodes(h0, h1);
        let expected_root: TapNodeHash = branch.clone().into();
        let tree = TapTree(clone_leaves.clone());
        assert_eq!(tree.merkle_root(), expected_root);

        // Compare the scripts & paths of each ControlBlock
        for (idx, (cb, ls)) in items.into_iter().enumerate() {
            assert_eq!(ls.version, tree.0[idx].script.version);
            let expected_path = tree.merkle_path(idx);
            assert_eq!(cb.merkle_branch, expected_path);
        }
    }
}
#[cfg(test)]
mod negative_tests {
    use super::*;
    use amplify::num::u7;
    use std::convert::TryFrom;
    use bc::{LeafScript, LeafVer, ScriptBytes};

    #[test]
    #[should_panic(expected = "unbalanced tap tree")]
    fn merkle_path_empty_tree_panics() {
        // If the merkle path is called directly on an empty tree, it will panic "unbalanced tap tree" because there is no root node.
        let empty: TapTree = TapTree(vec![]);
        let _ = empty.merkle_path(0);
    }

    #[test]
    fn tree_from_no_leaves_err() {
        let err = TapTree::from_leaves(std::iter::empty::<LeafInfo<LeafScript>>());
        assert!(matches!(err, Err(InvalidTree::Unfinalized(_))));
    }

    #[test]
    fn leaf_depth_overflow_err() {
        assert!(u7::try_from(128u8).is_err());
    }

    #[test]
    fn duplicate_leaves_nonzero_depth_ok() {
        // The same script has a depth of 1 and is repeated twice without underflow.
        let depth = u7::ONE;
        let script = LeafScript::new(
            LeafVer::from_consensus_u8(0xc0).unwrap(),
            ScriptBytes::try_from(vec![]).unwrap(),
        );
        let leaf = LeafInfo { depth, script };
        let tree = TapTree(vec![leaf.clone(), leaf.clone()]);

        // The root hash should be the result of merging two identical leaf hashes.
        let h = TapLeafHash::with_leaf_script(&leaf.script).into();
        let expected_root: TapNodeHash = TapBranchHash::with_nodes(h, h).into();
        assert_eq!(tree.merkle_root(), expected_root);

        // The corresponding two paths have only this one branch
        let expected_path = TapMerklePath::try_from(vec![TapBranchHash::with_nodes(h, h)]).unwrap();
        assert_eq!(tree.merkle_path(0), expected_path);
        assert_eq!(tree.merkle_path(1), expected_path);
    }
}
