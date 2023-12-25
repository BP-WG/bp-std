// RGB wallet library for smart contracts on Bitcoin & Lightning network
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
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

use std::collections::BTreeMap;

use amplify::confinement::{Confined, U32};
use amplify::num::u5;
use amplify::{confinement, FromSliceError};
use commit_verify::mpc::{self, Commitment, Message, ProtocolId, MPC_MINIMAL_DEPTH};
use commit_verify::{CommitmentId, TryCommitVerify};
use derive::ByteStr;
use strict_encoding::StrictSerialize;

use crate::{KeyAlreadyPresent, KeyMap, Output, PropKey, ValueData};

/// PSBT proprietary key prefix used for MPC commitment-related data.
pub const PSBT_MPC_PREFIX: &str = "MPC";

/// Proprietary key subtype for storing MPC single commitment message under
/// some protocol in global map.
pub const PSBT_OUT_MPC_MESSAGE: u64 = 0x00;
/// Proprietary key subtype for storing MPC entropy constant.
pub const PSBT_OUT_MPC_ENTROPY: u64 = 0x01;
/// Proprietary key subtype for storing MPC requirement for a minimal tree
/// size.
pub const PSBT_OUT_MPC_MIN_TREE_DEPTH: u64 = 0x04;
/// The final multi-protocol commitment value.
pub const PSBT_OUT_MPC_COMMITMENT: u64 = 0x10;
/// The multi-protocol commitment proof.
pub const PSBT_OUT_MPC_PROOF: u64 = 0x11;

impl PropKey {
    /// Constructs [`PSBT_OUT_MPC_MESSAGE`] proprietary key.
    fn mpc_message(protocol_id: ProtocolId) -> PropKey {
        PropKey {
            identifier: PSBT_MPC_PREFIX.to_owned(),
            subtype: PSBT_OUT_MPC_MESSAGE,
            data: ByteStr::from(protocol_id.to_vec()),
        }
    }

    /// Constructs [`PSBT_OUT_MPC_ENTROPY`] proprietary key.
    fn mpc_entropy() -> PropKey {
        PropKey {
            identifier: PSBT_MPC_PREFIX.to_owned(),
            subtype: PSBT_OUT_MPC_ENTROPY,
            data: empty!(),
        }
    }

    /// Constructs [`PSBT_OUT_MPC_MIN_TREE_DEPTH`] proprietary key.
    fn mpc_min_tree_depth() -> PropKey {
        PropKey {
            identifier: PSBT_MPC_PREFIX.to_owned(),
            subtype: PSBT_OUT_MPC_MIN_TREE_DEPTH,
            data: empty!(),
        }
    }

    /// Constructs [`PSBT_OUT_MPC_COMMITMENT`] proprietary key.
    fn mpc_commitment() -> PropKey {
        PropKey {
            identifier: PSBT_MPC_PREFIX.to_owned(),
            subtype: PSBT_OUT_MPC_COMMITMENT,
            data: empty!(),
        }
    }

    /// Constructs [`PSBT_OUT_MPC_PROOF`] proprietary key.
    fn mpc_proof() -> PropKey {
        PropKey {
            identifier: PSBT_MPC_PREFIX.to_owned(),
            subtype: PSBT_OUT_MPC_PROOF,
            data: empty!(),
        }
    }
}

/// Errors processing MPC-related proprietary PSBT keys and their values.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum MpcPsbtError {
    /// the key contains invalid value.
    #[from(FromSliceError)]
    InvalidKeyValue,

    /// message map produced from PSBT inputs exceeds maximum size bounds.
    #[from]
    MessageMapTooLarge(confinement::Error),

    #[from(KeyAlreadyPresent)]
    KeyAlreadyPresent,

    /// output already contains commitment; there must be a single commitment
    /// per output.
    OutputAlreadyHasCommitment,

    #[from]
    #[display(inner)]
    Mpc(mpc::Error),

    /// multi-protocol commitment is already finalized.
    Finalized,
}

/// Extension trait for [`Output`] for working with proprietary MPC
/// keys.
impl Output {
    /// Returns [`mpc::MessageMap`] constructed from the proprietary key
    /// data.
    pub fn mpc_message_map(&self) -> Result<mpc::MessageMap, MpcPsbtError> {
        let map = self
            .proprietary
            .iter()
            .filter(|(key, _)| {
                key.identifier == PSBT_MPC_PREFIX && key.subtype == PSBT_OUT_MPC_MESSAGE
            })
            .map(|(key, val)| {
                Ok((ProtocolId::copy_from_slice(&key.data)?, Message::copy_from_slice(val)?))
            })
            .collect::<Result<BTreeMap<_, _>, MpcPsbtError>>()?;
        Confined::try_from(map).map_err(MpcPsbtError::from)
    }

    /// Returns a valid LNPBP-4 [`Message`] associated with the given
    /// [`ProtocolId`], if any.
    ///
    /// We do not error on invalid data in order to support future update of
    /// this proprietary key to a standard one. In this case, the invalid
    /// data will be filtered at the moment of PSBT deserialization and this
    /// function will return `None` only in situations when the key is absent.
    pub fn mpc_message(&self, protocol_id: ProtocolId) -> Option<Message> {
        let key = PropKey::mpc_message(protocol_id);
        let data = self.proprietary(&key)?;
        Message::copy_from_slice(data).ok()
    }

    /// Returns a valid LNPBP-4 entropy value, if present.
    ///
    /// We do not error on invalid data in order to support future update of
    /// this proprietary key to a standard one. In this case, the invalid
    /// data will be filtered at the moment of PSBT deserialization and this
    /// function will return `None` only in situations when the key is absent.
    pub fn mpc_entropy(&self) -> Option<u64> {
        let key = PropKey::mpc_entropy();
        let data = self.proprietary(&key)?;
        if data.len() != 8 {
            return None;
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(data);
        Some(u64::from_le_bytes(buf))
    }

    /// Returns a valid LNPBP-4 minimal tree depth value, if present.
    ///
    /// # Errors
    ///
    /// If the key is present, but it's value can't be deserialized as a valid
    /// minimal tree depth value.
    pub fn mpc_min_tree_depth(&self) -> Option<u8> {
        let key = PropKey::mpc_min_tree_depth();
        let data = self.proprietary(&key)?;
        if data.len() != 1 {
            return None;
        }
        Some(data[0])
    }

    /// Sets MPC [`Message`] for the given [`ProtocolId`].
    ///
    /// # Returns
    ///
    /// `true`, if the message was set successfully, `false` if this message was
    /// already present for this protocol.
    ///
    /// # Errors
    ///
    /// If the key for the given [`ProtocolId`] is already present and the
    /// message is different.
    pub fn set_mpc_message(
        &mut self,
        protocol_id: ProtocolId,
        message: Message,
    ) -> Result<bool, MpcPsbtError> {
        if self.has_proprietary(&PropKey::mpc_commitment()) {
            return Err(MpcPsbtError::Finalized);
        }
        let key = PropKey::mpc_message(protocol_id);
        let val = message.to_vec();
        if let Some(v) = self.proprietary(&key) {
            if v.as_slice() != val {
                return Err(MpcPsbtError::InvalidKeyValue);
            }
            return Ok(false);
        }
        self.push_proprietary(key, val)?;
        Ok(true)
    }

    /// Sets MPC entropy value.
    ///
    /// # Returns
    ///
    /// `true`, if the entropy was set successfully, `false` if this entropy
    /// value was already set.
    ///
    /// # Errors
    ///
    /// If the entropy was already set with a different value than the provided
    /// one.
    pub fn set_mpc_entropy(&mut self, entropy: u64) -> Result<bool, MpcPsbtError> {
        if self.has_proprietary(&PropKey::mpc_commitment()) {
            return Err(MpcPsbtError::Finalized);
        }
        let key = PropKey::mpc_entropy();
        let val = entropy.to_le_bytes().to_vec();
        if let Some(v) = self.proprietary.get(&key) {
            if v.as_slice() != val {
                return Err(MpcPsbtError::InvalidKeyValue);
            }
            return Ok(false);
        }
        self.push_proprietary(key, val)?;
        Ok(true)
    }

    /// Sets MPC min tree depth value.
    ///
    /// # Returns
    ///
    /// Previous minimal tree depth value, if it was present and valid - or None
    /// if the value was absent or invalid (the new value is still assigned).
    pub fn set_mpc_min_tree_depth(&mut self, min_depth: u8) -> Result<Option<u8>, MpcPsbtError> {
        if self.has_proprietary(&PropKey::mpc_commitment()) {
            return Err(MpcPsbtError::Finalized);
        }
        let key = PropKey::mpc_min_tree_depth();
        let val = vec![min_depth];
        let prev = self.mpc_min_tree_depth();
        self.push_proprietary(key, val)?;
        Ok(prev)
    }

    pub fn mpc_commit(&mut self) -> Result<(Commitment, mpc::MerkleBlock), MpcPsbtError> {
        let messages = self.mpc_message_map()?;
        let min_depth = self.mpc_min_tree_depth().map(u5::with).unwrap_or(MPC_MINIMAL_DEPTH);
        let source = mpc::MultiSource {
            min_depth,
            messages,
            static_entropy: self.mpc_entropy(),
        };
        let merkle_tree = mpc::MerkleTree::try_commit(&source)?;
        let entropy = merkle_tree.entropy();
        self.set_mpc_entropy(entropy)?;
        let commitment = merkle_tree.commitment_id();
        let mpc_proof = mpc::MerkleBlock::from(merkle_tree);

        self.push_proprietary(PropKey::mpc_commitment(), commitment)
            .and_then(|_| self.push_proprietary(PropKey::mpc_proof(), &mpc_proof))
            .map_err(|_| MpcPsbtError::OutputAlreadyHasCommitment)?;

        Ok((commitment, mpc_proof))
    }
}

impl From<&mpc::MerkleBlock> for ValueData {
    fn from(proof: &mpc::MerkleBlock) -> Self {
        let val = proof.to_strict_serialized::<U32>().expect("max length");
        ByteStr::from(val).into()
    }
}

impl From<Commitment> for ValueData {
    fn from(value: Commitment) -> Self { ValueData::from(value.to_vec()) }
}
