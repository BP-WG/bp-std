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

//! Processing proprietary PSBT keys related to OP_RETURN (or opret)
//! commitments.
//!
//! NB: Wallets supporting opret commitments must do that through the use of
//! deterministic bitcoin commitments crate (`bp-dpc`) in order to ensure
//! that multiple protocols can put commitment inside the same transaction
//! without collisions between them.
//!
//! This module provides support for marking PSBT outputs which may host
//! opret commitment and populating PSBT with the data related to opret
//! commitments.

use bp::dbc::opret::OpretProof;
use bp::opcodes::{OP_PUSHBYTES_0, OP_PUSHBYTES_32, OP_RETURN};
use bp::ScriptPubkey;
use commit_verify::mpc;

use crate::{KeyMap, Output, PropKey, Psbt, ValueData};

/// PSBT proprietary key prefix used for opret commitment.
pub const PSBT_OPRET_PREFIX: &str = "OPRET";

/// Proprietary key subtype marking PSBT outputs which may host opret
/// commitment.
pub const PSBT_OUT_OPRET_HOST: u64 = 0x00;
/// Proprietary key subtype holding 32-byte commitment which will be put into
/// opret data.
pub const PSBT_OUT_OPRET_COMMITMENT: u64 = 0x01;

/// Extension trait for static functions returning opret-related proprietary
/// keys.
impl PropKey {
    /// Constructs [`PSBT_OUT_OPRET_HOST`] proprietary key.
    pub fn opret_host() -> PropKey {
        PropKey {
            identifier: PSBT_OPRET_PREFIX.to_owned(),
            subtype: PSBT_OUT_OPRET_HOST,
            data: none!(),
        }
    }

    /// Constructs [`PSBT_OUT_OPRET_COMMITMENT`] proprietary key.
    pub fn opret_commitment() -> PropKey {
        PropKey {
            identifier: PSBT_OPRET_PREFIX.to_owned(),
            subtype: PSBT_OUT_OPRET_COMMITMENT,
            data: none!(),
        }
    }
}

impl Psbt {
    pub fn opret_hosts(&self) -> impl Iterator<Item = &Output> {
        self.outputs.iter().filter(|o| o.is_opret_host())
    }

    pub fn opret_hosts_mut(&mut self) -> impl Iterator<Item = &mut Output> {
        self.outputs.iter_mut().filter(|o| o.is_opret_host())
    }
}

/// Errors processing opret-related proprietary PSBT keys and their values.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum OpretKeyError {
    /// output already contains commitment; there must be a single commitment
    /// per output.
    OutputAlreadyHasCommitment,

    /// the output can't host a commitment since it does not contain OP_RETURN
    /// script
    NonOpReturnOutput,

    /// the output is not marked to host opret commitments. Please first set
    /// PSBT_OUT_OPRET_HOST flag.
    OpretProhibited,

    /// the output contains no valid opret commitment.
    NoCommitment,

    /// the value of opret commitment has invalid length.
    InvalidCommitment,

    /// the script format doesn't match requirements for opret commitment.
    InvalidOpReturnScript,
}

impl Output {
    fn is_valid_opret_script(&self) -> bool {
        matches!(&self.script.as_slice(), &[] | &[OP_RETURN] | &[OP_RETURN, OP_PUSHBYTES_0])
    }
    fn has_final_opret_script(&self, data: impl AsRef<[u8]>) -> bool {
        self.script.len() == 34
            && self.script[0] == OP_RETURN
            && self.script[1] == OP_PUSHBYTES_32
            && &self.script[2..] == data.as_ref()
    }

    /// Returns whether this output may contain opret commitment. This is
    /// detected by the presence of [`PSBT_OUT_OPRET_HOST`] key.
    #[inline]
    pub fn is_opret_host(&self) -> bool {
        self.has_proprietary(&PropKey::opret_host()) && self.is_valid_opret_script()
    }

    /// Allows opret commitments for this output. Returns whether opret
    /// commitments were enabled before.
    ///
    /// # Errors
    ///
    /// If output script is not OP_RETURN script
    #[inline]
    pub fn set_opret_host(&mut self) -> Result<bool, OpretKeyError> {
        if !self.is_valid_opret_script() {
            return Err(OpretKeyError::NonOpReturnOutput);
        }
        Ok(self.push_proprietary(PropKey::opret_host(), vec![]).is_err())
    }

    /// Detects presence of a valid [`PSBT_OUT_OPRET_COMMITMENT`].
    ///
    /// If [`PSBT_OUT_OPRET_COMMITMENT`] is absent or its value is invalid,
    /// returns `false`. In the future, when `PSBT_OUT_OPRET_COMMITMENT` will
    /// become a standard and non-custom key, PSBTs with invalid key values
    /// will error at deserialization and this function will return `false`
    /// only in cases when the output does not have
    /// `PSBT_OUT_OPRET_COMMITMENT`.
    ///
    /// # Errors
    ///
    /// If output script is not OP_RETURN script
    pub fn has_opret_commitment(&self) -> Result<bool, OpretKeyError> {
        if !self.script.is_op_return() {
            return Err(OpretKeyError::NonOpReturnOutput);
        }
        if let Some(data) = self.proprietary(&PropKey::opret_commitment()) {
            if !self.has_final_opret_script(data) {
                return Err(OpretKeyError::InvalidOpReturnScript);
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Returns valid opret commitment from the [`PSBT_OUT_OPRET_COMMITMENT`]
    /// key, if present. If the commitment is absent or invalid, returns
    /// [`OpretKeyError::NoCommitment`].
    ///
    /// We do not error on invalid commitments in order to support future update
    /// of this proprietary key to the standard one. In this case, the
    /// invalid commitments (having non-32 bytes) will be filtered at the
    /// moment of PSBT deserialization and this function will return `None`
    /// only in situations when the commitment is absent.
    ///
    /// # Errors
    ///
    /// If output script is not a valid opret host script.
    pub fn opret_commitment(&self) -> Result<mpc::Commitment, OpretKeyError> {
        if !self.has_opret_commitment()? {
            return Err(OpretKeyError::NonOpReturnOutput);
        }
        let data =
            self.proprietary(&PropKey::opret_commitment()).ok_or(OpretKeyError::NoCommitment)?;
        mpc::Commitment::copy_from_slice(data.as_slice())
            .map_err(|_| OpretKeyError::InvalidCommitment)
    }

    /// Assigns value of the opreturn commitment to this PSBT output, by
    /// adding [`PSBT_OUT_OPRET_COMMITMENT`] proprietary key containing the
    /// 32-byte commitment as its value. Also modifies the output script and removes
    /// [`PSBT_OUT_OPRET_HOST`] key.
    ///
    /// Opret commitment can be set only once.
    ///
    /// Errors with [`OpretKeyError::OutputAlreadyHasCommitment`] if the
    /// commitment is already present in the output.
    ///
    /// # Errors
    ///
    /// If output script is not OP_RETURN script or opret commitments are not
    /// enabled for this output.
    pub fn opret_commit(&mut self, commitment: mpc::Commitment) -> Result<(), OpretKeyError> {
        if !self.is_opret_host() {
            return Err(OpretKeyError::OpretProhibited);
        }

        self.script = ScriptPubkey::op_return(&commitment.to_byte_array());
        self.push_proprietary(PropKey::opret_commitment(), commitment)
            .map_err(|_| OpretKeyError::OutputAlreadyHasCommitment)?;
        self.remove_proprietary(&PropKey::opret_host());
        Ok(())
    }
}

impl From<&OpretProof> for ValueData {
    fn from(_: &OpretProof) -> Self { ValueData::default() }
}
