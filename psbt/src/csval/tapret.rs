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

//! Processing proprietary PSBT keys related to taproot-based OP_RETURN
//! (or tapret) commitments.
//!
//! NB: Wallets supporting tapret commitments must do that through the use of
//! deterministic bitcoin commitments crate (`bp-dpc`) in order to ensure
//! that multiple protocols can put commitment inside the same transaction
//! without collisions between them.
//!
//! This module provides support for marking PSBT outputs which may host
//! tapreturn commitment and populating PSBT with the data related to tapret
//! commitments.

use amplify::confinement::{Confined, U16};
use bp::dbc::tapret::{TapretCommitment, TapretPathProof, TapretProof};
use bp::ByteStr;
use commit_verify::{mpc, CommitVerify};
use derive::{ScriptPubkey, TapScript, TapTree};
use strict_encoding::{StrictDeserialize, StrictSerialize};

use crate::{KeyMap, Output, PropKey, Psbt, ValueData};

/// PSBT proprietary key prefix used for tapreturn commitment.
pub const PSBT_TAPRET_PREFIX: &str = "TAPRET";

/// Proprietary key subtype for PSBT inputs containing the applied tapret tweak
/// information.
pub const PSBT_IN_TAPRET_TWEAK: u64 = 0x00;

/// Proprietary key subtype marking PSBT outputs which may host tapreturn
/// commitment.
pub const PSBT_OUT_TAPRET_HOST: u64 = 0x00;
/// Proprietary key subtype holding 32-byte commitment which will be put into
/// tapret tweak.
pub const PSBT_OUT_TAPRET_COMMITMENT: u64 = 0x01;
/// Proprietary key subtype holding merkle branch path to tapreturn tweak inside
/// the taptree structure.
pub const PSBT_OUT_TAPRET_PROOF: u64 = 0x02;

/// Extension trait for static functions returning tapreturn-related proprietary
/// keys.
impl PropKey {
    /// Constructs [`PSBT_IN_TAPRET_TWEAK`] proprietary key.
    pub fn tapret_tweak() -> PropKey {
        PropKey {
            identifier: PSBT_TAPRET_PREFIX.to_owned(),
            subtype: PSBT_IN_TAPRET_TWEAK,
            data: none!(),
        }
    }

    /// Constructs [`PSBT_OUT_TAPRET_HOST`] proprietary key.
    pub fn tapret_host() -> PropKey {
        PropKey {
            identifier: PSBT_TAPRET_PREFIX.to_owned(),
            subtype: PSBT_OUT_TAPRET_HOST,
            data: none!(),
        }
    }

    /// Constructs [`PSBT_OUT_TAPRET_COMMITMENT`] proprietary key.
    pub fn tapret_commitment() -> PropKey {
        PropKey {
            identifier: PSBT_TAPRET_PREFIX.to_owned(),
            subtype: PSBT_OUT_TAPRET_COMMITMENT,
            data: none!(),
        }
    }

    /// Constructs [`PSBT_OUT_TAPRET_PROOF`] proprietary key.
    pub fn tapret_proof() -> PropKey {
        PropKey {
            identifier: PSBT_TAPRET_PREFIX.to_owned(),
            subtype: PSBT_OUT_TAPRET_PROOF,
            data: none!(),
        }
    }
}

impl Psbt {
    pub fn tapret_hosts(&self) -> impl Iterator<Item = &Output> {
        self.outputs.iter().filter(|o| o.is_tapret_host())
    }

    pub fn tapret_hosts_mut(&mut self) -> impl Iterator<Item = &mut Output> {
        self.outputs.iter_mut().filter(|o| o.is_tapret_host())
    }
}

/// Errors processing tapret-related proprietary PSBT keys and their values.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum TapretKeyError {
    /// output already contains commitment; there must be a single commitment
    /// per output.
    OutputAlreadyHasCommitment,

    /// the output is not marked to host tapret commitments. Please first set
    /// PSBT_OUT_TAPRET_HOST flag.
    TapretProhibited,

    /// the provided output is not a taproot output and can't host a tapret
    /// commitment.
    NotTaprootOutput,

    /// the output contains no valid tapret commitment.
    NoCommitment,

    /// the value of tapret commitment has invalid length.
    InvalidCommitment,

    /// use of taproot script descriptors is not yet supported. You may also check the latest
    /// version of the software which may already support this feature.
    TapTreeNonEmpty,

    /// taproot output doesn't specify internal key.
    NoInternalKey,
}

impl Output {
    /// Returns whether this output may contain tapret commitment. This is
    /// detected by the presence of [`PSBT_OUT_TAPRET_HOST`] key.
    #[inline]
    pub fn is_tapret_host(&self) -> bool {
        self.has_proprietary(&PropKey::tapret_host()) && self.script.is_p2tr()
    }

    /// Allows tapret commitments for this output. Returns whether tapret
    /// commitments were enabled before.
    ///
    /// # Errors
    ///
    /// Errors with [`TapretKeyError::NotTaprootOutput`] if the output is not a
    /// taproot output.
    pub fn set_tapret_host(&mut self) -> Result<bool, TapretKeyError> {
        if !self.script.is_p2tr() {
            return Err(TapretKeyError::NotTaprootOutput);
        }
        Ok(self.push_proprietary(PropKey::tapret_host(), vec![]).is_err())
    }

    /// Detects presence of a valid [`PSBT_OUT_TAPRET_COMMITMENT`].
    ///
    /// If [`PSBT_OUT_TAPRET_COMMITMENT`] is absent or its value is invalid,
    /// returns `false`. In the future, when `PSBT_OUT_TAPRET_COMMITMENT` will
    /// become a standard and non-custom key, PSBTs with invalid key values
    /// will error at deserialization and this function will return `false`
    /// only in cases when the output does not have
    /// `PSBT_OUT_TAPRET_COMMITMENT`.
    pub fn has_tapret_commitment(&self) -> Result<bool, TapretKeyError> {
        if !self.script.is_p2tr() {
            return Err(TapretKeyError::NotTaprootOutput);
        }
        Ok(self.has_proprietary(&PropKey::tapret_commitment()))
    }

    /// Returns valid tapret commitment from the [`PSBT_OUT_TAPRET_COMMITMENT`]
    /// key, if present. If the commitment is absent or invalid, returns
    /// [`TapretKeyError::NoCommitment`].
    ///
    /// We do not error on invalid commitments in order to support future update
    /// of this proprietary key to the standard one. In this case, the
    /// invalid commitments (having non-32 bytes) will be filtered at the
    /// moment of PSBT deserialization and this function will return `None`
    /// only in situations when the commitment is absent.
    pub fn tapret_commitment(&self) -> Result<TapretCommitment, TapretKeyError> {
        if !self.script.is_p2tr() {
            return Err(TapretKeyError::NotTaprootOutput);
        }
        let data =
            self.proprietary(&PropKey::tapret_commitment()).ok_or(TapretKeyError::NoCommitment)?;
        TapretCommitment::from_strict_serialized::<U16>(
            Confined::try_from(data.to_vec()).map_err(|_| TapretKeyError::InvalidCommitment)?,
        )
        .map_err(|_| TapretKeyError::InvalidCommitment)
    }

    /// Assigns value of the tapreturn commitment to this PSBT output, by
    /// adding [`PSBT_OUT_TAPRET_COMMITMENT`] and [`PSBT_OUT_TAPRET_PROOF`]
    /// proprietary keys containing the 32-byte commitment as its proof.
    ///
    /// # Errors
    ///
    /// Errors with [`TapretKeyError::OutputAlreadyHasCommitment`] if the
    /// commitment is already present in the output, and with
    /// [`TapretKeyError::TapretProhibited`] if tapret commitments are not
    /// enabled for this output.
    pub fn tapret_commit(
        &mut self,
        commitment: mpc::Commitment,
    ) -> Result<TapretProof, TapretKeyError> {
        if !self.script.is_p2tr() {
            return Err(TapretKeyError::NotTaprootOutput);
        }
        if !self.is_tapret_host() {
            return Err(TapretKeyError::TapretProhibited);
        }

        // TODO: support non-empty tap trees
        if self.tap_tree.is_some() {
            return Err(TapretKeyError::TapTreeNonEmpty);
        }
        let nonce = 0;
        let tapret_commitment = &TapretCommitment::with(commitment, nonce);
        let script_commitment = TapScript::commit(tapret_commitment);
        let tap_tree = TapTree::with_single_leaf(script_commitment);
        let internal_pk = self.tap_internal_key.ok_or(TapretKeyError::NoInternalKey)?;
        let tapret_proof = TapretProof {
            path_proof: TapretPathProof::root(nonce),
            internal_pk,
        };

        self.push_proprietary(PropKey::tapret_commitment(), tapret_commitment)
            .and_then(|_| self.push_proprietary(PropKey::tapret_proof(), &tapret_proof))
            .map_err(|_| TapretKeyError::OutputAlreadyHasCommitment)?;

        self.script = ScriptPubkey::p2tr(internal_pk, Some(tap_tree.merkle_root()));
        self.tap_tree = Some(tap_tree);

        Ok(tapret_proof)
    }

    /// Detects presence of a valid [`PSBT_OUT_TAPRET_PROOF`].
    ///
    /// If [`PSBT_OUT_TAPRET_PROOF`] is absent or its value is invalid,
    /// returns `false`. In the future, when `PSBT_OUT_TAPRET_PROOF` will
    /// become a standard and non-custom key, PSBTs with invalid key values
    /// will error at deserialization and this function will return `false`
    /// only in cases when the output does not have `PSBT_OUT_TAPRET_PROOF`.
    pub fn has_tapret_proof(&self) -> bool { self.tapret_proof().is_some() }

    /// Returns valid tapret commitment proof from the [`PSBT_OUT_TAPRET_PROOF`]
    /// key, if present. If the commitment is absent or invalid, returns `None`.
    ///
    /// We do not error on invalid proofs in order to support future update of
    /// this proprietary key to a standard one. In this case, the invalid
    /// commitments (having non-32 bytes) will be filtered at the moment of PSBT
    /// deserialization and this function will return `None` only in situations
    /// when the commitment is absent.
    ///
    /// Function returns generic type since the real type will create dependency
    /// on `bp-dpc` crate, which will result in circular dependency with the
    /// current crate.
    pub fn tapret_proof(&self) -> Option<TapretPathProof> {
        let data = self.proprietary(&PropKey::tapret_proof())?;
        let vec = Confined::try_from_iter(data.iter().copied()).ok()?;
        TapretPathProof::from_strict_serialized::<U16>(vec).ok()
    }
}

impl From<&TapretProof> for ValueData {
    fn from(proof: &TapretProof) -> Self {
        let val = proof.to_strict_serialized::<U16>().expect("tapret proof longer than 64KB");
        ByteStr::from(val).into()
    }
}

impl From<&TapretCommitment> for ValueData {
    fn from(commitment: &TapretCommitment) -> Self {
        let val = commitment.to_strict_serialized::<U16>().expect("tapret proof longer than 64KB");
        ByteStr::from(val).into()
    }
}
