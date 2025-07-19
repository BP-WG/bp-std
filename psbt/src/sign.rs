// Modern, minimalistic & standard-compliant Bitcoin library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Labs, Institute for Distributed and Cognitive Systems (InDCS).
// Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
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

use std::borrow::Borrow;

use derive::{Bip340Sig, LegacySig, SighashCache, SighashError, Sign, Tx, TxOut, Txid};

use crate::{Input, Psbt};

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display("the transaction was rejected by the signer.")]
pub struct Rejected;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum SignError {
    /// the transaction was rejected by the signer.
    #[from(Rejected)]
    Rejected,

    /// transaction {txid} input {index} uses SIGHASH_SINGLE, but the total
    /// number of outputs is {outputs} and thus no signature can be produced.
    SighashOnlyMismatch {
        txid: Txid,
        index: usize,
        outputs: usize,
    },
}

impl From<SighashError> for SignError {
    fn from(err: SighashError) -> Self {
        match err {
            SighashError::InvalidInputIndex { .. } => unreachable!(
                "sign PSBT algorithm ensures that we iterate only over existing input indexes"
            ),
            SighashError::NoSingleOutputMatch {
                txid,
                index,
                outputs,
            } => Self::SighashOnlyMismatch {
                txid,
                index,
                outputs,
            },
        }
    }
}

/// Trait which should be implemented by all signers.
///
/// Signers must ensure that the transaction is checked by the user when they get
/// [`Signer::approve`] callback.
// TODO: Add when implemented
// If the transaction passes the check, they must provide the caller
// with [`Satisfier`] instance, responsible for selecting specific script paths and keys for the
// signing.
pub trait Signer {
    /// Type which does the actual signatures. See [`Sign`] trait for the details.
    type Sign<'s>: Sign
    where Self: 's;

    /// In the implementation of this method signers must ensure that transaction is checked by the
    /// user.
    // TODO: Add when implemented
    // If the transaction passes the check, they must provide the caller
    // with [`Satisfier`] instance, responsible for selecting specific script paths and keys for the
    // signing.
    fn approve(&self, psbt: &Psbt) -> Result<Self::Sign<'_>, Rejected>;
}

impl Psbt {
    /// Signs PSBT using the given `signer`. The signer determines whether the
    /// transaction should be accepted by the user and which script paths
    /// and keys should be used for signing for each of the inputs.
    ///
    /// See [`Signer`] and [`Sign`] traits for details on how the interaction with `signer`
    /// happens.
    pub fn sign(&mut self, signer: &impl Signer) -> Result<usize, SignError> {
        let satisfier = signer.approve(self)?;

        let tx = self.to_unsigned_tx();
        let prevouts = self.inputs.iter().map(Input::prev_txout).cloned().collect::<Vec<_>>();
        let mut sig_hasher = SighashCache::new(Tx::from(tx), prevouts)
            .expect("inputs and prevouts match algorithmically");
        let mut sig_count = 0usize;

        for input in &mut self.inputs {
            sig_count += input.sign(&satisfier, &mut sig_hasher)?;
        }

        Ok(sig_count)
    }
}

impl Input {
    fn sign<Prevout: Borrow<TxOut>>(
        &mut self,
        satisfier: &impl Sign,
        sig_hasher: &mut SighashCache<Prevout>,
    ) -> Result<usize, SighashError> {
        if self.is_bip340() {
            self.sign_bip340(satisfier, sig_hasher)
        } else {
            self.sign_ecdsa(satisfier, sig_hasher)
        }
    }

    fn sign_ecdsa<Prevout: Borrow<TxOut>>(
        &mut self,
        signer: &impl Sign,
        sig_hasher: &mut SighashCache<Prevout>,
    ) -> Result<usize, SighashError> {
        let mut signature_count = 0usize;
        let sighash_type = self.sighash_type.unwrap_or_default();
        let sighash = if self.is_segwit_v0() {
            let Some(script_code) = self.script_code() else {
                return Ok(0);
            };

            sig_hasher.segwit_sighash(
                self.index,
                &script_code,
                self.prevout().value,
                sighash_type,
            )?
        } else {
            sig_hasher.legacy_sighash(self.index, &self.prev_txout().script_pubkey, sighash_type)?
        };
        for (pk, origin) in &self.bip32_derivation {
            let Some(sig) = signer.sign_ecdsa(sighash, *pk, Some(origin)) else {
                continue;
            };
            self.partial_sigs.insert(*pk, LegacySig { sig, sighash_type });
            signature_count += 1;
        }
        Ok(signature_count)
    }

    fn sign_bip340<Prevout: Borrow<TxOut>>(
        &mut self,
        signer: &impl Sign,
        sig_hasher: &mut SighashCache<Prevout>,
    ) -> Result<usize, SighashError> {
        let mut signature_count = 0usize;
        let sighash_type = self.sighash_type;

        // Sign all script paths
        for (control_block, leaf_script) in &self.tap_leaf_script {
            let tapleaf_hash = leaf_script.tap_leaf_hash();

            if !signer.should_sign_script_path(
                self.index,
                &control_block.merkle_branch,
                tapleaf_hash,
            ) {
                continue;
            }

            let sighash = sig_hasher.tap_sighash_script(
                self.index,
                leaf_script.tap_leaf_hash(),
                sighash_type,
            )?;

            for (pk, tap) in &self.tap_bip32_derivation {
                if !tap.leaf_hashes.contains(&tapleaf_hash) {
                    continue;
                }
                let Some(sig) = signer.sign_bip340_script_path(sighash, *pk, Some(&tap.origin))
                else {
                    continue;
                };
                let sig = Bip340Sig { sig, sighash_type };
                self.tap_script_sig.insert((*pk, tapleaf_hash), sig);
                signature_count += 1;
            }
        }

        // Sign keypath
        if !signer.should_sign_key_path(self.index) {
            return Ok(signature_count);
        }
        let Some(internal_key) = self.tap_internal_key else {
            return Ok(signature_count);
        };
        let derivation = self.tap_bip32_derivation.get(&internal_key.to_xonly_pk());
        let sighash = sig_hasher.tap_sighash_key(self.index, sighash_type)?;
        let Some(sig) = signer.sign_bip340_key_only(
            sighash,
            internal_key,
            derivation.map(|d| &d.origin),
            self.tap_merkle_root,
        ) else {
            return Ok(signature_count);
        };
        let sig = Bip340Sig { sig, sighash_type };
        self.tap_key_sig = Some(sig);
        signature_count += 1;

        Ok(signature_count)
    }
}
