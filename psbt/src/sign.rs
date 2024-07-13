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

use std::borrow::Borrow;

use derive::{Bip340Sig, Satisfy, SighashCache, SighashError, Tx, TxOut, Txid, XOnlyPk};

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
/// Signers must ensure that transaction is checked by the user when they get [`Sign::approve`]
/// callback. If the transaction passes the check, they must provide the caller with [`Satisfier`]
/// instance, responsible for selecting specific script paths and keys for the signing.
pub trait Sign {
    /// Type which does the actual signatures. See [`Satisfy`] trait for the details.
    type Satisfier<'s>: Satisfy
    where Self: 's;

    /// In the implementation of this method signers must ensure that transaction is checked by the
    /// user. If the transaction passes the check, they must provide the caller with [`Satisfier`]
    /// instance, responsible for selecting specific script paths and keys for the signing.
    fn approve(&self, psbt: &Psbt) -> Result<Self::Satisfier<'_>, Rejected>;
}

impl Psbt {
    /// Signs PSBT using the given `signer`. The signer determines whether the
    /// transaction should be accepted by the user and which script paths
    /// and keys should be used for signing for each of the inputs.
    ///
    /// See [`Sign`] and [`Satisfy`] traits for details on how the interaction with `signer`
    /// happens.
    pub fn sign(&mut self, signer: &impl Sign) -> Result<usize, SignError> {
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
        satisfier: &impl Satisfy,
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
        _satisfier: &impl Satisfy,
        _sig_hasher: &mut SighashCache<Prevout>,
    ) -> Result<usize, SighashError> {
        todo!("Signing pre-taproot inputs is not yet implemented")
    }

    fn sign_bip340<Prevout: Borrow<TxOut>>(
        &mut self,
        satisfier: &impl Satisfy,
        sig_hasher: &mut SighashCache<Prevout>,
    ) -> Result<usize, SighashError> {
        let mut signature_count = 0usize;
        let sighash_type = self.sighash_type;

        // Sign all script paths
        for (control_block, leaf_script) in &self.tap_leaf_script {
            let tapleaf_hash = leaf_script.tap_leaf_hash();

            if !satisfier.should_satisfy_script_path(
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
                let Some(sig) = satisfier.signature_bip340(sighash, *pk, Some(&tap.origin)) else {
                    continue;
                };
                let sig = Bip340Sig { sig, sighash_type };
                self.tap_script_sig.insert((*pk, tapleaf_hash), sig);
                signature_count += 1;
            }
        }

        // Sign keypath
        if !satisfier.should_satisfy_key_path(self.index) {
            return Ok(signature_count);
        }
        let Some(internal_key) = self.tap_internal_key else {
            return Ok(signature_count);
        };
        let xonly_key = XOnlyPk::from(internal_key);
        let derivation = self.tap_bip32_derivation.get(&xonly_key);
        let sighash = sig_hasher.tap_sighash_key(self.index, sighash_type)?;
        let Some(sig) =
            satisfier.signature_bip340(sighash, xonly_key, derivation.map(|d| &d.origin))
        else {
            return Ok(signature_count);
        };
        let sig = Bip340Sig { sig, sighash_type };
        self.tap_key_sig = Some(sig);
        signature_count += 1;

        Ok(signature_count)
    }
}