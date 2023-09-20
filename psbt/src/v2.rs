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

use std::collections::BTreeMap;

use bp::{
    ComprPubkey, KeyOrigin, LegacyPubkey, LockTime, Outpoint, ScriptPubkey, SeqNo, SigScript,
    TxOut, TxVer, Witness, Xpub, XpubOrigin,
};

use crate::{EcdsaSig, LockHeight, LockTimestamp, RedeemScript, SighashType, WitnessScript};

#[derive(Clone, Eq, PartialEq, Debug, Default)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct PsbtV2 {
    /// Transaction version.
    pub tx_version: TxVer,

    /// Fallback locktime (used if none of the inputs specifies their locktime).
    pub fallback_locktime: Option<LockTime>,

    /// The corresponding key-value map for each input.
    pub inputs: Vec<InputV2>,

    /// The corresponding key-value map for each output.
    pub outputs: Vec<OutputV2>,

    /// A global map from extended public keys to the used key fingerprint and
    /// derivation path as defined by BIP 32
    pub xpub: BTreeMap<Xpub, XpubOrigin>,
    // TODO: Add modifiable flags
    // TODO: Add proprietary flags
    // TODO: Add unknown flags
}

#[derive(Clone, Eq, PartialEq, Debug, Default)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct InputV2 {
    /// The index of this input. Used in error reporting.
    pub(crate) index: usize,

    /// Previous transaction outpoint to spent.
    pub previous_outpoint: Outpoint,

    /// Sequence number of this input. If omitted, the sequence number is
    /// assumed to be the final sequence number (0xffffffff).
    pub sequence_number: Option<SeqNo>,

    /// 32 bit unsigned little endian integer greater than or equal to 500000000
    /// representing the minimum Unix timestamp that this input requires to be
    /// set as the transaction's lock time.
    pub required_time_locktime: Option<LockTimestamp>,

    /// 32 bit unsigned little endian integer less than 500000000 representing
    /// the minimum block height that this input requires to be set as the
    /// transaction's lock time.
    pub required_height_locktime: Option<LockHeight>,

    /* TODO: Add non_witness_utxo
    /// The non-witness transaction this input spends from. Should only be
    /// `Some` for inputs which spend non-segwit outputs or if it is unknown
    /// whether an input spends a segwit output.
    pub non_witness_utxo: Option<Transaction>,
     */
    /// The transaction output this input spends from. Should only be `Some` for
    /// inputs which spend segwit outputs, including P2SH embedded ones.
    pub witness_utxo: Option<TxOut>,

    /// A map from public keys to their corresponding signature as would be
    /// pushed to the stack from a scriptSig or witness for a non-taproot
    /// inputs.
    pub partial_sigs: BTreeMap<LegacyPubkey, EcdsaSig>,

    /// The sighash type to be used for this input. Signatures for this input
    /// must use the sighash type.
    pub sighash_type: Option<SighashType>,

    /// The redeem script for this input.
    pub redeem_script: Option<RedeemScript>,

    /// The witness script for this input.
    pub witness_script: Option<WitnessScript>,

    /// A map from public keys needed to sign this input to their corresponding
    /// master key fingerprints and derivation paths.
    pub bip32_derivation: BTreeMap<ComprPubkey, KeyOrigin>,

    /// The finalized, fully-constructed scriptSig with signatures and any other
    /// scripts necessary for this input to pass validation.
    pub final_script_sig: Option<SigScript>,

    /// The finalized, fully-constructed scriptWitness with signatures and any
    /// other scripts necessary for this input to pass validation.
    pub final_script_witness: Option<Witness>,
    // TODO: Add taproot
    // TODO: Add proof of reserves
    // TODO: Add hashes
    // TODO: Add P2C
    // TODO: Add proprietary flags
    // TODO: Add unknown flags
}

#[derive(Clone, Eq, PartialEq, Debug, Default)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct OutputV2 {
    /// The index of this output. Used in error reporting.
    pub(crate) index: usize,

    /// The output's amount in satoshis.
    pub amount: u64,

    /// The script for this output, also known as the scriptPubKey.
    pub script: ScriptPubkey,

    /// The redeem script for this output.
    pub redeem_script: Option<RedeemScript>,

    /// The witness script for this output.
    pub witness_script: Option<WitnessScript>,

    /// A map from public keys needed to spend this output to their
    /// corresponding master key fingerprints and derivation paths.
    pub bip32_derivation: BTreeMap<ComprPubkey, KeyOrigin>,
    // TODO: Add proprietary flags
    // TODO: Add unknown flags
}
