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

use bp::{
    ComprPubkey, Derive, KeyOrigin, LegacyPubkey, LockTime, Outpoint, Sats, ScriptPubkey, SeqNo,
    SigScript, Terminal, TxOut, TxVer, Txid, Vout, Witness, Xpub, XpubDescriptor, XpubOrigin,
};
use indexmap::IndexMap;

use crate::{EcdsaSig, LockHeight, LockTimestamp, RedeemScript, SighashType, WitnessScript};

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display("PSBT can't be modified")]
pub struct Unmodifiable;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Prevout {
    pub txid: Txid,
    pub vout: Vout,
    pub value: Sats,
}

impl Prevout {
    pub fn new(outpoint: Outpoint, value: Sats) -> Self {
        Prevout {
            txid: outpoint.txid,
            vout: outpoint.vout,
            value,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Psbt {
    /// Transaction version.
    pub tx_version: TxVer,

    /// Fallback locktime (used if none of the inputs specifies their locktime).
    pub fallback_locktime: Option<LockTime>,

    /// The corresponding key-value map for each input.
    pub(crate) inputs: Vec<Input>,

    /// The corresponding key-value map for each output.
    pub(crate) outputs: Vec<Output>,

    /// A global map from extended public keys to the used key fingerprint and
    /// derivation path as defined by BIP 32
    pub(crate) xpubs: IndexMap<Xpub, XpubOrigin>,

    /// Transaction Modifiable Flags
    pub(crate) tx_modifiable: Option<ModifiableFlags>,
    // TODO: Add proprietary flags
    // TODO: Add unknown flags
}

impl Default for Psbt {
    fn default() -> Self { Psbt::create() }
}

impl Psbt {
    pub fn create() -> Psbt {
        Psbt {
            tx_version: TxVer::V2,
            fallback_locktime: None,
            inputs: vec![],
            outputs: vec![],
            xpubs: none!(),
            tx_modifiable: Some(ModifiableFlags::modifiable()),
        }
    }

    pub fn inputs(&self) -> impl Iterator<Item = &Input> { self.inputs.iter() }

    pub fn outputs(&self) -> impl Iterator<Item = &Output> { self.outputs.iter() }

    pub fn xpubs(&self) -> impl Iterator<Item = (&Xpub, &XpubOrigin)> { self.xpubs.iter() }

    pub fn are_inputs_modifiable(&self) -> bool {
        self.tx_modifiable
            .map(|flags| flags.inputs_modifiable && !flags.sighash_single)
            .unwrap_or_default()
    }

    pub fn are_outputs_modifiable(&self) -> bool {
        self.tx_modifiable
            .map(|flags| flags.inputs_modifiable && !flags.sighash_single)
            .unwrap_or_default()
    }

    pub fn construct_input<D: DeriveScripts>(
        &mut self,
        prevout: Prevout,
        decriptor: D,
        terminal: Terminal,
        sequence: SeqNo,
    ) -> Result<(), Unmodifiable> {
        if !self.are_inputs_modifiable() {
            Err(Unmodifiable)
        }
        // Derive
        // Add xpubs
        self.inputs.push(input);
        Ok(())
    }

    pub fn construct_input_expect<D: DeriveScripts>(
        &mut self,
        prevout: Prevout,
        decriptor: D,
        terminal: Terminal,
        sequence: SeqNo,
    ) {
        self.construct_input(prevout, decriptor, terminal, sequence)
            .expect("PSBT inputs are expected to be modifiable")
    }

    pub fn construct_output(
        &mut self,
        script_pubkey: ScriptPubkey,
        value: Sats,
    ) -> Result<(), Unmodifiable> {
        if !self.are_outputs_modifiable() {
            Err(Unmodifiable)
        }
        let output = Output::with(TxOut::new(script_pubkey, value));
        self.outputs.push(output);
        Ok(())
    }

    pub fn construct_output_expect(&mut self, output: Output) {
        self.push_output(output).expect("PSBT outputs are expected to be modifiable")
    }

    pub fn complete_construction(&mut self) {
        self.tx_modifiable = Some(ModifiableFlags::unmodifiable())
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Input {
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
    pub required_time_lock: Option<LockTimestamp>,

    /// 32 bit unsigned little endian integer less than 500000000 representing
    /// the minimum block height that this input requires to be set as the
    /// transaction's lock time.
    pub required_height_lock: Option<LockHeight>,

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
    pub partial_sigs: IndexMap<LegacyPubkey, EcdsaSig>,

    /// The sighash type to be used for this input. Signatures for this input
    /// must use the sighash type.
    pub sighash_type: Option<SighashType>,

    /// The redeem script for this input.
    pub redeem_script: Option<RedeemScript>,

    /// The witness script for this input.
    pub witness_script: Option<WitnessScript>,

    /// A map from public keys needed to sign this input to their corresponding
    /// master key fingerprints and derivation paths.
    pub bip32_derivation: IndexMap<ComprPubkey, KeyOrigin>,

    /// The finalized, fully-constructed scriptSig with signatures and any other
    /// scripts necessary for this input to pass validation.
    pub final_script_sig: Option<SigScript>,

    /// The finalized, fully-constructed scriptWitness with signatures and any
    /// other scripts necessary for this input to pass validation.
    pub final_witness: Option<Witness>,
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
pub struct Output {
    /// The index of this output. Used in error reporting.
    pub(crate) index: usize,

    /// The output's amount in satoshis.
    pub amount: Sats,

    /// The script for this output, also known as the scriptPubKey.
    pub script: ScriptPubkey,

    /// The redeem script for this output.
    pub redeem_script: Option<RedeemScript>,

    /// The witness script for this output.
    pub witness_script: Option<WitnessScript>,

    /// A map from public keys needed to spend this output to their
    /// corresponding master key fingerprints and derivation paths.
    pub bip32_derivation: IndexMap<ComprPubkey, KeyOrigin>,
    // TODO: Add proprietary flags
    // TODO: Add unknown flags
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ModifiableFlags {
    pub inputs_modifiable: bool,
    pub outputs_modifiable: bool,
    pub sighash_single: bool,
}

impl ModifiableFlags {
    pub fn unmodifiable() -> Self {
        ModifiableFlags {
            inputs_modifiable: false,
            outputs_modifiable: false,
            sighash_single: false,
        }
    }

    pub fn modifiable() -> Self {
        ModifiableFlags {
            inputs_modifiable: true,
            outputs_modifiable: true,
            sighash_single: false,
        }
    }

    pub fn modifiable_sighash_single() -> Self {
        ModifiableFlags {
            inputs_modifiable: true,
            outputs_modifiable: true,
            sighash_single: true,
        }
    }

    pub fn to_standard_u8(&self) -> u8 {
        (self.inputs_modifiable as u8)
            | ((self.outputs_modifiable as u8) << 1)
            | ((self.sighash_single as u8) << 2)
    }
}
