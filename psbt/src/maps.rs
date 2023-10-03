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

use amplify::confinement::Confined;
use amplify::num::u5;
use bp::{
    ComprPubkey, Descriptor, KeyOrigin, LegacyPubkey, LockTime, NormalIndex, Outpoint,
    RedeemScript, Sats, ScriptPubkey, SeqNo, SigScript, Terminal, Tx, TxIn, TxOut, TxVer, Txid,
    Vout, Witness, WitnessScript, Xpub, XpubOrigin,
};
use indexmap::IndexMap;

use crate::{EcdsaSig, LockHeight, LockTimestamp, SighashType};

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

    pub fn outpoint(&self) -> Outpoint { Outpoint::new(self.txid, self.vout) }
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
// TODO: Serde deserialize must correctly initialzie inputs and outputs with their indexes and
//       account for unknown fields
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

    pub fn to_unsigned_tx(&self) -> Tx {
        Tx {
            version: self.tx_version,
            inputs: Confined::try_from_iter(self.inputs().map(Input::to_unsigned_txin))
                .expect("number of inputs exceeds billions"),
            outputs: Confined::try_from_iter(self.outputs().map(Output::to_txout))
                .expect("number of inputs exceeds billions"),
            lock_time: self.lock_time(),
        }
    }

    pub fn inputs(&self) -> impl Iterator<Item = &Input> { self.inputs.iter() }

    pub fn outputs(&self) -> impl Iterator<Item = &Output> { self.outputs.iter() }

    pub fn lock_time(&self) -> LockTime {
        // TODO: Compute correct LockTime
        self.fallback_locktime.unwrap_or(LockTime::ZERO)
    }

    #[inline]
    pub fn input_sum(&self) -> Sats { self.inputs().map(Input::value).sum() }

    #[inline]
    pub fn output_sum(&self) -> Sats { self.outputs().map(Output::value).sum() }

    #[inline]
    pub fn fee(&self) -> Option<Sats> { self.input_sum().checked_sub(self.output_sum()) }

    pub fn xpubs(&self) -> impl Iterator<Item = (&Xpub, &XpubOrigin)> { self.xpubs.iter() }

    pub fn are_inputs_modifiable(&self) -> bool {
        self.tx_modifiable
            .as_ref()
            .map(|flags| flags.inputs_modifiable && !flags.sighash_single)
            .unwrap_or_default()
    }

    pub fn are_outputs_modifiable(&self) -> bool {
        self.tx_modifiable
            .as_ref()
            .map(|flags| flags.inputs_modifiable && !flags.sighash_single)
            .unwrap_or_default()
    }

    pub fn construct_input<K, D: Descriptor<K>>(
        &mut self,
        prevout: Prevout,
        descriptor: &D,
        terminal: Terminal,
        sequence: SeqNo,
    ) -> Result<&mut Input, Unmodifiable> {
        if !self.are_inputs_modifiable() {
            return Err(Unmodifiable);
        }

        let scripts = descriptor.derive(terminal.keychain, terminal.index);
        let input = Input {
            index: self.inputs.len(),
            previous_outpoint: prevout.outpoint(),
            sequence_number: Some(sequence),
            required_time_lock: None,
            required_height_lock: None,
            witness_utxo: Some(TxOut::new(scripts.to_script_pubkey(), prevout.value)),
            partial_sigs: none!(),
            sighash_type: None,
            redeem_script: scripts.to_redeem_script(),
            witness_script: scripts.to_witness_script(),
            bip32_derivation: descriptor.compr_keyset(terminal),
            final_script_sig: None,
            final_witness: None,
        };
        self.inputs.push(input);
        Ok(self.inputs.last_mut().expect("just inserted"))
    }

    pub fn construct_input_expect<K, D: Descriptor<K>>(
        &mut self,
        prevout: Prevout,
        descriptor: &D,
        terminal: Terminal,
        sequence: SeqNo,
    ) -> &mut Input {
        self.construct_input(prevout, descriptor, terminal, sequence)
            .expect("PSBT inputs are expected to be modifiable")
    }

    pub fn construct_output(
        &mut self,
        script_pubkey: ScriptPubkey,
        value: Sats,
    ) -> Result<&mut Output, Unmodifiable> {
        if !self.are_outputs_modifiable() {
            return Err(Unmodifiable);
        }

        let output = Output {
            index: self.outputs.len(),
            amount: value,
            script: script_pubkey,
            redeem_script: None,
            witness_script: None,
            bip32_derivation: none!(),
        };
        self.outputs.push(output);
        Ok(self.outputs.last_mut().expect("just inserted"))
    }

    pub fn construct_output_expect(
        &mut self,
        script_pubkey: ScriptPubkey,
        value: Sats,
    ) -> &mut Output {
        self.construct_output(script_pubkey, value)
            .expect("PSBT outputs are expected to be modifiable")
    }

    pub fn construct_change<K, D: Descriptor<K>>(
        &mut self,
        descriptor: &D,
        index: NormalIndex,
        value: Sats,
    ) -> Result<&mut Output, Unmodifiable> {
        if !self.are_outputs_modifiable() {
            return Err(Unmodifiable);
        }

        let scripts = descriptor.derive(1, index);
        let output = Output {
            index: self.outputs.len(),
            amount: value,
            script: scripts.to_script_pubkey(),
            redeem_script: scripts.to_redeem_script(),
            witness_script: scripts.to_witness_script(),
            bip32_derivation: descriptor.compr_keyset(Terminal::change(index)),
        };
        self.outputs.push(output);
        Ok(self.outputs.last_mut().expect("just inserted"))
    }

    pub fn construct_change_expect<K, D: Descriptor<K>>(
        &mut self,
        descriptor: &D,
        index: NormalIndex,
        value: Sats,
    ) -> &mut Output {
        self.construct_change(descriptor, index, value)
            .expect("PSBT outputs are expected to be modifiable")
    }

    pub fn complete_construction(&mut self) {
        // TODO: Check all inputs have witness_utxo or non_witness_tx
        self.tx_modifiable = Some(ModifiableFlags::unmodifiable())
    }
}

/* TODO: Complete weight implementation
impl Weight for Psbt {
    fn weight_units(&self) -> WeightUnits {
        let bytes = 4 // version
            + VarInt::with(self.inputs.len()).len()
            + VarInt::with(self.outputs.len()).len()
            + 4; // lock time
        let mut weight = WeightUnits::no_discount(bytes)
            + self.inputs().map(TxIn::weight_units).sum()
            + self.outputs().map(TxOut::weight_units).sum();
        if self.is_segwit() {
            weight += WeightUnits::witness_discount(2); // marker and flag bytes
        }
        weight
    }
}
 */

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
// TODO: Enusure than on serde deserialization:
//       - all unknown fields go into unknown fields map
//       - input always contains either witness UTXO or non-witness Tx
//       - index is constructed in a correct way
pub struct Input {
    /// The index of this input. Used in error reporting.
    #[cfg_attr(feature = "serde", serde(skip))]
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

impl Input {
    pub fn to_unsigned_txin(&self) -> TxIn {
        TxIn {
            prev_output: self.previous_outpoint,
            sig_script: none!(),
            // TODO: Figure out default SeqNo
            sequence: self.sequence_number.unwrap_or(SeqNo::from_consensus_u32(0)),
            witness: none!(),
        }
    }

    #[inline]
    pub fn prev_txout(&self) -> &TxOut {
        // TODO: Add support for nonwitness_utxo
        match (&self.witness_utxo, None::<&Tx>) {
            (Some(txout), _) => txout,
            (None, Some(tx)) => &tx.outputs[self.index],
            (None, None) => unreachable!(
                "PSBT input must contain either witness UTXO or a non-witness transaction"
            ),
        }
    }

    #[inline]
    pub fn prevout(&self) -> Prevout {
        Prevout {
            txid: self.previous_outpoint.txid,
            vout: self.previous_outpoint.vout,
            value: self.value(),
        }
    }

    #[inline]
    pub fn value(&self) -> Sats { self.prev_txout().value }
}

#[derive(Clone, Eq, PartialEq, Debug, Default)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Output {
    /// The index of this output. Used in error reporting.
    #[cfg_attr(feature = "serde", serde(skip))]
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

impl Output {
    pub fn to_txout(&self) -> TxOut {
        TxOut {
            value: self.amount,
            script_pubkey: self.script.clone(),
        }
    }

    #[inline]
    pub fn value(&self) -> Sats { self.amount }
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
    pub unknown: u5,
}

impl ModifiableFlags {
    pub const fn unmodifiable() -> Self {
        ModifiableFlags {
            inputs_modifiable: false,
            outputs_modifiable: false,
            sighash_single: false,
            unknown: u5::ZERO,
        }
    }

    pub const fn modifiable() -> Self {
        ModifiableFlags {
            inputs_modifiable: true,
            outputs_modifiable: true,
            sighash_single: false,
            unknown: u5::ZERO,
        }
    }

    pub const fn modifiable_sighash_single() -> Self {
        ModifiableFlags {
            inputs_modifiable: true,
            outputs_modifiable: true,
            sighash_single: true,
            unknown: u5::ZERO,
        }
    }

    pub fn from_standard_u8(val: u8) -> Self {
        let inputs_modifiable = val & 0x01 == 0x01;
        let outputs_modifiable = val & 0x02 == 0x02;
        let sighash_single = val & 0x04 == 0x04;
        let unknown = u5::with(val >> 3);
        Self {
            inputs_modifiable,
            outputs_modifiable,
            sighash_single,
            unknown,
        }
    }

    pub const fn to_standard_u8(&self) -> u8 {
        (self.inputs_modifiable as u8)
            | ((self.outputs_modifiable as u8) << 1)
            | ((self.sighash_single as u8) << 2)
    }
}
