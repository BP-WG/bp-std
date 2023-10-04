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
use amplify::{Bytes20, Bytes32};
use bpstd::{
    CompressedPk, Descriptor, InternalPk, KeyOrigin, LegacyPk, LockTime, NormalIndex, Outpoint,
    RedeemScript, Sats, ScriptPubkey, SeqNo, SigScript, TaprootPk, Terminal, Tx, TxIn, TxOut,
    TxVer, Txid, Vout, Witness, WitnessScript, Xpub, XpubOrigin,
};
use indexmap::IndexMap;

use crate::{
    Bip340Sig, KeyData, LegacySig, LockHeight, LockTimestamp, PropKey, PsbtVer, SighashType,
    ValueData,
};

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
    /// PSBT version
    pub version: PsbtVer,

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
    pub xpubs: IndexMap<Xpub, XpubOrigin>,

    /// Transaction Modifiable Flags
    pub(crate) tx_modifiable: Option<ModifiableFlags>,

    /// Proprietary keys
    pub proprietary: IndexMap<PropKey, ValueData>,

    /// Unknown keys
    pub unknown: IndexMap<u8, IndexMap<KeyData, ValueData>>,
}

impl Default for Psbt {
    fn default() -> Self { Psbt::create() }
}

impl Psbt {
    pub fn create() -> Psbt {
        Psbt {
            version: PsbtVer::V2,
            tx_version: TxVer::V2,
            fallback_locktime: None,
            inputs: vec![],
            outputs: vec![],
            xpubs: none!(),
            tx_modifiable: Some(ModifiableFlags::modifiable()),
            proprietary: none!(),
            unknown: none!(),
        }
    }

    pub fn from_unsigned_tx(unsigned_tx: Tx) -> Self {
        let mut psbt = Psbt::create();
        psbt.reset_from_unsigned_tx(unsigned_tx);
        psbt
    }

    pub(crate) fn reset_from_unsigned_tx(&mut self, tx: Tx) {
        self.tx_version = tx.version;
        self.fallback_locktime = Some(tx.lock_time);
        self.inputs = tx.inputs.into_iter().enumerate().map(Input::from_unsigned_txin).collect();
        self.outputs = tx.outputs.into_iter().enumerate().map(Output::from_txout).collect();
    }

    pub(crate) fn reset_inputs(&mut self, input_count: usize) {
        self.inputs = (0..input_count).map(Input::new).collect();
    }

    pub(crate) fn reset_outputs(&mut self, output_count: usize) {
        self.outputs = (0..output_count).map(Output::new).collect();
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
            non_witness_tx: None,
            witness_utxo: Some(TxOut::new(scripts.to_script_pubkey(), prevout.value)),
            partial_sigs: none!(),
            sighash_type: None,
            redeem_script: scripts.to_redeem_script(),
            witness_script: scripts.to_witness_script(),
            bip32_derivation: descriptor.compr_keyset(terminal),
            // TODO: Fill hash preimages from descriptor
            // TODO: Fill taproot information from descriptor
            final_script_sig: None,
            final_witness: None,
            proof_of_reserves: None,
            ripemd160: none!(),
            sha256: none!(),
            hash160: none!(),
            hash256: none!(),
            tap_key_sig: None,
            tap_script_sig: none!(),
            tap_leaf_script: none!(),
            tap_bip32_derivation: none!(),
            tap_internal_key: None,
            tap_merkle_root: None,
            proprietary: none!(),
            unknown: none!(),
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
            amount: value,
            script: script_pubkey,
            ..Output::new(self.outputs.len())
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
            // TODO: Fill taproot data from descriptor
            tap_internal_key: None,
            tap_tree: None,
            tap_bip32_derivation: none!(),
            proprietary: none!(),
            unknown: none!(),
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

    /// The non-witness transaction this input spends from. Should only be
    /// `Some` for inputs which spend non-segwit outputs or if it is unknown
    /// whether an input spends a segwit output.
    pub non_witness_tx: Option<Tx>,

    /// The transaction output this input spends from. Should only be `Some` for
    /// inputs which spend segwit outputs, including P2SH embedded ones.
    pub witness_utxo: Option<TxOut>,

    /// A map from public keys to their corresponding signature as would be
    /// pushed to the stack from a scriptSig or witness for a non-taproot
    /// inputs.
    pub partial_sigs: IndexMap<LegacyPk, LegacySig>,

    /// The sighash type to be used for this input. Signatures for this input
    /// must use the sighash type.
    pub sighash_type: Option<SighashType>,

    /// The redeem script for this input.
    pub redeem_script: Option<RedeemScript>,

    /// The witness script for this input.
    pub witness_script: Option<WitnessScript>,

    /// A map from public keys needed to sign this input to their corresponding master key
    /// fingerprints and derivation paths.
    pub bip32_derivation: IndexMap<CompressedPk, KeyOrigin>,

    /// The finalized, fully-constructed scriptSig with signatures and any other scripts necessary
    /// for this input to pass validation.
    pub final_script_sig: Option<SigScript>,

    /// The finalized, fully-constructed scriptWitness with signatures and any other scripts
    /// necessary for this input to pass validation.
    pub final_witness: Option<Witness>,

    /// The UTF-8 encoded commitment message string for the proof-of-reserves. See BIP 127 for more
    /// information.
    pub proof_of_reserves: Option<String>,

    ///  The hash preimage, encoded as a byte vector, which must equal the key when run through the
    /// RIPEMD160 algorithm.
    pub ripemd160: IndexMap<Bytes20, ValueData>,

    ///  The hash preimage, encoded as a byte vector, which must equal the key when run through the
    /// SHA256 algorithm.
    pub sha256: IndexMap<Bytes32, ValueData>,

    /// The hash preimage, encoded as a byte vector, which must equal the key when run through the
    /// SHA256 algorithm followed by the RIPEMD160 algorithm .
    pub hash160: IndexMap<Bytes20, ValueData>,

    /// The hash preimage, encoded as a byte vector, which must equal the key when run through the
    /// SHA256 algorithm twice.
    pub hash256: IndexMap<Bytes32, ValueData>,

    /// The 64 or 65 byte Schnorr signature for key path spending a Taproot output. Finalizers
    /// should remove this field after `PSBT_IN_FINAL_SCRIPTWITNESS` is constructed.
    pub tap_key_sig: Option<Bip340Sig>,

    // TODO: Add taproot data structures: ControlBlock etc
    /// The 64 or 65 byte Schnorr signature for this pubkey and leaf combination. Finalizers
    /// should remove this field after `PSBT_IN_FINAL_SCRIPTWITNESS` is constructed.
    pub tap_script_sig: IndexMap<KeyData, Bip340Sig>,

    ///  The script for this leaf as would be provided in the witness stack followed by the single
    /// byte leaf version. Note that the leaves included in this field should be those that the
    /// signers of this input are expected to be able to sign for. Finalizers should remove this
    /// field after `PSBT_IN_FINAL_SCRIPTWITNESS` is constructed.
    pub tap_leaf_script: IndexMap<KeyData, ValueData>,

    /// A compact size unsigned integer representing the number of leaf hashes, followed by a list
    /// of leaf hashes, followed by the 4 byte master key fingerprint concatenated with the
    /// derivation path of the public key. The derivation path is represented as 32-bit little
    /// endian unsigned integer indexes concatenated with each other. Public keys are those needed
    /// to spend this output. The leaf hashes are of the leaves which involve this public key. The
    /// internal key does not have leaf hashes, so can be indicated with a hashes len of 0.
    /// Finalizers should remove this field after `PSBT_IN_FINAL_SCRIPTWITNESS` is constructed.
    pub tap_bip32_derivation: IndexMap<TaprootPk, ValueData>,

    /// The X-only pubkey used as the internal key in this output. Finalizers should remove this
    /// field after `PSBT_IN_FINAL_SCRIPTWITNESS` is constructed.
    pub tap_internal_key: Option<InternalPk>,

    ///  The 32 byte Merkle root hash. Finalizers should remove this field after
    /// PSBT_IN_FINAL_SCRIPTWITNESS is constructed.
    pub tap_merkle_root: Option<Bytes32>,

    /// Proprietary keys
    pub proprietary: IndexMap<PropKey, ValueData>,

    /// Unknown keys
    pub unknown: IndexMap<u8, IndexMap<KeyData, ValueData>>,
}

impl Input {
    pub fn new(index: usize) -> Input {
        Input {
            index,
            previous_outpoint: Outpoint::coinbse(),
            sequence_number: None,
            required_time_lock: None,
            required_height_lock: None,
            non_witness_tx: None,
            witness_utxo: None,
            partial_sigs: none!(),
            sighash_type: None,
            redeem_script: None,
            witness_script: None,
            bip32_derivation: none!(),
            final_script_sig: None,
            final_witness: None,
            proof_of_reserves: None,
            ripemd160: none!(),
            sha256: none!(),
            hash160: none!(),
            hash256: none!(),
            tap_key_sig: None,
            tap_script_sig: none!(),
            tap_leaf_script: none!(),
            tap_bip32_derivation: none!(),
            tap_internal_key: None,
            tap_merkle_root: None,
            proprietary: none!(),
            unknown: none!(),
        }
    }

    pub fn with_unsigned_txin(txin: TxIn, index: usize) -> Input {
        let mut input = Input::new(index);
        input.previous_outpoint = txin.prev_output;
        input.sequence_number = Some(txin.sequence);
        input
    }

    pub fn from_unsigned_txin((index, txin): (usize, TxIn)) -> Input {
        Input::with_unsigned_txin(txin, index)
    }

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

#[derive(Clone, Eq, PartialEq, Debug)]
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

    /// A map from public keys needed to spend this output to their corresponding master key
    /// fingerprints and derivation paths.
    pub bip32_derivation: IndexMap<CompressedPk, KeyOrigin>,

    /// The X-only pubkey used as the internal key in this output.
    // TODO: Add taproot data structures: TapTree and derivation info
    pub tap_internal_key: Option<InternalPk>,

    /// One or more tuples representing the depth, leaf version, and script for a leaf in the
    /// Taproot tree, allowing the entire tree to be reconstructed. The tuples must be in depth
    /// first search order so that the tree is correctly reconstructed. Each tuple is an 8-bit
    /// unsigned integer representing the depth in the Taproot tree for this script, an 8-bit
    /// unsigned integer representing the leaf version, the length of the script as a compact size
    /// unsigned integer, and the script itself.
    pub tap_tree: Option<ValueData>,

    /// A compact size unsigned integer representing the number of leaf hashes, followed by a list
    /// of leaf hashes, followed by the 4 byte master key fingerprint concatenated with the
    /// derivation path of the public key. The derivation path is represented as 32-bit little
    /// endian unsigned integer indexes concatenated with each other. Public keys are those needed
    /// to spend this output. The leaf hashes are of the leaves which involve this public key. The
    /// internal key does not have leaf hashes, so can be indicated with a hashes len of 0.
    /// Finalizers should remove this field after `PSBT_IN_FINAL_SCRIPTWITNESS` is constructed.
    pub tap_bip32_derivation: IndexMap<TaprootPk, ValueData>,

    /// Proprietary keys
    pub proprietary: IndexMap<PropKey, ValueData>,

    /// Unknown keys
    pub unknown: IndexMap<u8, IndexMap<KeyData, ValueData>>,
}

impl Output {
    pub fn new(index: usize) -> Self {
        Output {
            index,
            amount: Sats::ZERO,
            script: ScriptPubkey::new(),
            redeem_script: None,
            witness_script: None,
            bip32_derivation: none!(),
            tap_internal_key: None,
            tap_tree: None,
            tap_bip32_derivation: none!(),
            proprietary: none!(),
            unknown: none!(),
        }
    }

    pub fn with_txout(txout: TxOut, index: usize) -> Self {
        let mut output = Output::new(index);
        output.amount = txout.value;
        output.script = txout.script_pubkey;
        output
    }

    pub fn from_txout((index, txout): (usize, TxOut)) -> Self { Output::with_txout(txout, index) }

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
