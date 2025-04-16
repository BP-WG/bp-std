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

use std::collections::BTreeSet;

use amplify::num::u5;
use amplify::{ByteArray, Bytes20, Bytes32};
use derive::{
    Bip340Sig, ByteStr, ControlBlock, InternalPk, KeyOrigin, LeafScript, LegacyPk, LegacySig,
    LockHeight, LockTime, LockTimestamp, Outpoint, RedeemScript, Sats, ScriptCode, ScriptPubkey,
    SeqNo, SigScript, SighashType, TapDerivation, TapLeafHash, TapNodeHash, TapTree, Terminal, Tx,
    TxIn, TxOut, TxVer, Txid, VarIntArray, Vout, Witness, WitnessScript, XOnlyPk, XkeyOrigin, Xpub,
};
use descriptors::{Descriptor, LegacyKeySig, TaprootKeySig};
use indexmap::IndexMap;

pub use self::display_from_str::PsbtParseError;
use crate::{KeyData, PropKey, PsbtError, PsbtVer, ValueData};

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display("PSBT can't be modified")]
pub struct Unmodifiable;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(
    "can't extract signed transaction from PSBT since it still contains {0} non-finalized inputs"
)]
pub struct UnfinalizedInputs(pub usize);

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

/// Structure representing data on unsigned transaction the way it is stored in PSBTv1 global key.
///
/// We can't use [`Tx`] since PSBT may contain unsigned transaction with zero inputs, according to
/// BIP-174 test cases. [`Tx`] containing zero inputs is an invalid structure, prohibited by
/// consensus. An attempt to deserialize it will be incorrectly identified as a Segwit transaction
/// (since zero inputs is the trick which was used to make Segwit softfork) and fail with invalid
/// segwit flag error (since the second byte after 0 segwit indicator must be `01` and not a number
/// of inputs) fail to parse outputs (for transactions containing just a one output).
///
/// `UnsignedTx` also ensures invariant that none of its inputs contain witnesses or sigscripts.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(
    feature = "strict_encoding",
    derive(StrictType, StrictDumb, StrictEncode, StrictDecode),
    strict_type(lib = crate::LIB_NAME_PSBT)
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct UnsignedTx {
    pub version: TxVer,
    pub inputs: VarIntArray<UnsignedTxIn>,
    pub outputs: VarIntArray<TxOut>,
    pub lock_time: LockTime,
}

impl From<Tx> for UnsignedTx {
    #[inline]
    fn from(tx: Tx) -> UnsignedTx { UnsignedTx::with_sigs_removed(tx) }
}

impl From<UnsignedTx> for Tx {
    #[inline]
    fn from(unsigned_tx: UnsignedTx) -> Tx {
        Tx {
            version: unsigned_tx.version,
            inputs: VarIntArray::from_checked(
                unsigned_tx.inputs.into_iter().map(TxIn::from).collect(),
            ),
            outputs: unsigned_tx.outputs,
            lock_time: unsigned_tx.lock_time,
        }
    }
}

impl UnsignedTx {
    #[inline]
    pub fn with_sigs_removed(tx: Tx) -> UnsignedTx {
        UnsignedTx {
            version: tx.version,
            inputs: VarIntArray::from_checked(
                tx.inputs.into_iter().map(UnsignedTxIn::with_sigs_removed).collect(),
            ),
            outputs: tx.outputs,
            lock_time: tx.lock_time,
        }
    }

    pub fn txid(&self) -> Txid { Tx::from(self.clone()).txid() }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(
    feature = "strict_encoding",
    derive(StrictType, StrictDumb, StrictEncode, StrictDecode),
    strict_type(lib = crate::LIB_NAME_PSBT)
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct UnsignedTxIn {
    pub prev_output: Outpoint,
    pub sequence: SeqNo,
}

impl From<TxIn> for UnsignedTxIn {
    #[inline]
    fn from(txin: TxIn) -> UnsignedTxIn { UnsignedTxIn::with_sigs_removed(txin) }
}

impl From<UnsignedTxIn> for TxIn {
    #[inline]
    fn from(unsigned_txin: UnsignedTxIn) -> TxIn {
        TxIn {
            prev_output: unsigned_txin.prev_output,
            sig_script: none!(),
            sequence: unsigned_txin.sequence,
            witness: empty!(),
        }
    }
}

impl UnsignedTxIn {
    #[inline]
    pub fn with_sigs_removed(txin: TxIn) -> UnsignedTxIn {
        UnsignedTxIn {
            prev_output: txin.prev_output,
            sequence: txin.sequence,
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
    pub xpubs: IndexMap<Xpub, XkeyOrigin>,

    /// Transaction Modifiable Flags
    pub(crate) tx_modifiable: Option<ModifiableFlags>,

    /// Proprietary keys
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::indexmap_as_seq_byte_values"))]
    pub proprietary: IndexMap<PropKey, ValueData>,

    /// Unknown keys
    pub unknown: IndexMap<u8, IndexMap<KeyData, ValueData>>,
}

impl Default for Psbt {
    fn default() -> Self { Psbt::create(PsbtVer::V2) }
}

impl Psbt {
    pub fn create(version: PsbtVer) -> Psbt {
        Psbt {
            version,
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

    pub fn from_tx(tx: impl Into<UnsignedTx>) -> Self {
        let unsigned_tx = tx.into();
        let mut psbt = Psbt::create(PsbtVer::V0);
        psbt.reset_from_unsigned_tx(unsigned_tx);
        psbt
    }

    pub(crate) fn reset_from_unsigned_tx(&mut self, unsigned_tx: UnsignedTx) {
        self.version = PsbtVer::V0;
        self.tx_version = unsigned_tx.version;
        self.fallback_locktime = Some(unsigned_tx.lock_time);
        self.inputs =
            unsigned_tx.inputs.into_iter().enumerate().map(Input::from_unsigned_txin).collect();
        self.outputs =
            unsigned_tx.outputs.into_iter().enumerate().map(Output::from_txout).collect();
    }

    pub(crate) fn reset_inputs(&mut self, input_count: usize) {
        self.inputs = (0..input_count).map(Input::new).collect();
    }

    pub(crate) fn reset_outputs(&mut self, output_count: usize) {
        self.outputs = (0..output_count).map(Output::new).collect();
    }

    pub fn to_unsigned_tx(&self) -> UnsignedTx {
        UnsignedTx {
            version: self.tx_version,
            inputs: VarIntArray::from_iter_checked(self.inputs().map(Input::to_unsigned_txin)),
            outputs: VarIntArray::from_iter_checked(self.outputs().map(Output::to_txout)),
            lock_time: self.lock_time(),
        }
    }

    pub fn txid(&self) -> Txid { self.to_unsigned_tx().txid() }

    pub fn input(&self, index: usize) -> Option<&Input> { self.inputs.get(index) }

    pub fn input_mut(&mut self, index: usize) -> Option<&mut Input> { self.inputs.get_mut(index) }

    pub fn inputs(&self) -> impl Iterator<Item = &Input> { self.inputs.iter() }

    pub fn inputs_mut(&mut self) -> impl Iterator<Item = &mut Input> { self.inputs.iter_mut() }

    pub fn output(&self, index: usize) -> Option<&Output> { self.outputs.get(index) }

    pub fn output_mut(&mut self, index: usize) -> Option<&mut Output> {
        self.outputs.get_mut(index)
    }

    pub fn outputs(&self) -> impl Iterator<Item = &Output> { self.outputs.iter() }

    pub fn outputs_mut(&mut self) -> impl Iterator<Item = &mut Output> { self.outputs.iter_mut() }

    pub fn lock_time(&self) -> LockTime {
        // TODO #45: Compute correct LockTime
        self.fallback_locktime.unwrap_or(LockTime::ZERO)
    }

    #[inline]
    pub fn input_sum(&self) -> Sats { self.inputs().map(Input::value).sum() }

    #[inline]
    pub fn output_sum(&self) -> Sats { self.outputs().map(Output::value).sum() }

    #[inline]
    pub fn fee(&self) -> Option<Sats> { self.input_sum().checked_sub(self.output_sum()) }

    pub fn xpubs(&self) -> impl Iterator<Item = (&Xpub, &XkeyOrigin)> { self.xpubs.iter() }

    pub fn is_modifiable(&self) -> bool {
        self.tx_modifiable.as_ref().map(ModifiableFlags::is_modifiable).unwrap_or_default()
    }

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
        script_pubkey: ScriptPubkey,
        sequence: SeqNo,
    ) -> Result<&mut Input, Unmodifiable> {
        if !self.are_inputs_modifiable() {
            return Err(Unmodifiable);
        }

        let script = descriptor
            .derive(terminal.keychain, terminal.index)
            .find(|script| script.to_script_pubkey() == script_pubkey)
            .expect("unable to generate input matching prevout");
        let input = Input {
            index: self.inputs.len(),
            previous_outpoint: prevout.outpoint(),
            sequence_number: Some(sequence),
            required_time_lock: None,
            required_height_lock: None,
            non_witness_tx: None,
            witness_utxo: Some(TxOut::new(script.to_script_pubkey(), prevout.value)),
            partial_sigs: none!(),
            sighash_type: None,
            redeem_script: script.to_redeem_script(),
            witness_script: script.to_witness_script(),
            bip32_derivation: descriptor.legacy_keyset(terminal),
            // TODO #36: Fill hash preimages from descriptor
            final_script_sig: None,
            final_witness: None,
            proof_of_reserves: None,
            ripemd160: none!(),
            sha256: none!(),
            hash160: none!(),
            hash256: none!(),
            tap_key_sig: None,
            tap_script_sig: none!(),
            tap_leaf_script: script.to_leaf_scripts(),
            tap_bip32_derivation: descriptor.xonly_keyset(terminal),
            tap_internal_key: script.to_internal_pk(),
            tap_merkle_root: script.to_tap_root(),
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
        script_pubkey: ScriptPubkey,
        sequence: SeqNo,
    ) -> &mut Input {
        self.construct_input(prevout, descriptor, terminal, script_pubkey, sequence)
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
        change_terminal: Terminal,
        value: Sats,
    ) -> Result<&mut Output, Unmodifiable> {
        if !self.are_outputs_modifiable() {
            return Err(Unmodifiable);
        }

        let script = descriptor
            .derive(change_terminal.keychain, change_terminal.index)
            .next()
            .expect("unable to generate change script");
        let output = Output {
            index: self.outputs.len(),
            amount: value,
            script: script.to_script_pubkey(),
            redeem_script: script.to_redeem_script(),
            witness_script: script.to_witness_script(),
            bip32_derivation: descriptor.legacy_keyset(change_terminal),
            tap_internal_key: script.to_internal_pk(),
            tap_tree: script.to_tap_tree(),
            tap_bip32_derivation: descriptor.xonly_keyset(change_terminal),
            proprietary: none!(),
            unknown: none!(),
        };
        self.outputs.push(output);
        Ok(self.outputs.last_mut().expect("just inserted"))
    }

    pub fn construct_change_expect<K, D: Descriptor<K>>(
        &mut self,
        descriptor: &D,
        change_terminal: Terminal,
        value: Sats,
    ) -> &mut Output {
        self.construct_change(descriptor, change_terminal, value)
            .expect("PSBT outputs are expected to be modifiable")
    }

    pub fn sort_outputs_by<K: Ord>(
        &mut self,
        f: impl FnMut(&Output) -> K,
    ) -> Result<(), Unmodifiable> {
        if !self.are_outputs_modifiable() {
            return Err(Unmodifiable);
        }

        self.outputs.sort_by_key(f);
        for (index, output) in self.outputs.iter_mut().enumerate() {
            output.index = index;
        }

        Ok(())
    }

    pub fn complete_construction(&mut self) {
        // TODO #47: Check all inputs have witness_utxo or non_witness_tx
        self.tx_modifiable = Some(ModifiableFlags::unmodifiable())
    }

    pub fn is_finalized(&self) -> bool { self.inputs.iter().all(Input::is_finalized) }

    pub fn finalize<D: Descriptor<K, V>, K, V>(&mut self, descriptor: &D) -> usize {
        self.inputs.iter_mut().map(|input| input.finalize(descriptor) as usize).sum()
    }

    pub fn extract(&self) -> Result<Tx, UnfinalizedInputs> {
        let finalized = self.inputs.iter().filter(|i| i.is_finalized()).count();
        let unfinalized = self.inputs.len() - finalized;
        if unfinalized > 0 {
            return Err(UnfinalizedInputs(unfinalized));
        }

        Ok(Tx {
            version: self.tx_version,
            inputs: VarIntArray::from_iter_checked(self.inputs.iter().map(Input::to_signed_txin)),
            outputs: VarIntArray::from_iter_checked(self.outputs.iter().map(Output::to_txout)),
            lock_time: self.lock_time(),
        })
    }
}

mod display_from_str {
    use std::fmt::{self, Display, Formatter, LowerHex};
    use std::str::FromStr;

    use amplify::hex::{self, FromHex, ToHex};
    use base64::display::Base64Display;
    use base64::prelude::BASE64_STANDARD;
    use base64::Engine;

    use super::*;

    #[derive(Clone, Debug, Display, Error, From)]
    #[display(inner)]
    pub enum PsbtParseError {
        #[from]
        Hex(hex::Error),

        #[from]
        Base64(base64::DecodeError),

        #[from]
        Psbt(PsbtError),
    }

    impl Psbt {
        pub fn from_base64(s: &str) -> Result<Psbt, PsbtParseError> {
            Psbt::deserialize(BASE64_STANDARD.decode(s)?).map_err(PsbtParseError::from)
        }

        pub fn from_base16(s: &str) -> Result<Psbt, PsbtParseError> {
            let data = Vec::<u8>::from_hex(s)?;
            Psbt::deserialize(data).map_err(PsbtParseError::from)
        }

        pub fn to_base64(&self) -> String { self.to_base64_ver(self.version) }

        pub fn to_base64_ver(&self, version: PsbtVer) -> String {
            BASE64_STANDARD.encode(self.serialize(version))
        }

        pub fn to_base16(&self) -> String { self.to_base16_ver(self.version) }

        pub fn to_base16_ver(&self, version: PsbtVer) -> String { self.serialize(version).to_hex() }
    }

    /// FromStr implementation parses both Base64 and Hex (Base16) encodings.
    impl FromStr for Psbt {
        type Err = PsbtParseError;

        #[inline]
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Self::from_base16(s).or_else(|_| Self::from_base64(s))
        }
    }

    /// PSBT displays Base64-encoded string. The selection of the version if the following:
    /// - by default, it uses version specified in the PSBT itself;
    /// - if zero `{:0}` is given and no width (`{:0}`) or a zero width (`{:00}`) is provided, than
    ///   the PSBT is encoded as V0 even if the structure itself uses V2;
    /// - if a width equal to one is given like in `{:1}`, than zero flag is ignored (so `{:01}`
    ///   also works that way) and PSBT is encoded as V0 even if the structure itself uses V2;
    /// - if a width equal to two is given like in `{:2}`, than zero flag is ignored (so `{:02}`
    ///   also works that way) and PSBT is encoded as V2 even if the structure itself uses V1;
    /// - all other flags has no effect on the display.
    impl Display for Psbt {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            let ver = match (f.width(), f.sign_aware_zero_pad()) {
                (None, true) => PsbtVer::V0,
                (Some(1), _) => PsbtVer::V0,
                (Some(ver), _) => PsbtVer::try_from(ver).map_err(|_| fmt::Error)?,
                _ => self.version,
            };
            write!(f, "{}", Base64Display::new(&self.serialize(ver), &BASE64_STANDARD))
        }
    }

    /// PSBT is formatted like hex-encoded string. The selection of the version if the following:
    /// - by default, it uses version specified in the PSBT itself;
    /// - if zero `{:0}` is given and no width (`{:0}`) or a zero width (`{:00}`) is provided, than
    ///   the PSBT is encoded as V0 even if the structure itself uses V2;
    /// - if a width equal to one is given like in `{:1}`, than zero flag is ignored (so `{:01}`
    ///   also works that way) and PSBT is encoded as V0 even if the structure itself uses V2;
    /// - if a width equal to two is given like in `{:2}`, than zero flag is ignored (so `{:02}`
    ///   also works that way) and PSBT is encoded as V2 even if the structure itself uses V1;
    /// - all other flags has no effect on the display.
    impl LowerHex for Psbt {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            let ver = match (f.width(), f.sign_aware_zero_pad()) {
                (None, true) => PsbtVer::V0,
                (Some(1), _) => PsbtVer::V0,
                (Some(ver), _) => PsbtVer::try_from(ver).map_err(|_| fmt::Error)?,
                _ => self.version,
            };
            f.write_str(&self.to_base16_ver(ver))
        }
    }
}

/* TODO #43: Complete weight implementation
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
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::indexmap_as_seq"))]
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
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::indexmap_as_seq"))]
    pub bip32_derivation: IndexMap<LegacyPk, KeyOrigin>,

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
    pub ripemd160: IndexMap<Bytes20, ByteStr>,

    ///  The hash preimage, encoded as a byte vector, which must equal the key when run through the
    /// SHA256 algorithm.
    pub sha256: IndexMap<Bytes32, ByteStr>,

    /// The hash preimage, encoded as a byte vector, which must equal the key when run through the
    /// SHA256 algorithm followed by the RIPEMD160 algorithm .
    pub hash160: IndexMap<Bytes20, ByteStr>,

    /// The hash preimage, encoded as a byte vector, which must equal the key when run through the
    /// SHA256 algorithm twice.
    pub hash256: IndexMap<Bytes32, ByteStr>,

    /// The 64 or 65 byte Schnorr signature for key path spending a Taproot output. Finalizers
    /// should remove this field after `PSBT_IN_FINAL_SCRIPTWITNESS` is constructed.
    pub tap_key_sig: Option<Bip340Sig>,

    /// The 64 or 65 byte Schnorr signature for this pubkey and leaf combination. Finalizers
    /// should remove this field after `PSBT_IN_FINAL_SCRIPTWITNESS` is constructed.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::indexmap_as_seq"))]
    pub tap_script_sig: IndexMap<(XOnlyPk, TapLeafHash), Bip340Sig>,

    /// The script for this leaf as would be provided in the witness stack followed by the single
    /// byte leaf version. Note that the leaves included in this field should be those that the
    /// signers of this input are expected to be able to sign for. Finalizers should remove this
    /// field after `PSBT_IN_FINAL_SCRIPTWITNESS` is constructed.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::indexmap_as_seq"))]
    pub tap_leaf_script: IndexMap<ControlBlock, LeafScript>,

    /// A compact size unsigned integer representing the number of leaf hashes, followed by a list
    /// of leaf hashes, followed by the 4 byte master key fingerprint concatenated with the
    /// derivation path of the public key. The derivation path is represented as 32-bit little
    /// endian unsigned integer indexes concatenated with each other. Public keys are those needed
    /// to spend this output. The leaf hashes are of the leaves which involve this public key. The
    /// internal key does not have leaf hashes, so can be indicated with a hashes len of 0.
    /// Finalizers should remove this field after `PSBT_IN_FINAL_SCRIPTWITNESS` is constructed.
    pub tap_bip32_derivation: IndexMap<XOnlyPk, TapDerivation>,

    /// The X-only pubkey used as the internal key in this output. Finalizers should remove this
    /// field after `PSBT_IN_FINAL_SCRIPTWITNESS` is constructed.
    pub tap_internal_key: Option<InternalPk>,

    ///  The 32 byte Merkle root hash. Finalizers should remove this field after
    /// `PSBT_IN_FINAL_SCRIPTWITNESS` is constructed.
    pub tap_merkle_root: Option<TapNodeHash>,

    /// Proprietary keys
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::indexmap_as_seq_byte_values"))]
    pub proprietary: IndexMap<PropKey, ValueData>,

    /// Unknown keys
    pub unknown: IndexMap<u8, IndexMap<KeyData, ValueData>>,
}

impl Input {
    pub fn new(index: usize) -> Input {
        Input {
            index,
            previous_outpoint: Outpoint::coinbase(),
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

    pub fn with_txin(txin: impl Into<UnsignedTxIn>, index: usize) -> Input {
        let txin = txin.into();
        let mut input = Input::new(index);
        input.previous_outpoint = txin.prev_output;
        input.sequence_number = Some(txin.sequence);
        input
    }

    pub fn from_unsigned_txin((index, txin): (usize, UnsignedTxIn)) -> Input {
        Input::with_txin(txin, index)
    }

    fn to_signed_txin(&self) -> TxIn {
        TxIn {
            prev_output: self.previous_outpoint,
            // TODO #45: Figure out default SeqNo
            sig_script: self.final_script_sig.clone().expect("non-finalized input"),
            sequence: self.sequence_number.unwrap_or(SeqNo::from_consensus_u32(0)),
            witness: self.final_witness.clone().expect("non-finalized input"),
        }
    }

    pub fn to_unsigned_txin(&self) -> UnsignedTxIn {
        UnsignedTxIn {
            prev_output: self.previous_outpoint,
            // TODO #45: Figure out default SeqNo
            sequence: self.sequence_number.unwrap_or(SeqNo::from_consensus_u32(0)),
        }
    }

    #[inline]
    pub fn prev_txout(&self) -> &TxOut {
        // TODO #48: Add support for nonwitness_utxo
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

    #[inline]
    pub fn index(&self) -> usize { self.index }

    /// Computes script code, used in SegWit v0 signing algorithm (BIP143).
    ///
    /// NB: Does not support processing of `OP_CODESEPARATOR`.
    ///
    /// # Returns
    ///
    /// `None` if input spends P2WSH or P2WSH-in-P2SH output, but contains no witness script.
    pub fn script_code(&self) -> Option<ScriptCode> {
        let spk = &self.prev_txout().script_pubkey;
        Some(match (&self.witness_script, &self.redeem_script) {
            (None, None) if spk.is_p2wpkh() => ScriptCode::with_p2wpkh(spk),
            (Some(witness_script), None) if spk.is_p2wsh() => {
                ScriptCode::with_p2wsh(witness_script)
            }
            (_, Some(redeem_script)) if redeem_script.is_p2sh_wpkh() => {
                ScriptCode::with_p2sh_wpkh(spk)
            }
            (Some(witness_script), Some(redeem_script)) if redeem_script.is_p2sh_wsh() => {
                ScriptCode::with_p2sh_wsh(witness_script)
            }
            _ => return None,
        })
    }

    #[inline]
    pub fn is_segwit_v0(&self) -> bool {
        self.witness_script.is_some()
            || self.witness_utxo.is_some()
            || self.prev_txout().script_pubkey.is_p2wpkh()
            || self.prev_txout().script_pubkey.is_p2wsh()
    }

    #[must_use]
    pub fn is_bip340(&self) -> bool { self.tap_internal_key.is_some() }

    #[must_use]
    pub fn is_finalized(&self) -> bool {
        self.final_witness.is_some() || self.final_script_sig.is_some()
    }

    pub fn finalize<D: Descriptor<K, V>, K, V>(&mut self, descriptor: &D) -> bool {
        if self.is_finalized() {
            return false;
        }

        let satisfaction = if descriptor.is_taproot() {
            self.tap_internal_key
                .map(XOnlyPk::from)
                .and_then(|pk| self.tap_bip32_derivation.get(&pk).map(|d| (&d.origin, pk)))
                .zip(self.tap_key_sig)
                .and_then(|((origin, pk), sig)| {
                    // First, we try key path
                    descriptor.taproot_witness(map! { origin => TaprootKeySig::new(pk, sig) })
                })
                .or_else(|| {
                    // If we can't satisfy key path, we try script paths until we succeed
                    self.tap_leaf_script
                        .keys()
                        .filter_map(|cb| cb.merkle_branch.first())
                        .copied()
                        .map(|hash| TapLeafHash::from_byte_array(hash.to_byte_array()))
                        .find_map(|leafhash| {
                            let keysigs = self
                                .tap_script_sig
                                .iter()
                                .filter(|((_, lh), _)| *lh == leafhash)
                                .map(|((pk, _), sig)| TaprootKeySig::new(*pk, *sig))
                                .filter_map(|ks| {
                                    self.tap_bip32_derivation
                                        .get(&ks.key)
                                        .filter(|d| d.leaf_hashes.contains(&leafhash))
                                        .map(|d| (&d.origin, ks))
                                })
                                .collect();
                            descriptor.taproot_witness(keysigs)
                        })
                })
                .map(|witness| (empty!(), witness))
        } else {
            let keysigs = self
                .partial_sigs
                .iter()
                .map(|(pk, sig)| LegacyKeySig::new(*pk, *sig))
                .filter_map(|ks| self.bip32_derivation.get(&ks.key).map(|origin| (origin, ks)))
                .collect();
            descriptor.legacy_witness(keysigs)
        };
        let Some((sig_script, witness)) = satisfaction else {
            return false;
        };

        self.final_script_sig = Some(sig_script);
        self.final_witness = Some(witness);
        // reset everything
        self.partial_sigs.clear(); // 0x02
        self.sighash_type = None; // 0x03
        self.redeem_script = None; // 0x04
        self.witness_script = None; // 0x05
        self.bip32_derivation.clear(); // 0x05
                                       // finalized witness 0x06 and 0x07 are not clear
                                       // 0x09 Proof of reserves not yet supported
        self.ripemd160.clear(); // 0x0a
        self.sha256.clear(); // 0x0b
        self.hash160.clear(); // 0x0c
        self.hash256.clear(); // 0x0d
                              // psbt v2 fields till 0x012 not supported
        self.tap_key_sig = None; // 0x013
        self.tap_script_sig.clear(); // 0x014
        self.tap_leaf_script.clear(); // 0x015
        self.tap_bip32_derivation.clear(); // 0x16
        self.tap_internal_key = None; // x017
        self.tap_merkle_root = None; // 0x018

        true
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
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

    /// A map from public keys needed to spend this output to their corresponding master key
    /// fingerprints and derivation paths.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::indexmap_as_seq"))]
    pub bip32_derivation: IndexMap<LegacyPk, KeyOrigin>,

    /// The X-only pubkey used as the internal key in this output.
    // TODO #49: Add taproot data structures: TapTree and derivation info
    pub tap_internal_key: Option<InternalPk>,

    /// One or more tuples representing the depth, leaf version, and script for a leaf in the
    /// Taproot tree, allowing the entire tree to be reconstructed. The tuples must be in depth
    /// first search order so that the tree is correctly reconstructed. Each tuple is an 8-bit
    /// unsigned integer representing the depth in the Taproot tree for this script, an 8-bit
    /// unsigned integer representing the leaf version, the length of the script as a compact size
    /// unsigned integer, and the script itself.
    pub tap_tree: Option<TapTree>,

    /// A compact size unsigned integer representing the number of leaf hashes, followed by a list
    /// of leaf hashes, followed by the 4 byte master key fingerprint concatenated with the
    /// derivation path of the public key. The derivation path is represented as 32-bit little
    /// endian unsigned integer indexes concatenated with each other. Public keys are those needed
    /// to spend this output. The leaf hashes are of the leaves which involve this public key. The
    /// internal key does not have leaf hashes, so can be indicated with a hashes len of 0.
    /// Finalizers should remove this field after `PSBT_IN_FINAL_SCRIPTWITNESS` is constructed.
    pub tap_bip32_derivation: IndexMap<XOnlyPk, TapDerivation>,

    /// Proprietary keys
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::indexmap_as_seq_byte_values"))]
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

    #[inline]
    pub fn index(&self) -> usize { self.index }

    #[inline]
    pub fn vout(&self) -> Vout { Vout::from_u32(self.index as u32) }

    pub fn terminal_derivation(&self) -> Option<Terminal> {
        if self.bip32_derivation.is_empty() && self.tap_bip32_derivation.is_empty() {
            return None;
        }
        let terminal = self
            .bip32_derivation
            .values()
            .flat_map(|origin| origin.derivation().terminal())
            .chain(
                self.tap_bip32_derivation
                    .values()
                    .flat_map(|derivation| derivation.origin.derivation().terminal()),
            )
            .collect::<BTreeSet<_>>();
        if terminal.len() != 1 {
            return None;
        }
        terminal.first().copied()
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
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

    pub const fn is_modifiable(&self) -> bool {
        self.inputs_modifiable | self.outputs_modifiable | self.sighash_single
    }
}

#[cfg(test)]
mod tests {
    #![allow(unused)]

    use std::io::Cursor;
    use std::str::FromStr;

    use amplify::confinement::Confined;
    use commit_verify::mpc::ProtocolId;
    use derive::{DerivationPath, Idx, Keychain, NormalIndex};
    use strict_encoding::StrictDumb;

    use super::*;

    #[test]
    fn psbt_formats() {
        let v0_psbt = Psbt {
            version: PsbtVer::V0,
            tx_version: TxVer::default(),
            fallback_locktime: None,
            inputs: Vec::new(),
            outputs: Vec::new(),
            xpubs: IndexMap::new(),
            tx_modifiable: None,
            proprietary: IndexMap::new(),
            unknown: IndexMap::new(),
        };
        let v2_psbt = Psbt {
            version: PsbtVer::V2,
            tx_version: TxVer::default(),
            fallback_locktime: None,
            inputs: Vec::new(),
            outputs: Vec::new(),
            xpubs: IndexMap::new(),
            tx_modifiable: None,
            proprietary: IndexMap::new(),
            unknown: IndexMap::new(),
        };

        assert_eq!(format!("{v0_psbt}"), "cHNidP8BAAoCAAAAAAAAAAAAAfsEAAAAAAA=");
        assert_eq!(format!("{v2_psbt}"), "cHNidP8BAgQCAAAAAQQBAAEFAQAB+wQCAAAAAA==");

        assert_eq!(format!("{v0_psbt:#}"), "cHNidP8BAAoCAAAAAAAAAAAAAfsEAAAAAAA=");
        assert_eq!(format!("{v2_psbt:#}"), "cHNidP8BAgQCAAAAAQQBAAEFAQAB+wQCAAAAAA==");

        assert_eq!(format!("{v0_psbt:x}"), "70736274ff01000a0200000000000000000001fb040000000000");
        assert_eq!(
            format!("{v2_psbt:x}"),
            "70736274ff01020402000000010401000105010001fb040200000000"
        );

        assert_eq!(format!("{v0_psbt:#x}"), "70736274ff01000a0200000000000000000001fb040000000000");
        assert_eq!(
            format!("{v2_psbt:#x}"),
            "70736274ff01020402000000010401000105010001fb040200000000"
        );

        // format with a specific version
        assert_eq!(format!("{v2_psbt:00}"), "cHNidP8BAAoCAAAAAAAAAAAAAfsEAAAAAAA=");
        assert_eq!(format!("{v2_psbt:01}"), "cHNidP8BAAoCAAAAAAAAAAAAAfsEAAAAAAA=");
        assert_eq!(format!("{v0_psbt:02}"), "cHNidP8BAgQCAAAAAQQBAAEFAQAB+wQCAAAAAA==");

        assert_eq!(format!("{v2_psbt:0}"), "cHNidP8BAAoCAAAAAAAAAAAAAfsEAAAAAAA=");
        assert_eq!(format!("{v2_psbt:1}"), "cHNidP8BAAoCAAAAAAAAAAAAAfsEAAAAAAA=");
        assert_eq!(format!("{v0_psbt:2}"), "cHNidP8BAgQCAAAAAQQBAAEFAQAB+wQCAAAAAA==");

        assert_eq!(format!("{v2_psbt:#0}"), "cHNidP8BAAoCAAAAAAAAAAAAAfsEAAAAAAA=");
        assert_eq!(format!("{v2_psbt:#1}"), "cHNidP8BAAoCAAAAAAAAAAAAAfsEAAAAAAA=");
        assert_eq!(format!("{v0_psbt:#2}"), "cHNidP8BAgQCAAAAAQQBAAEFAQAB+wQCAAAAAA==");

        // error formats
        let result = std::panic::catch_unwind(|| format!("{v0_psbt:03}"));
        assert!(result.is_err(), "Should fail on unsupported psbt version");

        let result = std::panic::catch_unwind(|| format!("{v0_psbt:3}"));
        assert!(result.is_err(), "Should fail on unsupported psbt version");

        let result = std::panic::catch_unwind(|| format!("{v0_psbt:#03}"));
        assert!(result.is_err(), "Should fail on unsupported psbt version");

        let result = std::panic::catch_unwind(|| format!("{v0_psbt:#3}"));
        assert!(result.is_err(), "Should fail on unsupported psbt version");

        let result = std::panic::catch_unwind(|| format!("{v0_psbt:#3x}"));
        assert!(result.is_err(), "Should fail on unsupported psbt version");

        let result = std::panic::catch_unwind(|| format!("{v0_psbt:#03x}"));
        assert!(result.is_err(), "Should fail on unsupported psbt version");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn psbt_serde_roundtrip() {
        let proprietary = IndexMap::from([(
            PropKey::mpc_message(ProtocolId::strict_dumb()),
            ValueData::from(vec![7]),
        )]);

        let unknown = IndexMap::from([(
            5,
            IndexMap::from([(KeyData::strict_dumb(), ValueData::from(vec![9]))]),
        )]);

        let xpub = Xpub::from_str("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8").unwrap();
        let xkeyorigin = XkeyOrigin::from_str("c5e95ba5/86h/1h/0h").unwrap();
        let xpubs = IndexMap::from([(xpub, xkeyorigin.clone())]);

        let derivation_path = DerivationPath::from_str("86h/1h/0h").unwrap();
        let keyorigin = KeyOrigin::new(xkeyorigin.master_fp(), derivation_path);
        let bip32_derivation = IndexMap::from([(LegacyPk::strict_dumb(), keyorigin.clone())]);

        let tx = Tx {
            version: TxVer::V2,
            inputs: Confined::from_checked(vec![TxIn {
                prev_output: Outpoint::strict_dumb(),
                sig_script: SigScript::strict_dumb(),
                sequence: SeqNo::strict_dumb(),
                witness: Witness::strict_dumb(),
            }]),
            outputs: Confined::from_checked(vec![TxOut {
                value: Sats::ZERO,
                script_pubkey: ScriptPubkey::strict_dumb(),
            }]),
            lock_time: LockTime::ZERO,
        };

        let input_1 = Input {
            index: 8,
            previous_outpoint: Outpoint::strict_dumb(),
            sequence_number: Some(SeqNo::ZERO),
            required_time_lock: Some(LockTimestamp::anytime()),
            required_height_lock: Some(LockHeight::anytime()),
            non_witness_tx: Some(tx),
            witness_utxo: Some(TxOut::strict_dumb()),
            partial_sigs: IndexMap::from([(LegacyPk::strict_dumb(), LegacySig::strict_dumb())]),
            sighash_type: Some(SighashType::all()),
            redeem_script: Some(RedeemScript::strict_dumb()),
            witness_script: Some(WitnessScript::strict_dumb()),
            bip32_derivation: bip32_derivation.clone(),
            final_script_sig: Some(SigScript::strict_dumb()),
            final_witness: Some(Witness::strict_dumb()),
            proof_of_reserves: Some(s!("proof_of_reserves")),
            ripemd160: IndexMap::from([(Bytes20::with_fill(5), ByteStr::strict_dumb())]),
            sha256: IndexMap::from([(Bytes32::with_fill(5), ByteStr::strict_dumb())]),
            hash160: IndexMap::from([(Bytes20::with_fill(5), ByteStr::strict_dumb())]),
            hash256: IndexMap::from([(Bytes32::with_fill(5), ByteStr::strict_dumb())]),
            tap_key_sig: Some(Bip340Sig::strict_dumb()),
            tap_script_sig: IndexMap::from([(
                (XOnlyPk::strict_dumb(), TapLeafHash::strict_dumb()),
                Bip340Sig::strict_dumb(),
            )]),
            tap_leaf_script: IndexMap::from([(
                ControlBlock::strict_dumb(),
                LeafScript::strict_dumb(),
            )]),
            tap_bip32_derivation: IndexMap::from([(XOnlyPk::strict_dumb(), TapDerivation {
                leaf_hashes: vec![TapLeafHash::strict_dumb()],
                origin: keyorigin,
            })]),
            tap_internal_key: Some(InternalPk::strict_dumb()),
            tap_merkle_root: Some(TapNodeHash::strict_dumb()),
            proprietary: proprietary.clone(),
            unknown: unknown.clone(),
        };

        let mut input_2 = input_1.clone();
        input_2.index = 3;

        let output = Output {
            index: 1,
            amount: Sats::from_sats(5u64),
            script: ScriptPubkey::strict_dumb(),
            redeem_script: Some(RedeemScript::strict_dumb()),
            witness_script: Some(WitnessScript::strict_dumb()),
            bip32_derivation,
            tap_internal_key: Some(InternalPk::strict_dumb()),
            tap_tree: Some(TapTree::with_single_leaf(LeafScript::strict_dumb())),
            tap_bip32_derivation: IndexMap::from([(
                XOnlyPk::strict_dumb(),
                TapDerivation::with_internal_pk(xkeyorigin, Terminal {
                    keychain: Keychain::INNER,
                    index: NormalIndex::ZERO,
                }),
            )]),
            proprietary: proprietary.clone(),
            unknown: unknown.clone(),
        };

        let tx_modifiable = Some(ModifiableFlags::modifiable());

        let psbt_orig = Psbt {
            version: PsbtVer::V2,
            tx_version: TxVer::V2,
            fallback_locktime: Some(LockTime::ZERO),
            inputs: vec![input_1, input_2],
            outputs: vec![output],
            xpubs,
            tx_modifiable,
            proprietary,
            unknown,
        };

        // CBOR
        let mut buf = Vec::new();
        ciborium::into_writer(&psbt_orig, &mut buf).unwrap();
        let psbt_post: Psbt = ciborium::from_reader(Cursor::new(&buf)).unwrap();
        assert_eq!(psbt_orig, psbt_post);

        // JSON
        let psbt_str = serde_json::to_string(&psbt_orig).unwrap();
        let psbt_post: Psbt = serde_json::from_str(&psbt_str).unwrap();
        assert_eq!(psbt_orig, psbt_post);

        // YAML
        let psbt_str = serde_yaml::to_string(&psbt_orig).unwrap();
        let psbt_post: Psbt = serde_yaml::from_str(&psbt_str).unwrap();
        assert_eq!(psbt_orig, psbt_post);
    }
}
