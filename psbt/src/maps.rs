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

use std::collections::BTreeMap;
use std::io::{Read, Write};

use amplify::{Bytes20, Bytes32, IoError};
use derive::{
    Bip340Sig, ByteStr, ControlBlock, InternalPk, KeyOrigin, LeafScript, LegacyPk, LegacySig,
    LockHeight, LockTime, LockTimestamp, RedeemScript, Sats, ScriptPubkey, SeqNo, SigScript,
    SighashType, TapDerivation, TapLeafHash, TapNodeHash, TapTree, Tx, TxOut, TxVer, Txid, VarInt,
    Vout, Witness, WitnessScript, XOnlyPk, XkeyOrigin, Xpub,
};
use indexmap::IndexMap;

use crate::coders::RawBytes;
use crate::keys::KeyValue;
use crate::{
    Decode, DecodeError, Encode, GlobalKey, Input, InputKey, KeyPair, KeyType, ModifiableFlags,
    Output, OutputKey, PropKey, Psbt, PsbtError, PsbtVer, UnsignedTx,
};

pub type KeyData = ByteStr;

#[derive(Wrapper, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug, Display, From)]
#[wrapper(Deref, Index, RangeOps, AsSlice, BorrowSlice, Hex)]
#[display(LowerHex)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct ValueData(ByteStr);

impl From<Vec<u8>> for ValueData {
    fn from(vec: Vec<u8>) -> Self { ByteStr::from(vec).into() }
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error)]
#[display("proprietary key '{0}' is already present")]
pub struct KeyAlreadyPresent(pub PropKey);

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display)]
#[display(lowercase)]
pub enum MapName {
    Global,
    Input,
    Output,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Map<K: KeyType> {
    pub name: MapName,
    pub singular: BTreeMap<K, ValueData>,
    pub plural: BTreeMap<K, BTreeMap<KeyData, ValueData>>,
    pub proprietary: IndexMap<PropKey, ValueData>,
    pub unknown: IndexMap<u8, IndexMap<KeyData, ValueData>>,
}

impl<K: KeyType> Map<K> {
    fn new(name: MapName) -> Self {
        Map {
            name,
            singular: empty!(),
            plural: empty!(),
            proprietary: empty!(),
            unknown: empty!(),
        }
    }

    pub fn parse(name: MapName, stream: &mut impl Read) -> Result<Self, DecodeError> {
        let mut map = Map::<K>::new(name);

        while let KeyValue::<K>::Pair(pair) = KeyValue::<K>::decode(stream)? {
            if map.singular.contains_key(&pair.key_type) {
                return Err(PsbtError::RepeatedKey(name, pair.key_type.to_u8()).into());
            }
            if pair.key_type.is_proprietary() {
                let prop_key = PropKey::deserialize(pair.key_data)?;
                if map.proprietary.contains_key(&prop_key) {
                    return Err(PsbtError::RepeatedPropKey(name, prop_key).into());
                }
                map.proprietary.insert(prop_key, pair.value_data);
            } else if K::STANDARD.contains(&pair.key_type) {
                if pair.key_type.has_key_data() {
                    let submap = map.plural.entry(pair.key_type).or_default();
                    if submap.insert(pair.key_data, pair.value_data).is_some() {
                        return Err(PsbtError::RepeatedKey(name, pair.key_type.to_u8()).into());
                    }
                } else {
                    if !pair.key_data.is_empty() {
                        return Err(PsbtError::NonEmptyKeyData(
                            name,
                            pair.key_type.to_u8(),
                            pair.key_data,
                        )
                        .into());
                    }
                    map.singular.insert(pair.key_type, pair.value_data);
                }
            } else {
                let submap = map.unknown.entry(pair.key_type.to_u8()).or_default();
                if submap.contains_key(&pair.key_data) {
                    return Err(PsbtError::RepeatedUnknownKey(name, pair.key_type.to_u8()).into());
                }
                submap.insert(pair.key_data, pair.value_data);
            }
        }

        Ok(map)
    }

    pub fn check(&self, version: PsbtVer) -> Result<(), PsbtError> {
        for key_type in self.singular.keys().chain(self.plural.keys()) {
            if version < key_type.present_since() {
                return Err(PsbtError::UnexpectedKey(self.name, key_type.to_u8(), version));
            }
            if matches!(key_type.deprecated_since(), Some(depr) if version >= depr) {
                return Err(PsbtError::DeprecatedKey(self.name, key_type.to_u8(), version));
            }
        }
        for key_type in K::STANDARD {
            if key_type.is_required()
                && version >= key_type.present_since()
                && matches!(key_type.deprecated_since(), Some(depr) if version < depr)
                && ((key_type.has_key_data() && !self.plural.contains_key(key_type))
                    || (!key_type.has_key_data() && !self.singular.contains_key(key_type)))
            {
                return Err(PsbtError::RequiredKeyAbsent(self.name, key_type.to_u8(), version));
            }
        }
        Ok(())
    }
}

pub trait KeyMap: Sized {
    type Keys: KeyType;
    const PROPRIETARY_TYPE: Self::Keys;

    fn encode_map(&self, version: PsbtVer, writer: &mut dyn Write) -> Result<usize, IoError> {
        let mut counter = 0;

        for key_type in Self::Keys::STANDARD.iter().filter(|kt| kt.is_allowed(version)) {
            let iter = unsafe {
                // We need this hack since Rust borrower checker can't see that the
                // reference actually doesn't escape the scope
                #[allow(clippy::missing_transmute_annotations)]
                ::core::mem::transmute::<
                    _,
                    Vec<KeyPair<Self::Keys, Box<dyn Encode + 'static>, Box<dyn Encode + 'static>>>,
                >(self.retrieve_key_pair(version, *key_type))
            }
            .into_iter();
            for pair in iter {
                counter += pair.encode(writer)?;
            }
        }

        for (key_type, submap) in self._unknown_map() {
            for (key_data, value_data) in submap {
                let pair = KeyPair::new(
                    Self::Keys::unknown(*key_type),
                    RawBytes(key_data),
                    RawBytes(value_data),
                );
                counter += pair.encode(writer)?;
            }
        }

        for (key_data, value_data) in self._proprietary_map() {
            let pair = KeyPair::new(Self::PROPRIETARY_TYPE, key_data, RawBytes(value_data));
            counter += pair.encode(writer)?;
        }

        counter += 1;
        writer.write_all(&[0])?;

        Ok(counter)
    }

    fn parse_map(&mut self, version: PsbtVer, map: Map<Self::Keys>) -> Result<(), PsbtError> {
        map.check(version)?;

        for (k, v) in map.singular {
            self.insert_singular(k, v)?;
        }
        for (k, submap) in map.plural {
            for (d, v) in submap {
                self.insert_plural(k, d, v)?;
            }
        }
        for (p, v) in map.proprietary {
            self.insert_proprietary(p, v);
        }
        for (k, submap) in map.unknown {
            for (d, v) in submap {
                self.insert_unknown(k, d, v);
            }
        }
        Ok(())
    }

    #[doc(hidden)]
    fn _proprietary_map(&self) -> &IndexMap<PropKey, ValueData>;
    #[doc(hidden)]
    fn _proprietary_map_mut(&mut self) -> &mut IndexMap<PropKey, ValueData>;

    fn has_proprietary(&self, key: &PropKey) -> bool { self.proprietary(key).is_some() }
    fn proprietary(&self, key: &PropKey) -> Option<&ValueData> { self._proprietary_map().get(key) }
    fn proprietary_mut(&mut self, key: &PropKey) -> Option<&mut ValueData> {
        self._proprietary_map_mut().get_mut(key)
    }
    fn push_proprietary(
        &mut self,
        key: PropKey,
        value: impl Into<ValueData>,
    ) -> Result<bool, KeyAlreadyPresent> {
        let value = value.into();
        if let Some(existing) = self.proprietary(&key) {
            if &value != existing {
                Err(KeyAlreadyPresent(key))
            } else {
                Ok(false)
            }
        } else {
            self._proprietary_map_mut().insert(key, value);
            Ok(true)
        }
    }
    fn remove_proprietary(&mut self, key: &PropKey) -> Option<ValueData> {
        self._proprietary_map_mut().shift_remove(key)
    }

    #[doc(hidden)]
    fn _unknown_map(&self) -> &IndexMap<u8, IndexMap<KeyData, ValueData>>;
    #[doc(hidden)]
    fn _unknown_map_mut(&mut self) -> &mut IndexMap<u8, IndexMap<KeyData, ValueData>>;

    #[allow(clippy::type_complexity)]
    fn retrieve_key_pair<'enc>(
        &'enc self,
        version: PsbtVer,
        key_type: Self::Keys,
    ) -> Vec<KeyPair<Self::Keys, Box<dyn Encode + 'enc>, Box<dyn Encode + 'enc>>>;

    fn insert_singular(
        &mut self,
        key_type: Self::Keys,
        value_data: ValueData,
    ) -> Result<(), PsbtError>;

    fn insert_plural(
        &mut self,
        key_type: Self::Keys,
        key_data: KeyData,
        value_data: ValueData,
    ) -> Result<(), PsbtError>;

    fn insert_proprietary(&mut self, prop_key: PropKey, value_data: ValueData) {
        self._proprietary_map_mut().insert(prop_key, value_data);
    }

    fn insert_unknown(&mut self, key_type: u8, key_data: KeyData, value_data: ValueData) {
        self._unknown_map_mut().entry(key_type).or_default().insert(key_data, value_data);
    }
}

macro_rules! once {
    ($expr:expr) => {
        vec![KeyPair::boxed(Self::PROPRIETARY_TYPE, (), $expr)]
    };
}
macro_rules! option {
    ($expr:expr) => {
        $expr.as_ref().map(|e| KeyPair::boxed(Self::PROPRIETARY_TYPE, (), e)).into_iter().collect()
    };
}
macro_rules! option_raw {
    ($expr:expr) => {
        $expr
            .as_ref()
            .map(|e| KeyPair::boxed(Self::PROPRIETARY_TYPE, (), RawBytes(e)))
            .into_iter()
            .collect()
    };
}
macro_rules! iter {
    ($expr:expr) => {
        $expr.iter().map(|(k, v)| KeyPair::boxed(Self::PROPRIETARY_TYPE, k, v)).collect()
    };
}
macro_rules! iter_raw {
    ($expr:expr) => {
        $expr.iter().map(|(k, v)| KeyPair::boxed(Self::PROPRIETARY_TYPE, k, RawBytes(v))).collect()
    };
}

impl KeyMap for Psbt {
    type Keys = GlobalKey;
    const PROPRIETARY_TYPE: Self::Keys = GlobalKey::Proprietary;

    fn _proprietary_map(&self) -> &IndexMap<PropKey, ValueData> { &self.proprietary }
    fn _unknown_map(&self) -> &IndexMap<u8, IndexMap<KeyData, ValueData>> { &self.unknown }
    fn _proprietary_map_mut(&mut self) -> &mut IndexMap<PropKey, ValueData> {
        &mut self.proprietary
    }
    fn _unknown_map_mut(&mut self) -> &mut IndexMap<u8, IndexMap<KeyData, ValueData>> {
        &mut self.unknown
    }

    fn retrieve_key_pair<'enc>(
        &'enc self,
        version: PsbtVer,
        key_type: Self::Keys,
    ) -> Vec<KeyPair<Self::Keys, Box<dyn Encode + 'enc>, Box<dyn Encode + 'enc>>> {
        let mut pairs = match key_type {
            GlobalKey::UnsignedTx => once!(self.to_unsigned_tx()),
            GlobalKey::Xpub => iter!(self.xpubs),
            GlobalKey::TxVersion => once!(self.tx_version),
            GlobalKey::FallbackLocktime => option!(self.fallback_locktime),
            GlobalKey::InputCount => once!(VarInt::with(self.inputs.len())),
            GlobalKey::OutputCount => once!(VarInt::with(self.outputs.len())),
            GlobalKey::TxModifiable => option!(self.tx_modifiable),
            GlobalKey::Version => once!(version),

            GlobalKey::Proprietary | GlobalKey::Unknown(_) => unreachable!(),
        };
        pairs.iter_mut().for_each(|pair| pair.key_type = key_type);
        pairs
    }

    fn insert_singular(
        &mut self,
        key_type: Self::Keys,
        value_data: ValueData,
    ) -> Result<(), PsbtError> {
        match key_type {
            GlobalKey::UnsignedTx => {
                self.reset_from_unsigned_tx(UnsignedTx::deserialize(value_data)?)
            }
            GlobalKey::TxVersion => self.tx_version = TxVer::deserialize(value_data)?,
            GlobalKey::FallbackLocktime => {
                self.fallback_locktime = Some(LockTime::deserialize(value_data)?)
            }
            GlobalKey::InputCount => self.reset_inputs(VarInt::deserialize(value_data)?.to_usize()),
            GlobalKey::OutputCount => {
                self.reset_outputs(VarInt::deserialize(value_data)?.to_usize())
            }
            GlobalKey::TxModifiable => {
                self.tx_modifiable = Some(ModifiableFlags::deserialize(value_data)?)
            }
            GlobalKey::Version => self.version = PsbtVer::deserialize(value_data)?,

            GlobalKey::Xpub => unreachable!(),
            GlobalKey::Proprietary | GlobalKey::Unknown(_) => unreachable!(),
        }
        Ok(())
    }

    fn insert_plural(
        &mut self,
        key_type: Self::Keys,
        key_data: KeyData,
        value_data: ValueData,
    ) -> Result<(), PsbtError> {
        match key_type {
            GlobalKey::Xpub => {
                let xpub = Xpub::deserialize(key_data)?;
                let origin = XkeyOrigin::deserialize(value_data)?;
                self.xpubs.insert(xpub, origin);
            }

            GlobalKey::UnsignedTx
            | GlobalKey::TxVersion
            | GlobalKey::FallbackLocktime
            | GlobalKey::InputCount
            | GlobalKey::OutputCount
            | GlobalKey::TxModifiable
            | GlobalKey::Version => unreachable!(),

            GlobalKey::Proprietary | GlobalKey::Unknown(_) => unreachable!(),
        }
        Ok(())
    }
}

impl KeyMap for Input {
    type Keys = InputKey;
    const PROPRIETARY_TYPE: Self::Keys = InputKey::Proprietary;

    fn _proprietary_map(&self) -> &IndexMap<PropKey, ValueData> { &self.proprietary }
    fn _unknown_map(&self) -> &IndexMap<u8, IndexMap<KeyData, ValueData>> { &self.unknown }
    fn _proprietary_map_mut(&mut self) -> &mut IndexMap<PropKey, ValueData> {
        &mut self.proprietary
    }
    fn _unknown_map_mut(&mut self) -> &mut IndexMap<u8, IndexMap<KeyData, ValueData>> {
        &mut self.unknown
    }

    fn retrieve_key_pair<'enc>(
        &'enc self,
        _: PsbtVer,
        key_type: Self::Keys,
    ) -> Vec<KeyPair<Self::Keys, Box<dyn Encode + 'enc>, Box<dyn Encode + 'enc>>> {
        let mut pairs = match key_type {
            InputKey::NonWitnessUtxo => option!(self.non_witness_tx),
            InputKey::WitnessUtxo => option!(self.witness_utxo),
            InputKey::PartialSig => iter!(self.partial_sigs),
            InputKey::SighashType => option!(self.sighash_type),
            InputKey::RedeemScript => option!(self.redeem_script),
            InputKey::WitnessScript => option!(self.witness_script),
            InputKey::Bip32Derivation => iter!(self.bip32_derivation),
            InputKey::FinalScriptSig => option!(self.final_script_sig),
            InputKey::FinalWitness => option!(self.final_witness),
            InputKey::PorCommitment => option_raw!(self.proof_of_reserves),
            InputKey::Ripemd160 => iter_raw!(self.ripemd160),
            InputKey::Sha256 => iter_raw!(self.sha256),
            InputKey::Hash160 => iter_raw!(self.hash160),
            InputKey::Hash256 => iter_raw!(self.hash256),
            InputKey::PreviousTxid => once!(self.previous_outpoint.txid),
            InputKey::OutputIndex => once!(self.previous_outpoint.vout),
            InputKey::Sequence => option!(self.sequence_number),
            InputKey::RequiredTimeLock => option!(self.required_time_lock),
            InputKey::RequiredHeightLock => option!(self.required_height_lock),
            InputKey::TapKeySig => option!(self.tap_key_sig),
            InputKey::TapScriptSig => iter!(self.tap_script_sig),
            InputKey::TapLeafScript => iter!(self.tap_leaf_script),
            InputKey::TapBip32Derivation => {
                iter!(self.tap_bip32_derivation)
            }
            InputKey::TapInternalKey => option!(self.tap_internal_key),
            InputKey::TapMerkleRoot => option!(self.tap_merkle_root),

            InputKey::Proprietary | InputKey::Unknown(_) => unreachable!(),
        };
        pairs.iter_mut().for_each(|pair| pair.key_type = key_type);
        pairs
    }

    fn insert_singular(
        &mut self,
        key_type: Self::Keys,
        value_data: ValueData,
    ) -> Result<(), PsbtError> {
        match key_type {
            InputKey::NonWitnessUtxo => self.non_witness_tx = Some(Tx::deserialize(value_data)?),
            InputKey::WitnessUtxo => self.witness_utxo = Some(TxOut::deserialize(value_data)?),
            InputKey::SighashType => {
                self.sighash_type = Some(SighashType::deserialize(value_data)?)
            }
            InputKey::RedeemScript => {
                self.redeem_script = Some(RedeemScript::deserialize(value_data)?)
            }
            InputKey::WitnessScript => {
                self.witness_script = Some(WitnessScript::deserialize(value_data)?)
            }
            InputKey::FinalScriptSig => {
                self.final_script_sig = Some(SigScript::deserialize(value_data)?)
            }
            InputKey::FinalWitness => self.final_witness = Some(Witness::deserialize(value_data)?),
            InputKey::PorCommitment => {
                let bytes = RawBytes::<Vec<u8>>::deserialize(value_data)?;
                let por = String::from_utf8(bytes.0).map_err(PsbtError::InvalidPorString)?;
                self.proof_of_reserves = Some(por)
            }

            InputKey::PreviousTxid => self.previous_outpoint.txid = Txid::deserialize(value_data)?,
            InputKey::OutputIndex => self.previous_outpoint.vout = Vout::deserialize(value_data)?,
            InputKey::Sequence => self.sequence_number = Some(SeqNo::deserialize(value_data)?),
            InputKey::RequiredTimeLock => {
                self.required_time_lock = Some(LockTimestamp::deserialize(value_data)?)
            }
            InputKey::RequiredHeightLock => {
                self.required_height_lock = Some(LockHeight::deserialize(value_data)?)
            }

            InputKey::TapKeySig => self.tap_key_sig = Some(Bip340Sig::deserialize(value_data)?),
            InputKey::TapInternalKey => {
                self.tap_internal_key = Some(InternalPk::deserialize(value_data)?)
            }
            InputKey::TapMerkleRoot => {
                self.tap_merkle_root = Some(TapNodeHash::deserialize(value_data)?)
            }

            InputKey::PartialSig
            | InputKey::Bip32Derivation
            | InputKey::Ripemd160
            | InputKey::Sha256
            | InputKey::Hash160
            | InputKey::Hash256
            | InputKey::TapScriptSig
            | InputKey::TapLeafScript
            | InputKey::TapBip32Derivation => unreachable!(),

            InputKey::Proprietary | InputKey::Unknown(_) => unreachable!(),
        }
        Ok(())
    }

    fn insert_plural(
        &mut self,
        key_type: Self::Keys,
        key_data: KeyData,
        value_data: ValueData,
    ) -> Result<(), PsbtError> {
        match key_type {
            InputKey::NonWitnessUtxo
            | InputKey::WitnessUtxo
            | InputKey::SighashType
            | InputKey::RedeemScript
            | InputKey::WitnessScript
            | InputKey::FinalScriptSig
            | InputKey::FinalWitness
            | InputKey::PorCommitment
            | InputKey::TapKeySig
            | InputKey::TapInternalKey
            | InputKey::TapMerkleRoot => unreachable!(),

            InputKey::PreviousTxid
            | InputKey::OutputIndex
            | InputKey::Sequence
            | InputKey::RequiredTimeLock
            | InputKey::RequiredHeightLock => unreachable!(),

            InputKey::PartialSig => {
                let pk = LegacyPk::deserialize(key_data)?;
                let sig = LegacySig::deserialize(value_data)?;
                self.partial_sigs.insert(pk, sig);
            }
            InputKey::Bip32Derivation => {
                let pk = LegacyPk::deserialize(key_data)?;
                let origin = KeyOrigin::deserialize(value_data)?;
                self.bip32_derivation.insert(pk, origin);
            }
            InputKey::Ripemd160 => {
                let hash = Bytes20::deserialize(key_data)?;
                self.ripemd160.insert(hash, value_data.into());
            }
            InputKey::Sha256 => {
                let hash = Bytes32::deserialize(key_data)?;
                self.sha256.insert(hash, value_data.into());
            }
            InputKey::Hash160 => {
                let hash = Bytes20::deserialize(key_data)?;
                self.hash160.insert(hash, value_data.into());
            }
            InputKey::Hash256 => {
                let hash = Bytes32::deserialize(key_data)?;
                self.hash256.insert(hash, value_data.into());
            }
            InputKey::TapScriptSig => {
                let (internal_pk, leaf_hash) = <(XOnlyPk, TapLeafHash)>::deserialize(key_data)?;
                let sig = Bip340Sig::deserialize(value_data)?;
                self.tap_script_sig.insert((internal_pk, leaf_hash), sig);
            }
            InputKey::TapLeafScript => {
                let control_block = ControlBlock::deserialize(key_data)?;
                let leaf_script = LeafScript::deserialize(value_data)?;
                self.tap_leaf_script.insert(control_block, leaf_script);
            }
            InputKey::TapBip32Derivation => {
                let pk = XOnlyPk::deserialize(key_data)?;
                let derivation = TapDerivation::deserialize(value_data)?;
                self.tap_bip32_derivation.insert(pk, derivation);
            }

            InputKey::Proprietary | InputKey::Unknown(_) => unreachable!(),
        }
        Ok(())
    }
}

impl KeyMap for Output {
    type Keys = OutputKey;
    const PROPRIETARY_TYPE: Self::Keys = OutputKey::Proprietary;

    fn _proprietary_map(&self) -> &IndexMap<PropKey, ValueData> { &self.proprietary }
    fn _proprietary_map_mut(&mut self) -> &mut IndexMap<PropKey, ValueData> {
        &mut self.proprietary
    }

    fn _unknown_map(&self) -> &IndexMap<u8, IndexMap<KeyData, ValueData>> { &self.unknown }
    fn _unknown_map_mut(&mut self) -> &mut IndexMap<u8, IndexMap<KeyData, ValueData>> {
        &mut self.unknown
    }

    fn retrieve_key_pair<'enc>(
        &'enc self,
        _: PsbtVer,
        key_type: Self::Keys,
    ) -> Vec<KeyPair<Self::Keys, Box<dyn Encode + 'enc>, Box<dyn Encode + 'enc>>> {
        let mut pairs = match key_type {
            OutputKey::RedeemScript => option!(self.redeem_script),
            OutputKey::WitnessScript => option!(self.witness_script),
            OutputKey::Bip32Derivation => iter!(self.bip32_derivation),
            OutputKey::Amount => once!(self.amount),
            OutputKey::Script => once!(&self.script),
            OutputKey::TapInternalKey => option!(self.tap_internal_key),
            OutputKey::TapTree => option!(self.tap_tree),
            OutputKey::TapBip32Derivation => {
                iter!(self.tap_bip32_derivation)
            }

            OutputKey::Proprietary | OutputKey::Unknown(_) => unreachable!(),
        };
        pairs.iter_mut().for_each(|pair| pair.key_type = key_type);
        pairs
    }

    fn insert_singular(
        &mut self,
        key_type: Self::Keys,
        value_data: ValueData,
    ) -> Result<(), PsbtError> {
        match key_type {
            OutputKey::RedeemScript => {
                self.redeem_script = Some(RedeemScript::deserialize(value_data)?)
            }
            OutputKey::WitnessScript => {
                self.witness_script = Some(WitnessScript::deserialize(value_data)?)
            }
            OutputKey::Amount => self.amount = Sats::deserialize(value_data)?,
            OutputKey::Script => self.script = ScriptPubkey::deserialize(value_data)?,
            OutputKey::TapInternalKey => {
                self.tap_internal_key = Some(InternalPk::deserialize(value_data)?)
            }
            OutputKey::TapTree => self.tap_tree = Some(TapTree::deserialize(value_data)?),

            OutputKey::Bip32Derivation | OutputKey::TapBip32Derivation => unreachable!(),

            OutputKey::Proprietary | OutputKey::Unknown(_) => unreachable!(),
        }
        Ok(())
    }

    fn insert_plural(
        &mut self,
        key_type: Self::Keys,
        key_data: KeyData,
        value_data: ValueData,
    ) -> Result<(), PsbtError> {
        match key_type {
            OutputKey::RedeemScript
            | OutputKey::WitnessScript
            | OutputKey::Amount
            | OutputKey::Script
            | OutputKey::TapInternalKey
            | OutputKey::TapTree => unreachable!(),

            OutputKey::Bip32Derivation => {
                let pk = LegacyPk::deserialize(key_data)?;
                let origin = KeyOrigin::deserialize(value_data)?;
                self.bip32_derivation.insert(pk, origin);
            }
            OutputKey::TapBip32Derivation => {
                let pk = XOnlyPk::deserialize(key_data)?;
                let derivation = TapDerivation::deserialize(value_data)?;
                self.tap_bip32_derivation.insert(pk, derivation);
            }

            OutputKey::Proprietary | OutputKey::Unknown(_) => unreachable!(),
        }
        Ok(())
    }
}
