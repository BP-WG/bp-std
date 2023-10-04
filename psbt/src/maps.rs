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
use std::io::{Read, Write};
use std::iter;

use amplify::IoError;
use bp::{LockTime, Tx, TxVer, VarInt, VarIntArray, Xpub, XpubOrigin};
use indexmap::IndexMap;

use crate::coders::RawBytes;
use crate::keys::KeyValue;
use crate::{
    Decode, DecodeError, Encode, GlobalKey, Input, InputKey, KeyPair, KeyType, ModifiableFlags,
    Output, OutputKey, PropKey, Psbt, PsbtError, PsbtVer,
};

pub type KeyData = VarIntArray<u8>;
pub type ValueData = VarIntArray<u8>;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Map<K: KeyType> {
    pub singular: BTreeMap<K, ValueData>,
    pub plural: BTreeMap<K, BTreeMap<KeyData, ValueData>>,
    pub proprietary: IndexMap<PropKey, ValueData>,
    pub unknown: IndexMap<u8, IndexMap<KeyData, ValueData>>,
}

impl<K: KeyType> Default for Map<K> {
    fn default() -> Self {
        Map {
            singular: empty!(),
            plural: empty!(),
            proprietary: empty!(),
            unknown: empty!(),
        }
    }
}

impl<K: KeyType> Map<K> {
    pub fn parse(stream: &mut impl Read) -> Result<Self, DecodeError> {
        let mut map = Map::<K>::default();

        while let KeyValue::<K>::Pair(pair) = KeyValue::<K>::decode(stream)? {
            if map.singular.contains_key(&pair.key_type) {
                return Err(PsbtError::RepeatedKey(pair.key_type.to_u8()).into());
            }
            if pair.key_type.is_proprietary() {
                let prop_key = PropKey::deserialize(pair.key_data)?;
                if map.proprietary.contains_key(&prop_key) {
                    return Err(PsbtError::RepeatedPropKey(prop_key).into());
                }
                map.proprietary.insert(prop_key, pair.value_data);
            } else if K::STANDARD.contains(&pair.key_type) {
                if pair.key_type.has_key_data() {
                    let submap = map.plural.entry(pair.key_type).or_default();
                    submap.insert(pair.key_data, pair.value_data);
                } else {
                    if !pair.key_data.is_empty() {
                        return Err(PsbtError::NonEmptyKeyData(
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
                    return Err(PsbtError::RepeatedUnknownKey(pair.key_type.to_u8()).into());
                }
                submap.insert(pair.key_data, pair.value_data);
            }
        }

        Ok(map)
    }

    pub fn check(&self, version: PsbtVer) -> Result<(), PsbtError> {
        for key_type in self.singular.keys().chain(self.plural.keys()) {
            if version < key_type.present_since() {
                return Err(PsbtError::UnexpectedKey(key_type.to_u8(), version));
            }
            if Some(version) >= key_type.deprecated_since() {
                return Err(PsbtError::DeprecatedKey(key_type.to_u8(), version));
            }
        }
        for key_type in K::STANDARD {
            if key_type.is_required() {
                if (key_type.has_key_data() && !self.plural.contains_key(&key_type))
                    || (!key_type.has_key_data() && !self.singular.contains_key(&key_type))
                {
                    return Err(PsbtError::RequiredKeyAbsent(key_type.to_u8(), version));
                }
            }
        }
        Ok(())
    }
}

pub trait KeyMap: Sized {
    type Keys: KeyType;
    const PROPRIETARY_TYPE: Self::Keys;

    fn encode_map<'enc>(
        &'enc self,
        version: PsbtVer,
        writer: &mut dyn Write,
    ) -> Result<usize, IoError> {
        let mut counter = 0;

        for key_type in Self::Keys::STANDARD {
            if key_type.is_allowed(version) {
                let mut iter = unsafe {
                    // We need this hack since Rust borrower checker can't see that the
                    // reference actually doesn't escape the scope
                    ::core::mem::transmute::<
                        _,
                        Vec<
                            KeyPair<
                                Self::Keys,
                                Box<dyn Encode + 'static>,
                                Box<dyn Encode + 'static>,
                            >,
                        >,
                    >(self.retrieve_key_pair(*key_type))
                }
                .into_iter();
                while let Some(pair) = iter.next() {
                    counter += pair.encode(writer)?;
                }
            }
        }

        for (key_type, submap) in self.unknown() {
            for (key_data, value_data) in submap {
                let pair = KeyPair::new(
                    Self::Keys::unknown(*key_type),
                    RawBytes(key_data),
                    RawBytes(value_data),
                );
                counter += pair.encode(writer)?;
            }
        }

        for (key_data, value_data) in self.proprietary() {
            let pair = KeyPair::new(Self::PROPRIETARY_TYPE, key_data, RawBytes(value_data));
            counter += pair.encode(writer)?;
        }

        counter += Psbt::SEPARATOR.len();
        writer.write_all(&Psbt::SEPARATOR)?;

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

    fn proprietary(&self) -> &IndexMap<PropKey, ValueData>;
    fn unknown(&self) -> &IndexMap<u8, IndexMap<KeyData, ValueData>>;
    fn proprietary_mut(&mut self) -> &mut IndexMap<PropKey, ValueData>;
    fn unknown_mut(&mut self) -> &mut IndexMap<u8, IndexMap<KeyData, ValueData>>;

    fn retrieve_key_pair<'enc>(
        &'enc self,
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
        self.proprietary_mut().insert(prop_key, value_data);
    }

    fn insert_unknown(&mut self, key_type: u8, key_data: KeyData, value_data: ValueData) {
        self.unknown_mut().entry(key_type).or_default().insert(key_data, value_data);
    }
}

macro_rules! once {
    ($key:ident, $expr:expr) => {
        vec![KeyPair::boxed(Self::Keys::$key, (), $expr)]
    };
}
macro_rules! option {
    ($key:ident, $expr:expr) => {
        $expr.as_ref().map(|e| KeyPair::boxed(Self::Keys::$key, (), e)).into_iter().collect()
    };
}
macro_rules! iter {
    ($key:ident, $expr:expr) => {
        $expr.iter().map(|(k, v)| KeyPair::boxed(Self::Keys::$key, k, v)).collect()
    };
}

impl KeyMap for Psbt {
    type Keys = GlobalKey;
    const PROPRIETARY_TYPE: Self::Keys = GlobalKey::Proprietary;

    fn proprietary(&self) -> &IndexMap<PropKey, ValueData> { &self.proprietary }
    fn unknown(&self) -> &IndexMap<u8, IndexMap<KeyData, ValueData>> { &self.unknown }
    fn proprietary_mut(&mut self) -> &mut IndexMap<PropKey, ValueData> { &mut self.proprietary }
    fn unknown_mut(&mut self) -> &mut IndexMap<u8, IndexMap<KeyData, ValueData>> {
        &mut self.unknown
    }

    fn retrieve_key_pair<'enc>(
        &'enc self,
        key_type: Self::Keys,
    ) -> Vec<KeyPair<Self::Keys, Box<dyn Encode + 'enc>, Box<dyn Encode + 'enc>>> {
        match key_type {
            GlobalKey::UnsignedTx => once!(UnsignedTx, self.to_unsigned_tx()),
            GlobalKey::Xpub => iter!(Xpub, self.xpubs),
            GlobalKey::TxVersion => once!(TxVersion, &self.tx_version),
            GlobalKey::FallbackLocktime => option!(FallbackLocktime, self.fallback_locktime),
            GlobalKey::InputCount => once!(InputCount, VarInt::with(self.inputs.len())),
            GlobalKey::OutputCount => once!(OutputCount, VarInt::with(self.inputs.len())),
            GlobalKey::TxModifiable => option!(FallbackLocktime, self.tx_modifiable),
            GlobalKey::Version => once!(OutputCount, &self.version),

            GlobalKey::Proprietary | GlobalKey::Unknown(_) => unreachable!(),
        }
    }

    fn insert_singular(
        &mut self,
        key_type: Self::Keys,
        value_data: ValueData,
    ) -> Result<(), PsbtError> {
        match key_type {
            GlobalKey::UnsignedTx => self.reset_from_unsigned_tx(Tx::deserialize(value_data)?),
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
                let origin = XpubOrigin::deserialize(value_data)?;
                self.push_xpub(xpub, origin);
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

    fn proprietary(&self) -> &IndexMap<PropKey, ValueData> { &self.proprietary }
    fn unknown(&self) -> &IndexMap<u8, IndexMap<KeyData, ValueData>> { &self.unknown }
    fn proprietary_mut(&mut self) -> &mut IndexMap<PropKey, ValueData> { &mut self.proprietary }
    fn unknown_mut(&mut self) -> &mut IndexMap<u8, IndexMap<KeyData, ValueData>> {
        &mut self.unknown
    }

    fn retrieve_key_pair<'enc>(
        &'enc self,
        key_type: Self::Keys,
    ) -> Vec<KeyPair<Self::Keys, Box<dyn Encode + 'enc>, Box<dyn Encode + 'enc>>> {
        todo!()
    }

    fn insert_singular(
        &mut self,
        key_type: Self::Keys,
        value_data: ValueData,
    ) -> Result<(), PsbtError> {
        match key_type {
            InputKey::NonWitnessUtxo => {}
            InputKey::WitnessUtxo => {}
            InputKey::SighashType => {}
            InputKey::RedeemScript => {}
            InputKey::WitnessScript => {}
            InputKey::FinalScriptSig => {}
            InputKey::FinalWitness => {}
            InputKey::PorCommitment => {}

            InputKey::PreviousTxid => {}
            InputKey::OutputIndex => {}
            InputKey::Sequence => {}
            InputKey::RequiredTimeLock => {}
            InputKey::RequiredHeighLock => {}

            InputKey::TapKeySig => {}
            InputKey::TapInternalKey => {}
            InputKey::TapMerkleRoot => {}

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
            | InputKey::RequiredHeighLock => unreachable!(),

            InputKey::PartialSig => {}
            InputKey::Bip32Derivation => {}
            InputKey::Ripemd160 => {}
            InputKey::Sha256 => {}
            InputKey::Hash160 => {}
            InputKey::Hash256 => {}
            InputKey::TapScriptSig => {}
            InputKey::TapLeafScript => {}
            InputKey::TapBip32Derivation => {}

            InputKey::Proprietary | InputKey::Unknown(_) => unreachable!(),
        }
        Ok(())
    }
}

impl KeyMap for Output {
    type Keys = OutputKey;
    const PROPRIETARY_TYPE: Self::Keys = OutputKey::Proprietary;

    fn proprietary(&self) -> &IndexMap<PropKey, ValueData> { &self.proprietary }
    fn unknown(&self) -> &IndexMap<u8, IndexMap<KeyData, ValueData>> { &self.unknown }
    fn proprietary_mut(&mut self) -> &mut IndexMap<PropKey, ValueData> { &mut self.proprietary }
    fn unknown_mut(&mut self) -> &mut IndexMap<u8, IndexMap<KeyData, ValueData>> {
        &mut self.unknown
    }

    fn retrieve_key_pair<'enc>(
        &'enc self,
        key_type: Self::Keys,
    ) -> Vec<KeyPair<Self::Keys, Box<dyn Encode + 'enc>, Box<dyn Encode + 'enc>>> {
        todo!()
    }

    fn insert_singular(
        &mut self,
        key_type: Self::Keys,
        value_data: ValueData,
    ) -> Result<(), PsbtError> {
        todo!()
    }

    fn insert_plural(
        &mut self,
        key_type: Self::Keys,
        key_data: KeyData,
        value_data: ValueData,
    ) -> Result<(), PsbtError> {
        todo!()
    }
}
