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
use std::io::Read;

use bp::{LockTime, Tx, TxVer, VarInt, VarIntArray, Xpub, XpubOrigin};
use indexmap::IndexMap;

use crate::keys::KeyValue;
use crate::{
    Decode, DecodeError, GlobalKey, Input, InputKey, KeyType, ModifiableFlags, Output, OutputKey,
    PropKey, Psbt, PsbtError, PsbtVer,
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

    fn populate(&mut self, map: Map<Self::Keys>, version: PsbtVer) -> Result<(), PsbtError> {
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

    fn proprietary_mut(&mut self) -> &mut IndexMap<PropKey, ValueData>;
    fn unknown_mut(&mut self) -> &mut IndexMap<u8, IndexMap<KeyData, ValueData>>;

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

impl KeyMap for Psbt {
    type Keys = GlobalKey;

    fn proprietary_mut(&mut self) -> &mut IndexMap<PropKey, ValueData> { &mut self.proprietary }

    fn unknown_mut(&mut self) -> &mut IndexMap<u8, IndexMap<KeyData, ValueData>> {
        &mut self.unknown
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

    fn proprietary_mut(&mut self) -> &mut IndexMap<PropKey, ValueData> { &mut self.proprietary }

    fn unknown_mut(&mut self) -> &mut IndexMap<u8, IndexMap<KeyData, ValueData>> {
        &mut self.unknown
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

impl KeyMap for Output {
    type Keys = OutputKey;

    fn proprietary_mut(&mut self) -> &mut IndexMap<PropKey, ValueData> { &mut self.proprietary }

    fn unknown_mut(&mut self) -> &mut IndexMap<u8, IndexMap<KeyData, ValueData>> {
        &mut self.unknown
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
