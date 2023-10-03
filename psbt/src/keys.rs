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

use std::fmt::Debug;
use std::hash::Hash;
use std::io::Sink;

use bp::VarInt;

use crate::{Decode, Encode};

pub trait KeyType: Copy + Ord + Eq + Hash + Debug + Encode + Decode {
    fn byte_len(&self) -> usize;
    fn try_from_u8(val: u8) -> Result<Self, u8>;
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[repr(u8)]
pub enum GlobalKey {
    /// `PSBT_GLOBAL_UNSIGNED_TX`
    UnsignedTx = 0x00,

    /// `PSBT_GLOBAL_XPUB`
    ///
    /// The master key fingerprint as defined by BIP 32 concatenated with the derivation path of
    /// the public key. The derivation path is represented as 32-bit little endian unsigned integer
    /// indexes concatenated with each other. The number of 32 bit unsigned integer indexes must
    /// match the depth provided in the extended public key.
    Xpub = 0x01,

    /// `PSBT_GLOBAL_TX_VERSION`
    ///
    /// The 32-bit little endian signed integer representing the version number of the transaction
    /// being created. Note that this is not the same as the PSBT version number specified by the
    /// PSBT_GLOBAL_VERSION field.
    TxVersion = 0x02,

    /// `PSBT_GLOBAL_FALLBACK_LOCKTIME`
    ///
    /// The 32-bit little endian unsigned integer representing the transaction locktime to use if
    /// no inputs specify a required locktime.
    FallbackLocktime = 0x03,

    /// `PSBT_GLOBAL_INPUT_COUNT`
    ///
    /// Compact size unsigned integer representing the number of inputs in this PSBT.
    InputCount = 0x04,

    /// `PSBT_GLOBAL_OUTPUT_COUNT`
    ///
    /// Compact size unsigned integer representing the number of outputs in this PSBT.
    OutputCount = 0x05,

    /// `PSBT_GLOBAL_TX_MODIFIABLE`
    ///
    /// An 8 bit little endian unsigned integer as a bitfield for various transaction modification
    /// flags. Bit 0 is the Inputs Modifiable Flag and indicates whether inputs can be modified.
    /// Bit 1 is the Outputs Modifiable Flag and indicates whether outputs can be modified. Bit 2
    /// is the Has SIGHASH_SINGLE flag and indicates whether the transaction has a SIGHASH_SINGLE
    /// signature who's input and output pairing must be preserved. Bit 2 essentially indicates
    /// that the Constructor must iterate the inputs to determine whether and how to add an input.
    TxModifiable = 0x06,

    /// `PSBT_GLOBAL_VERSION`
    ///
    /// The 32-bit little endian unsigned integer representing the version number of this PSBT. If
    /// omitted, the version number is 0.
    Version = 0xFB,

    /// `PSBT_GLOBAL_PROPRIETARY`
    Proprietary = 0xFC,
}

impl KeyType for GlobalKey {
    fn byte_len(&self) -> usize { 1 }

    fn try_from_u8(val: u8) -> Result<Self, u8> {
        Ok(match val {
            x if x == Self::UnsignedTx as u8 => Self::UnsignedTx,
            x if x == Self::Xpub as u8 => Self::Xpub,
            x if x == Self::TxVersion as u8 => Self::TxVersion,
            x if x == Self::FallbackLocktime as u8 => Self::FallbackLocktime,
            x if x == Self::InputCount as u8 => Self::InputCount,
            x if x == Self::OutputCount as u8 => Self::OutputCount,
            x if x == Self::TxModifiable as u8 => Self::TxModifiable,
            x if x == Self::Version as u8 => Self::Version,
            x if x == Self::Proprietary as u8 => Self::Proprietary,
            wrong => return Err(wrong),
        })
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[repr(u8)]
pub enum InputKey {
    WitnessUtxo = 0x01,
    PartialSig = 0x02,
    SighashType = 0x03,
    RedeemScript = 0x04,
    WitnessScript = 0x05,
    Bip32Derivation = 0x06,
    FinalScriptSig = 0x07,
    FinalWitness = 0x08,
    PreviousTxid = 0x0E,
    OutputIndex = 0x0F,
    Sequence = 0x10,
    RequiredTimeLock = 0x11,
    RequiredHeighLock = 0x12,
    Proprietary = 0xFC,
}

impl KeyType for InputKey {
    fn byte_len(&self) -> usize { 1 }

    fn try_from_u8(val: u8) -> Result<Self, u8> {
        Ok(match val {
            x if x == Self::WitnessUtxo as u8 => Self::WitnessUtxo,
            x if x == Self::PartialSig as u8 => Self::PartialSig,
            x if x == Self::SighashType as u8 => Self::SighashType,
            x if x == Self::RedeemScript as u8 => Self::RedeemScript,
            x if x == Self::WitnessScript as u8 => Self::WitnessScript,
            x if x == Self::Bip32Derivation as u8 => Self::Bip32Derivation,
            x if x == Self::FinalScriptSig as u8 => Self::FinalScriptSig,
            x if x == Self::FinalWitness as u8 => Self::FinalWitness,
            x if x == Self::PreviousTxid as u8 => Self::PreviousTxid,
            x if x == Self::OutputIndex as u8 => Self::OutputIndex,
            x if x == Self::Sequence as u8 => Self::Sequence,
            x if x == Self::RequiredTimeLock as u8 => Self::RequiredTimeLock,
            x if x == Self::RequiredHeighLock as u8 => Self::RequiredHeighLock,
            x if x == Self::Proprietary as u8 => Self::Proprietary,
            wrong => return Err(wrong),
        })
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[repr(u8)]
pub enum OutputKey {
    /// `PSBT_OUT_REDEEM_SCRIPT`
    RedeemScript = 0x00,

    /// `PSBT_OUT_WITNESS_SCRIPT`
    WitnessScript = 0x01,

    /// `PSBT_OUT_BIP32_DERIVATION`
    Bip32Derivation = 0x02,

    /// `PSBT_OUT_AMOUNT`
    Amount = 0x03,

    /// `PSBT_OUT_SCRIPT`
    Script = 0x04,

    Proprietary = 0xFC,
}

impl KeyType for OutputKey {
    fn byte_len(&self) -> usize { 1 }

    fn try_from_u8(val: u8) -> Result<Self, u8> {
        Ok(match val {
            x if x == Self::RedeemScript as u8 => Self::RedeemScript,
            x if x == Self::WitnessScript as u8 => Self::WitnessScript,
            x if x == Self::Bip32Derivation as u8 => Self::Bip32Derivation,
            x if x == Self::Amount as u8 => Self::Amount,
            x if x == Self::Script as u8 => Self::Script,
            x if x == Self::Proprietary as u8 => Self::Proprietary,
            wrong => return Err(wrong),
        })
    }
}

pub struct KeyPair<T: KeyType, K, V> {
    pub key_type: T,
    pub key_data: K,
    pub value_data: V,
}

impl<T: KeyType, K, V> KeyPair<T, K, V> {
    pub fn new(key_type: T, key_data: K, value_data: V) -> Self {
        Self {
            key_type,
            key_data,
            value_data,
        }
    }

    pub fn key_len(&self) -> VarInt
    where K: Encode {
        let mut sink = Sink::default();
        let count = self.key_data.encode(&mut sink).expect("sink write doesn't fail");
        let len = count + self.key_type.byte_len();
        VarInt::with(len)
    }

    pub fn value_len(&self) -> VarInt
    where V: Encode {
        let mut sink = Sink::default();
        let len = self.value_data.encode(&mut sink).expect("sink write doesn't fail");
        VarInt::with(len)
    }
}
