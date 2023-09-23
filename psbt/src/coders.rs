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

use std::io;
use std::io::{Cursor, Read, Write};

use amplify::IoError;
use bp::{Idx, LockTime, TxVer, Xpub, XpubOrigin};

use crate::{GlobalKey, Input, KeyPair, KeyType, ModifiableFlags, Output, Psbt};

#[derive(Clone, Debug, Display, Error, From)]
#[display(inner)]
pub enum DecodeError {
    #[from]
    #[from(io::Error)]
    Io(IoError),

    #[from]
    Psbt(PsbtError),
}

#[derive(Clone, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum PsbtError {
    /// PSBT data are followed by some excessive bytes
    DataNotConsumed,
}

/// A variable-length unsigned integer.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct VarInt(pub u64);

#[allow(clippy::len_without_is_empty)] // VarInt has on concept of 'is_empty'.
impl VarInt {
    pub fn with(u: impl Into<usize>) -> Self { VarInt(u.into() as u64) }

    /// Gets the length of this VarInt when encoded.
    ///
    /// Returns 1 for 0..=0xFC, 3 for 0xFD..=(2^16-1), 5 for 0x10000..=(2^32-1),
    /// and 9 otherwise.
    #[inline]
    pub const fn len(&self) -> usize {
        match self.0 {
            0..=0xFC => 1,
            0xFD..=0xFFFF => 3,
            0x10000..=0xFFFFFFFF => 5,
            _ => 9,
        }
    }
}

pub trait Encode {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError>;
}

pub trait Decode
where Self: Sized
{
    fn decode(reader: &mut impl Read) -> Result<Self, DecodeError>;
    fn deserialize(bytes: impl AsRef<[u8]>) -> Result<Self, PsbtError> {
        let mut cursor = Cursor::new(bytes.as_ref());
        let me = Self::decode(&mut cursor).map_err(|err| match err {
            DecodeError::Psbt(e) => e,
            DecodeError::Io(_) => unreachable!(),
        })?;
        if cursor.position() as usize != bytes.as_ref().len() {
            return Err(PsbtError::DataNotConsumed);
        }
        Ok(me)
    }
}

impl Psbt {
    pub fn encode_v2(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        let mut counter = 0;
        counter += writer.write(b"psbt\xFF")?;

        self.encode_v2_global(writer)?;
        writer.write(&[0x0])?;

        for input in &self.inputs {
            input.encode_v2(writer)?;
        }
        writer.write(&[0x0])?;

        for output in &self.outputs {
            output.encode_v2(writer)?;
        }
        writer.write(&[0x0])?;

        Ok(counter)
    }
    pub fn encode_v2_vec(&self, writer: &mut Vec<u8>) -> usize {
        self.encode_v2(writer).expect("in-memory encoding can't error")
    }
    pub fn serialize_v2(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        self.encode_v2_vec(&mut vec);
        vec
    }
    fn encode_v2_global(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        let mut counter = 0;

        for (xpub, source) in &self.xpub {
            counter += KeyPair::new(GlobalKey::Xpub, xpub, source).encode(writer)?;
        }
        KeyPair::new(GlobalKey::TxVersion, &(), &self.tx_version).encode(writer)?;

        KeyPair::new(GlobalKey::FallbackLocktime, &(), &self.fallback_locktime).encode(writer)?;

        KeyPair::new(GlobalKey::InputCount, &(), &self.inputs.len()).encode(writer)?;

        KeyPair::new(GlobalKey::InputCount, &(), &self.outputs.len()).encode(writer)?;

        KeyPair::new(GlobalKey::TxModifiable, &(), &self.tx_modifiable).encode(writer)?;

        KeyPair::new(GlobalKey::Version, &(), &0x02u32).encode(writer)?;

        Ok(counter)
    }
}

impl Input {
    fn encode_v2(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        let mut counter = 0;

        todo!();

        Ok(counter)
    }
}

impl Output {
    fn encode_v2(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        let mut counter = 0;

        todo!();

        Ok(counter)
    }
}

impl<'a, T: KeyType, K: Encode, V: Encode> Encode for KeyPair<'a, T, K, V> {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        let mut counter = 0;

        counter += self.key_len().encode(writer)?;
        counter += writer.write(&[self.key_type.into()])?;
        counter += self.key_data.encode(writer)?;

        counter += self.value_len().encode(writer)?;
        counter += self.value_data.encode(writer)?;

        Ok(counter)
    }
}

impl Encode for Xpub {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write(&self.encode())?;
        Ok(78)
    }
}

impl Encode for XpubOrigin {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write(self.master_fp().as_ref())?;
        for index in self.derivation() {
            index.index().encode(writer)?;
        }
        Ok(4 + self.derivation().len() * 4)
    }
}

impl Encode for LockTime {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.to_consensus_u32().encode(writer)
    }
}

impl Encode for ModifiableFlags {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.to_standard_u8().encode(writer)
    }
}

impl Encode for TxVer {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write(&self.to_consensus_i32().to_le_bytes())?;
        Ok(4)
    }
}

impl Encode for VarInt {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        match self.0 {
            0..=0xFC => {
                (self.0 as u8).encode(writer)?;
                Ok(1)
            }
            0xFD..=0xFFFF => {
                0xFDu8.encode(writer)?;
                (self.0 as u16).encode(writer)?;
                Ok(3)
            }
            0x10000..=0xFFFFFFFF => {
                0xFEu8.encode(writer)?;
                (self.0 as u32).encode(writer)?;
                Ok(5)
            }
            _ => {
                0xFFu8.encode(writer)?;
                self.0.encode(writer)?;
                Ok(9)
            }
        }
    }
}

/*
impl Decode for VarInt {
    fn decode(reader: &mut impl Read) -> Result<Self, DecodeError> {
        let n = u8::decode(reader)?;
        match n {
            0xFF => {
                let x = u64::decode(reader)?;
                if x < 0x100000000 {
                    Err(self::Error::NonMinimalVarInt)
                } else {
                    Ok(VarInt::with(x))
                }
            }
            0xFE => {
                let x = u32::decode(reader)?;
                if x < 0x10000 {
                    Err(self::Error::NonMinimalVarInt)
                } else {
                    Ok(VarInt::with(x))
                }
            }
            0xFD => {
                let x = u16::decode(reader)?;
                if x < 0xFD {
                    Err(self::Error::NonMinimalVarInt)
                } else {
                    Ok(VarInt::with(x))
                }
            }
            n => Ok(VarInt::with(n)),
        }
    }
}
 */

impl Encode for u8 {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write(&[*self])?;
        Ok(1)
    }
}

impl Encode for u16 {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write(&self.to_le_bytes())?;
        Ok(2)
    }
}

impl Encode for u32 {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write(&self.to_le_bytes())?;
        Ok(4)
    }
}

impl Encode for u64 {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write(&self.to_le_bytes())?;
        Ok(8)
    }
}

impl Encode for usize {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        VarInt::with(*self).encode(writer)
    }
}

impl<T: Encode> Encode for Option<T> {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        Ok(match self {
            Some(data) => data.encode(writer)?,
            None => 0,
        })
    }
}

impl Encode for () {
    fn encode(&self, _writer: &mut impl Write) -> Result<usize, IoError> { Ok(0) }
}
