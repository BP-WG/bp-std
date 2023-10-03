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
use amplify::hex;
use amplify::hex::FromHex;
use bp::{OpCode, ScriptBytes};

#[derive(Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Default)]
#[wrapper(Deref, Index, RangeOps, BorrowSlice, LowerHex, UpperHex)]
#[wrapper_mut(DerefMut, IndexMut, RangeMut, BorrowSliceMut)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct WitnessScript(
    #[from]
    #[from(Vec<u8>)]
    ScriptBytes,
);

impl WitnessScript {
    pub fn new() -> Self { Self::default() }

    pub fn with_capacity(capacity: usize) -> Self {
        Self(ScriptBytes::from(Confined::with_capacity(capacity)))
    }

    /// Adds a single opcode to the script.
    pub fn push_opcode(&mut self, op_code: OpCode) {
        self.0.push(op_code as u8).expect("script exceeds 2^64 bytes");
    }

    pub fn as_script_bytes(&self) -> &ScriptBytes { &self.0 }
}

impl FromHex for WitnessScript {
    fn from_hex(s: &str) -> Result<Self, hex::Error> { ScriptBytes::from_hex(s).map(Self) }

    fn from_byte_iter<I>(_: I) -> Result<Self, hex::Error>
    where I: Iterator<Item = Result<u8, hex::Error>> + ExactSizeIterator + DoubleEndedIterator {
        unreachable!()
    }
}

#[derive(Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Default)]
#[wrapper(Deref, Index, RangeOps, BorrowSlice, LowerHex, UpperHex)]
#[wrapper_mut(DerefMut, IndexMut, RangeMut, BorrowSliceMut)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct RedeemScript(
    #[from]
    #[from(Vec<u8>)]
    ScriptBytes,
);

impl RedeemScript {
    pub fn new() -> Self { Self::default() }

    pub fn with_capacity(capacity: usize) -> Self {
        Self(ScriptBytes::from(Confined::with_capacity(capacity)))
    }

    /// Adds a single opcode to the script.
    pub fn push_opcode(&mut self, op_code: OpCode) {
        self.0.push(op_code as u8).expect("script exceeds 2^64 bytes");
    }

    pub fn as_script_bytes(&self) -> &ScriptBytes { &self.0 }
}

impl FromHex for RedeemScript {
    fn from_hex(s: &str) -> Result<Self, hex::Error> { ScriptBytes::from_hex(s).map(Self) }

    fn from_byte_iter<I>(_: I) -> Result<Self, hex::Error>
    where I: Iterator<Item = Result<u8, hex::Error>> + ExactSizeIterator + DoubleEndedIterator {
        unreachable!()
    }
}
