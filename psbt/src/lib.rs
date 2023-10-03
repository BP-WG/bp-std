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

#[macro_use]
extern crate amplify;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;

mod maps;
mod timelocks;
mod sigtypes;
mod keys;
mod coders;

pub use coders::{Decode, DecodeError, Encode, PsbtError};
pub use keys::{GlobalKey, InputKey, KeyPair, KeyType, OutputKey};
pub use maps::{Input, ModifiableFlags, Output, Prevout, Psbt};
pub use sigtypes::{EcdsaSig, EcdsaSigError, NonStandardSighashType, SighashFlag, SighashType};
pub use timelocks::{InvalidTimelock, LockHeight, LockTimestamp, TimelockParseError};

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display("unsupported version of PSBT v{0}")]
pub struct PsbtUnsupportedVer(u32);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum PsbtVer {
    V0 = 0,
    V2 = 2,
}

impl PsbtVer {
    pub const fn try_from_standard_u32(v: u32) -> Result<Self, PsbtUnsupportedVer> {
        Ok(match v {
            0 => Self::V0,
            2 => Self::V2,
            wrong => return Err(PsbtUnsupportedVer(wrong)),
        })
    }

    pub const fn to_standard_u32(&self) -> u32 { *self as u32 }

    pub const fn max() -> Self {
        // this is a special syntax construct to get compiler error each time we add a new version
        // and not to forget upgrade the result of this method
        match Self::V0 {
            PsbtVer::V0 | PsbtVer::V2 => PsbtVer::V2,
        }
    }
}
