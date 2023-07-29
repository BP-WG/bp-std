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

use secp256k1::{PublicKey, XOnlyPublicKey};

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrap(Deref, LowerHex)]
pub struct TaprootPubkey(pub XOnlyPublicKey);

impl TaprootPubkey {
    pub fn from_slice(data: impl AsRef<[u8]>) -> Result<Self, secp256k1::Error> {
        XOnlyPublicKey::from_slice(data.as_ref()).map(Self)
    }

    pub fn to_byte_array(&self) -> [u8; 32] { self.0.serialize() }
}

impl From<TaprootPubkey> for [u8; 32] {
    fn from(pk: TaprootPubkey) -> [u8; 32] { pk.to_byte_array() }
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrap(Deref, LowerHex)]
pub struct ComprPubkey(pub PublicKey);

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrap(Deref, LowerHex)]
pub struct UncomprPubkey(pub PublicKey);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct LegacyPubkey {
    pub compressed: bool,
    pub pubkey: PublicKey,
}
