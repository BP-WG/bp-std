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

use std::str::FromStr;

use amplify::hex;
use bc::secp256k1::{PublicKey, XOnlyPublicKey};

use crate::xpub::XpubParseError;
use crate::{DerivationParseError, DerivationPath, XpubFp};

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrap(Deref, LowerHex)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct TaprootPubkey(pub XOnlyPublicKey);

impl TaprootPubkey {
    pub fn from_slice(data: impl AsRef<[u8]>) -> Result<Self, bc::secp256k1::Error> {
        XOnlyPublicKey::from_slice(data.as_ref()).map(Self)
    }

    pub fn to_byte_array(&self) -> [u8; 32] { self.0.serialize() }
}

impl From<TaprootPubkey> for [u8; 32] {
    fn from(pk: TaprootPubkey) -> [u8; 32] { pk.to_byte_array() }
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrap(Deref, LowerHex)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct ComprPubkey(pub PublicKey);

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrap(Deref, LowerHex)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct UncomprPubkey(pub PublicKey);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct LegacyPubkey {
    pub compressed: bool,
    pub pubkey: PublicKey,
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum OriginParseError {
    /// invalid derivation path - {0}
    #[from]
    DerivationPath(DerivationParseError),

    /// invalid master key fingerprint - {0}
    #[from]
    InvalidMasterFp(hex::Error),
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display)]
#[display("{master_fp}{derivation}", alt = "{master_fp}{derivation:#}")]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct KeyOrigin {
    master_fp: XpubFp,
    derivation: DerivationPath,
}

impl FromStr for KeyOrigin {
    type Err = XpubParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (master_fp, path) = match s.split_once('/') {
            None => (XpubFp::default(), ""),
            Some(("00000000", p)) | Some(("m", p)) => (XpubFp::default(), p),
            Some((fp, p)) => (XpubFp::from_str(fp)?, p),
        };
        Ok(KeyOrigin {
            master_fp,
            derivation: DerivationPath::from_str(path)?,
        })
    }
}
