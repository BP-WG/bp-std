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
use bc::InvalidPubkey;

use crate::xpub::XpubParseError;
use crate::{DerivationIndex, DerivationParseError, DerivationPath, Terminal, XpubFp, XpubOrigin};

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrap(Deref, LowerHex)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct TaprootPk(pub XOnlyPublicKey);

impl TaprootPk {
    pub fn from_byte_array(data: [u8; 32]) -> Result<Self, InvalidPubkey> {
        XOnlyPublicKey::from_slice(data.as_ref()).map(Self).map_err(|_| InvalidPubkey)
    }

    pub fn to_byte_array(&self) -> [u8; 32] { self.0.serialize() }
}

impl From<TaprootPk> for [u8; 32] {
    fn from(pk: TaprootPk) -> [u8; 32] { pk.to_byte_array() }
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrap(Deref, LowerHex)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct CompressedPk(pub PublicKey);

impl CompressedPk {
    pub fn from_byte_array(data: [u8; 33]) -> Result<Self, InvalidPubkey> {
        PublicKey::from_slice(&data).map(Self).map_err(|_| InvalidPubkey)
    }
    pub fn to_byte_array(&self) -> [u8; 33] { self.0.serialize() }
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrap(Deref, LowerHex)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct UncompressedPk(pub PublicKey);

impl UncompressedPk {
    pub fn from_byte_array(data: [u8; 65]) -> Result<Self, InvalidPubkey> {
        PublicKey::from_slice(&data).map(Self).map_err(|_| InvalidPubkey)
    }
    pub fn to_byte_array(&self) -> [u8; 65] { self.0.serialize_uncompressed() }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct LegacyPk {
    pub compressed: bool,
    pub pubkey: PublicKey,
}

impl From<CompressedPk> for LegacyPk {
    fn from(pk: CompressedPk) -> Self { LegacyPk::compressed(pk.0) }
}

impl From<UncompressedPk> for LegacyPk {
    fn from(pk: UncompressedPk) -> Self { LegacyPk::uncompressed(pk.0) }
}

impl LegacyPk {
    pub const fn compressed(pubkey: PublicKey) -> Self {
        LegacyPk {
            compressed: true,
            pubkey,
        }
    }

    pub const fn uncompressed(pubkey: PublicKey) -> Self {
        LegacyPk {
            compressed: false,
            pubkey,
        }
    }
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

#[derive(Getters, Clone, Eq, PartialEq, Hash, Debug, Display)]
#[display("{master_fp}{derivation}", alt = "{master_fp}{derivation:#}")]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct KeyOrigin {
    #[getter(as_copy)]
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

impl KeyOrigin {
    pub fn new(master_fp: XpubFp, derivation: DerivationPath) -> Self {
        KeyOrigin {
            master_fp,
            derivation,
        }
    }

    pub fn with(xpub_origin: XpubOrigin, terminal: Terminal) -> Self {
        let mut derivation = DerivationPath::new();
        derivation.extend(xpub_origin.derivation().iter().copied().map(DerivationIndex::from));
        derivation.push(DerivationIndex::normal(terminal.keychain as u16));
        derivation.push(DerivationIndex::Normal(terminal.index));
        KeyOrigin {
            master_fp: xpub_origin.master_fp(),
            derivation,
        }
    }
}
