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

//! Address-related types for detailed payload analysis and memory-efficient
//! processing.

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use amplify::Wrapper;
use bc::{ScriptPubkey, WitnessVer};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
pub struct AddressCompat {
    /// Address payload (see [`AddressPayload`]).
    pub payload: AddressPayload,

    /// A type of the network used by the address
    pub network: AddressNetwork,
}

impl AddressCompat {
    /// Constructs compatible address for a given `scriptPubkey`.
    /// Returns `None` if the uncompressed key is provided or `scriptPubkey`
    /// can't be represented as an address.
    pub fn with(script: &ScriptPubkey, network: AddressNetwork) -> Option<Self> {
        let payload = AddressPayload::from_script(script)?;
        Some(AddressCompat { payload, network })
    }

    /// Returns script corresponding to the given address.
    pub fn script_pubkey(self) -> ScriptPubkey { self.payload.script_pubkey() }

    /// Returns if the address is testnet-, signet- or regtest-specific
    pub fn is_testnet(self) -> bool { self.network != AddressNetwork::Mainnet }
}

impl Display for AddressCompat {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { Display::fmt(&Address::from(*self), f) }
}

impl FromStr for AddressCompat {
    type Err = address::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Address::from_str(s).and_then(AddressCompat::try_from)
    }
}

/// Internal address content. Consists of serialized hashes or x-only key value.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
pub enum AddressPayload {
    /// P2PKH payload.
    #[from]
    #[display("raw_pkh({0})")]
    PubkeyHash(PubkeyHash),

    /// P2SH and SegWit nested (legacy) P2WPKH/WSH-in-P2SH payloads.
    #[from]
    #[display("raw_sh({0})")]
    ScriptHash(ScriptHash),

    /// P2WPKH payload.
    #[from]
    #[display("raw_wpkh({0})")]
    WPubkeyHash(WPubkeyHash),

    /// P2WSH payload.
    #[from]
    #[display("raw_wsh({0})")]
    WScriptHash(WScriptHash),

    /// P2TR payload.
    #[from]
    #[display("raw_tr({output_key})")]
    Taproot {
        /// Taproot output key (tweaked key)
        output_key: TweakedPublicKey,
    },
}

impl AddressPayload {
    /// Constructs [`AddressCompat`] from the payload.
    pub fn into_address(self, network: AddressNetwork) -> AddressCompat {
        AddressCompat {
            payload: self,
            network,
        }
    }

    /// Constructs payload from a given `scriptPubkey`. Fails on future
    /// (post-taproot) witness types with `None`.
    pub fn from_script(script: &ScriptPubkey) -> Option<Self> {
        Address::from_script(script.as_inner(), bitcoin::Network::Bitcoin)
            .ok()
            .and_then(Self::from_address)
    }

    /// Returns script corresponding to the given address.
    pub fn script_pubkey(self) -> ScriptPubkey {
        match self {
            AddressPayload::PubkeyHash(hash) => ScriptPubkey::p2pkh(&hash),
            AddressPayload::ScriptHash(hash) => ScriptPubkey::p2sh(&hash),
            AddressPayload::WPubkeyHash(hash) => ScriptPubkey::p2wpkh(&hash),
            AddressPayload::WScriptHash(hash) => ScriptPubkey::p2wsh(&hash),
            AddressPayload::Taproot { output_key } => ScriptPubkey::p2tr_tweaked(output_key),
        }
    }
}

impl From<AddressPayload> for ScriptPubkey {
    fn from(ap: AddressPayload) -> Self {
        ap.into_address(bitcoin::Network::Bitcoin).script_pubkey().into()
    }
}

/// Errors parsing address strings.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum AddressParseError {
    /// unknown address payload prefix `{0}`; expected `pkh`, `sh`, `wpkh`,
    /// `wsh` and `pkxo` only
    UnknownPrefix(String),

    /// unrecognized address payload string format
    UnrecognizedStringFormat,

    /// address payload must be prefixed by pyaload format prefix, indicating
    /// specific form of hash or a public key used inside the address
    PrefixAbsent,

    /// wrong address payload data
    #[from(hex::Error)]
    WrongPayloadHashData,

    /// wrong BIP340 public key (xcoord-only)
    #[from(secp256k1::Error)]
    WrongPublicKeyData,

    /// unrecognized address network string; only `mainnet`, `testnet` and
    /// `regtest` are possible at address level
    UnrecognizedAddressNetwork,

    /// unrecognized address format string; must be one of `P2PKH`, `P2SH`,
    /// `P2WPKH`, `P2WSH`, `P2TR`
    UnrecognizedAddressFormat,

    /// wrong witness version
    WrongWitnessVersion,
}

impl FromStr for AddressPayload {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_lowercase();
        let mut split = s.trim_end_matches(')').split('(');
        Ok(match (split.next(), split.next(), split.next()) {
            (_, _, Some(_)) => return Err(AddressParseError::UnrecognizedStringFormat),
            (Some("pkh"), Some(hash), None) => {
                AddressPayload::PubkeyHash(PubkeyHash::from_str(hash)?)
            }
            (Some("sh"), Some(hash), None) => {
                AddressPayload::ScriptHash(ScriptHash::from_str(hash)?)
            }
            (Some("wpkh"), Some(hash), None) => {
                AddressPayload::WPubkeyHash(WPubkeyHash::from_str(hash)?)
            }
            (Some("wsh"), Some(hash), None) => {
                AddressPayload::WScriptHash(WScriptHash::from_str(hash)?)
            }
            (Some("pkxo"), Some(hash), None) => AddressPayload::Taproot {
                output_key: TweakedPublicKey::dangerous_assume_tweaked(XOnlyPublicKey::from_str(
                    hash,
                )?),
            },
            (Some(prefix), ..) => return Err(AddressParseError::UnknownPrefix(prefix.to_owned())),
            (None, ..) => return Err(AddressParseError::PrefixAbsent),
        })
    }
}

/// Address format
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum AddressFormat {
    /// Pay-to-public key hash
    #[display("P2PKH")]
    P2pkh,

    /// Pay-to-script hash
    #[display("P2SH")]
    P2sh,

    /// Pay-to-witness public key hash
    #[display("P2WPKH")]
    P2wpkh,

    /// Pay-to-witness script pash
    #[display("P2WSH")]
    P2wsh,

    /// Pay-to-taproot
    #[display("P2TR")]
    P2tr,

    /// Future witness address
    #[display("P2W{0}")]
    Future(WitnessVer),
}

impl AddressFormat {
    /// Returns witness version used by the address format.
    /// Returns `None` for pre-SegWit address formats.
    pub fn witness_version(self) -> Option<WitnessVer> {
        match self {
            AddressFormat::P2pkh => None,
            AddressFormat::P2sh => None,
            AddressFormat::P2wpkh | AddressFormat::P2wsh => Some(WitnessVer::V0),
            AddressFormat::P2tr => Some(WitnessVer::V1),
            AddressFormat::Future(ver) => Some(ver),
        }
    }
}

impl FromStr for AddressFormat {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        #[allow(clippy::match_str_case_mismatch)]
        Ok(match s.to_uppercase().as_str() {
            "P2PKH" => AddressFormat::P2pkh,
            "P2SH" => AddressFormat::P2sh,
            "P2WPKH" => AddressFormat::P2wpkh,
            "P2WSH" => AddressFormat::P2wsh,
            "P2TR" => AddressFormat::P2tr,
            s if s.starts_with("P2W") => AddressFormat::Future(
                WitnessVer::from_str(&s[3..])
                    .map_err(|_| AddressParseError::WrongWitnessVersion)?,
            ),
            _ => return Err(AddressParseError::UnrecognizedAddressFormat),
        })
    }
}

/// Bitcoin network used by the address
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum AddressNetwork {
    /// Bitcoin mainnet
    #[display("mainnet")]
    Mainnet,

    /// Bitcoin testnet and signet
    #[display("testnet")]
    Testnet,

    /// Bitcoin regtest networks
    #[display("regtest")]
    Regtest,
}

impl FromStr for AddressNetwork {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "mainnet" => AddressNetwork::Mainnet,
            "testnet" => AddressNetwork::Testnet,
            "regtest" => AddressNetwork::Regtest,
            _ => return Err(AddressParseError::UnrecognizedAddressNetwork),
        })
    }
}

impl AddressNetwork {
    /// Detects whether the network is a kind of test network (testnet, signet,
    /// regtest).
    pub fn is_testnet(self) -> bool { self != Self::Mainnet }
}
