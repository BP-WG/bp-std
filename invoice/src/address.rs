// Modern, minimalistic & standard-compliant cold wallet library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2020-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2020-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2020-2024 Dr Maxim Orlovsky. All rights reserved.
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

use std::fmt::{self, Debug, Display, Formatter};
use std::io::{Cursor, Write};
use std::str::FromStr;

use amplify::{ByteArray, Bytes32};
use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};
use bc::{
    InvalidPubkey, OutputPk, PubkeyHash, ScriptHash, ScriptPubkey, WPubkeyHash, WScriptHash,
    WitnessVer,
};
use bech32::u5;

use crate::base58;

/// Mainnet (bitcoin) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = 0; // 0x00
/// Mainnet (bitcoin) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = 5; // 0x05
/// Test (tesnet, signet, regtest) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_TEST: u8 = 111; // 0x6f
/// Test (tesnet, signet, regtest) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = 196; // 0xc4

/// Errors creating address from scriptPubkey.
#[derive(Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum AddressError {
    /// scriptPubkey contains invalid BIP340 output pubkey.
    InvalidTaprootKey,
    /// scriptPubkey can't be represented with any known address standard.
    UnsupportedScriptPubkey,
}

/// Errors parsing address strings.
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum AddressParseError {
    /// wrong Base58 encoding of address data - {0}
    #[from]
    Base58(base58::Error),

    /// wrong Bech32 encoding of address data - {0}
    #[from]
    Bech32(bech32::Error),

    /// proprietary address has an invalid version code {0:#04x}.
    InvalidAddressVersion(u8),

    /// segwit address has an invalid witness version {0:#04x}.
    InvalidWitnessVersion(u8),

    /// unsupported future taproot version in address `{1}` detected by a length of {0}.
    FutureTaprootVersion(usize, String),

    /// address has an unsupported future witness version {0}.
    FutureWitnessVersion(WitnessVer),

    /// address has an invalid Bech32 variant {0:?}.
    InvalidBech32Variant(bech32::Variant),

    /// unrecognized address format in '{0}'.
    UnrecognizableFormat(String),

    /// wrong BIP340 public key
    #[from(InvalidPubkey<32>)]
    WrongPublicKeyData,

    /// unrecognized address format string; must be one of `P2PKH`, `P2SH`,
    /// `P2WPKH`, `P2WSH`, `P2TR`
    UnrecognizedAddressType,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
pub struct Address {
    /// Address payload (see [`AddressPayload`]).
    pub payload: AddressPayload,

    /// A type of the network used by the address
    pub network: AddressNetwork,
}

impl Address {
    pub fn new(payload: AddressPayload, network: AddressNetwork) -> Self {
        Address { payload, network }
    }

    /// Constructs compatible address for a given `scriptPubkey`.
    /// Returns `None` if the uncompressed key is provided or `scriptPubkey`
    /// can't be represented as an address.
    pub fn with(
        script: &ScriptPubkey,
        network: impl Into<AddressNetwork>,
    ) -> Result<Self, AddressError> {
        let payload = AddressPayload::from_script(script)?;
        Ok(Address {
            payload,
            network: network.into(),
        })
    }

    /// Returns script corresponding to the given address.
    pub fn script_pubkey(self) -> ScriptPubkey { self.payload.script_pubkey() }

    /// Returns if the address is testnet-, signet- or regtest-specific.
    pub fn is_testnet(self) -> bool { self.network != AddressNetwork::Mainnet }

    /// Detects address type.
    pub fn address_type(self) -> AddressType { self.payload.address_type() }
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let (version, variant, prog) = match self.payload {
            AddressPayload::Pkh(PubkeyHash(hash)) | AddressPayload::Sh(ScriptHash(hash)) => {
                let mut prefixed = [0; 21];
                prefixed[0] = match (self.payload, self.network) {
                    (AddressPayload::Pkh(_), AddressNetwork::Mainnet) => PUBKEY_ADDRESS_PREFIX_MAIN,
                    (AddressPayload::Sh(_), AddressNetwork::Mainnet) => SCRIPT_ADDRESS_PREFIX_MAIN,
                    (AddressPayload::Pkh(_), _) => PUBKEY_ADDRESS_PREFIX_TEST,
                    (AddressPayload::Sh(_), _) => SCRIPT_ADDRESS_PREFIX_TEST,
                    _ => unreachable!(),
                };
                prefixed[1..].copy_from_slice(hash.as_ref());
                return base58::encode_check_to_fmt(f, &prefixed[..]);
            }
            AddressPayload::Wpkh(hash) => {
                (WitnessVer::V0, bech32::Variant::Bech32, Box::new(hash) as Box<dyn AsRef<[u8]>>)
            }
            AddressPayload::Wsh(hash) => {
                (WitnessVer::V0, bech32::Variant::Bech32, Box::new(hash) as Box<dyn AsRef<[u8]>>)
            }
            AddressPayload::Tr(pk) => (
                WitnessVer::V1,
                bech32::Variant::Bech32m,
                Box::new(pk.to_byte_array()) as Box<dyn AsRef<[u8]>>,
            ),
        };

        struct UpperWriter<W: fmt::Write>(W);
        impl<W: fmt::Write> fmt::Write for UpperWriter<W> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                for c in s.chars() {
                    self.0.write_char(c.to_ascii_uppercase())?;
                }
                Ok(())
            }
        }

        let mut upper_writer;
        let writer = if f.alternate() {
            upper_writer = UpperWriter(f);
            &mut upper_writer as &mut dyn fmt::Write
        } else {
            f as &mut dyn fmt::Write
        };
        let mut bech32_writer =
            bech32::Bech32Writer::new(self.network.bech32_hrp(), variant, writer)?;
        let ver_u5 = u5::try_from_u8(version.version_no()).expect("witness version <= 16");
        bech32::WriteBase32::write_u5(&mut bech32_writer, ver_u5)?;
        bech32::ToBase32::write_base32(&prog.as_ref(), &mut bech32_writer)
    }
}

impl FromStr for Address {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parse_base58 = || -> Result<Self, Self::Err> {
            if s.len() > 50 {
                return Err(AddressParseError::Base58(base58::Error::InvalidLength(
                    s.len() * 11 / 15,
                )));
            }
            let data = base58::decode_check(s)?;
            if data.len() != 21 {
                return Err(AddressParseError::Base58(base58::Error::InvalidLength(data.len())));
            }

            let network = match data[0] {
                PUBKEY_ADDRESS_PREFIX_MAIN | SCRIPT_ADDRESS_PREFIX_MAIN => AddressNetwork::Mainnet,
                PUBKEY_ADDRESS_PREFIX_TEST | SCRIPT_ADDRESS_PREFIX_TEST => AddressNetwork::Testnet,
                x => return Err(AddressParseError::InvalidAddressVersion(x)),
            };

            let mut hash = [0u8; 20];
            hash.copy_from_slice(&data[1..]);
            let payload = match data[0] {
                PUBKEY_ADDRESS_PREFIX_MAIN | PUBKEY_ADDRESS_PREFIX_TEST => {
                    AddressPayload::Pkh(PubkeyHash::from(hash))
                }
                SCRIPT_ADDRESS_PREFIX_MAIN | SCRIPT_ADDRESS_PREFIX_TEST => {
                    AddressPayload::Sh(ScriptHash::from(hash))
                }
                _ => unreachable!(),
            };

            Ok(Address::new(payload, network))
        };

        let parse_bech32 = |hri: String,
                            payload: Vec<bech32::u5>,
                            variant: bech32::Variant|
         -> Result<Self, Self::Err> {
            let network = match hri.as_str() {
                "bc" | "BC" => AddressNetwork::Mainnet,
                "tb" | "TB" => AddressNetwork::Testnet,
                "bcrt" | "BCRT" => AddressNetwork::Regtest,
                _ => return parse_base58(),
            };
            let (v, p5) = payload.split_at(1);
            let wv = v[0].to_u8();
            let version = WitnessVer::from_version_no(wv).map_err(|err| {
                eprintln!("{err}");
                AddressParseError::InvalidWitnessVersion(wv)
            })?;
            let program: Vec<u8> = bech32::FromBase32::from_base32(p5)?;
            let payload = match (version, variant) {
                (WitnessVer::V0, bech32::Variant::Bech32) if program.len() == 20 => {
                    let mut hash = [0u8; 20];
                    hash.copy_from_slice(&program);
                    AddressPayload::Wpkh(hash.into())
                }
                (WitnessVer::V0, bech32::Variant::Bech32) if program.len() == 32 => {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&program);
                    AddressPayload::Wsh(hash.into())
                }
                (WitnessVer::V1, bech32::Variant::Bech32m) if program.len() == 32 => {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&program);
                    let pk = OutputPk::from_byte_array(key)?;
                    AddressPayload::Tr(pk)
                }

                (WitnessVer::V1, bech32::Variant::Bech32m) => {
                    return Err(AddressParseError::FutureTaprootVersion(
                        program.len(),
                        s.to_owned(),
                    ));
                }

                (WitnessVer::V0 | WitnessVer::V1, wrong) => {
                    return Err(AddressParseError::InvalidBech32Variant(wrong));
                }

                (future, _) => return Err(AddressParseError::FutureWitnessVersion(future)),
            };
            Ok(Address::new(payload, network))
        };

        match bech32::decode(s) {
            Ok((hri, payload, variant)) => parse_bech32(hri, payload, variant),
            Err(_) => {
                parse_base58().map_err(|_| AddressParseError::UnrecognizableFormat(s.to_owned()))
            }
        }
    }
}

/// Internal address content. Consists of serialized hashes or x-only key value.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
pub enum AddressPayload {
    /// P2PKH payload.
    #[from]
    Pkh(PubkeyHash),

    /// P2SH and SegWit nested (proprietary) P2WPKH/WSH-in-P2SH payloads.
    #[from]
    Sh(ScriptHash),

    /// P2WPKH payload.
    #[from]
    Wpkh(WPubkeyHash),

    /// P2WSH payload.
    #[from]
    Wsh(WScriptHash),

    /// P2TR payload.
    #[from]
    Tr(OutputPk),
}

impl AddressPayload {
    pub(crate) const P2PKH: u8 = 1;
    pub(crate) const P2SH: u8 = 2;
    pub(crate) const P2WPKH: u8 = 3;
    pub(crate) const P2WSH: u8 = 4;
    pub(crate) const P2TR: u8 = 5;
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum AddressPayloadError {
    /// unexpected address type byte {0:#04x}.
    InvalidAddressType(u8),
    /// invalid taproot output key; specifically {0}.
    InvalidTapkey(InvalidPubkey<32>),
}

impl TryFrom<[u8; 33]> for AddressPayload {
    type Error = AddressPayloadError;

    fn try_from(data: [u8; 33]) -> Result<Self, Self::Error> {
        let address = match data[0] {
            Self::P2PKH => AddressPayload::Pkh(PubkeyHash::from_slice_unsafe(&data[1..21])),
            Self::P2SH => AddressPayload::Sh(ScriptHash::from_slice_unsafe(&data[1..21])),
            Self::P2WPKH => AddressPayload::Wpkh(WPubkeyHash::from_slice_unsafe(&data[1..21])),
            Self::P2WSH => AddressPayload::Wsh(WScriptHash::from_slice_unsafe(&data[1..])),
            Self::P2TR => AddressPayload::Tr(
                OutputPk::from_byte_array(Bytes32::from_slice_unsafe(&data[1..33]).to_byte_array())
                    .map_err(AddressPayloadError::InvalidTapkey)?,
            ),
            wrong => return Err(AddressPayloadError::InvalidAddressType(wrong)),
        };
        Ok(address)
    }
}

impl AddressPayload {
    /// Constructs [`Address`] from the payload.
    pub fn into_address(self, network: AddressNetwork) -> Address {
        Address {
            payload: self,
            network,
        }
    }

    /// Constructs payload from a given `scriptPubkey`. Fails on future
    /// (post-taproot) witness types with `None`.
    pub fn from_script(script: &ScriptPubkey) -> Result<Self, AddressError> {
        Ok(if script.is_p2pkh() {
            let mut bytes = [0u8; 20];
            bytes.copy_from_slice(&script[3..23]);
            AddressPayload::Pkh(PubkeyHash::from(bytes))
        } else if script.is_p2sh() {
            let mut bytes = [0u8; 20];
            bytes.copy_from_slice(&script[2..22]);
            AddressPayload::Sh(ScriptHash::from(bytes))
        } else if script.is_p2wpkh() {
            let mut bytes = [0u8; 20];
            bytes.copy_from_slice(&script[2..]);
            AddressPayload::Wpkh(WPubkeyHash::from(bytes))
        } else if script.is_p2wsh() {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&script[2..]);
            AddressPayload::Wsh(WScriptHash::from(bytes))
        } else if script.is_p2tr() {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&script[2..]);
            AddressPayload::Tr(
                OutputPk::from_byte_array(bytes).map_err(|_| AddressError::InvalidTaprootKey)?,
            )
        } else {
            return Err(AddressError::UnsupportedScriptPubkey);
        })
    }

    /// Returns script corresponding to the given address.
    pub fn script_pubkey(self) -> ScriptPubkey {
        match self {
            AddressPayload::Pkh(hash) => ScriptPubkey::p2pkh(hash),
            AddressPayload::Sh(hash) => ScriptPubkey::p2sh(hash),
            AddressPayload::Wpkh(hash) => ScriptPubkey::p2wpkh(hash),
            AddressPayload::Wsh(hash) => ScriptPubkey::p2wsh(hash),
            AddressPayload::Tr(output_key) => ScriptPubkey::p2tr_tweaked(output_key),
        }
    }

    /// Detects address type.
    pub fn address_type(self) -> AddressType {
        match self {
            AddressPayload::Pkh(_) => AddressType::P2pkh,
            AddressPayload::Sh(_) => AddressType::P2sh,
            AddressPayload::Wpkh(_) => AddressType::P2wpkh,
            AddressPayload::Wsh(_) => AddressType::P2wsh,
            AddressPayload::Tr(_) => AddressType::P2tr,
        }
    }
}

impl From<AddressPayload> for ScriptPubkey {
    fn from(ap: AddressPayload) -> Self { ap.script_pubkey() }
}

impl DisplayBaid64<33> for AddressPayload {
    const HRI: &'static str = "wvout";
    const CHUNKING: bool = true;
    const PREFIX: bool = true;
    const EMBED_CHECKSUM: bool = true;
    const MNEMONIC: bool = false;

    fn to_baid64_payload(&self) -> [u8; 33] {
        let mut payload = [0u8; 33];
        // tmp stack array to store the tr payload to resolve lifetime issue
        let schnorr_pk: [u8; 32];
        let (addr_type, spk) = match &self {
            AddressPayload::Pkh(pkh) => (Self::P2PKH, pkh.as_ref()),
            AddressPayload::Sh(sh) => (Self::P2SH, sh.as_ref()),
            AddressPayload::Wpkh(wpkh) => (Self::P2WPKH, wpkh.as_ref()),
            AddressPayload::Wsh(wsh) => (Self::P2WSH, wsh.as_ref()),
            AddressPayload::Tr(tr) => {
                schnorr_pk = tr.to_byte_array();
                (Self::P2TR, &schnorr_pk[..])
            }
        };
        payload[0] = addr_type;
        Cursor::new(&mut payload[1..])
            .write_all(spk)
            .expect("address payload always less than 32 bytes");
        payload
    }
}

impl Display for AddressPayload {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
}
impl FromBaid64Str<33> for AddressPayload {}
impl FromStr for AddressPayload {
    type Err = Baid64ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
}

/// Address type
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum AddressType {
    /// Pay-to-public key hash
    #[display("P2PKH")]
    P2pkh,

    /// Pay-to-script hash
    #[display("P2SH")]
    P2sh,

    /// Pay-to-witness public key hash
    #[display("P2WPKH")]
    P2wpkh,

    /// Pay-to-witness script hash
    #[display("P2WSH")]
    P2wsh,

    /// Pay-to-taproot
    #[display("P2TR")]
    P2tr,
}

impl AddressType {
    /// Returns witness version used by the address format.
    /// Returns `None` for pre-SegWit address formats.
    pub fn witness_version(self) -> Option<WitnessVer> {
        match self {
            AddressType::P2pkh => None,
            AddressType::P2sh => None,
            AddressType::P2wpkh | AddressType::P2wsh => Some(WitnessVer::V0),
            AddressType::P2tr => Some(WitnessVer::V1),
        }
    }
}

impl FromStr for AddressType {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        #[allow(clippy::match_str_case_mismatch)]
        Ok(match s.to_uppercase().as_str() {
            "P2PKH" => AddressType::P2pkh,
            "P2SH" => AddressType::P2sh,
            "P2WPKH" => AddressType::P2wpkh,
            "P2WSH" => AddressType::P2wsh,
            "P2TR" => AddressType::P2tr,
            _ => return Err(AddressParseError::UnrecognizedAddressType),
        })
    }
}

/// Bitcoin network used by the address
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum AddressNetwork {
    /// Bitcoin mainnet
    Mainnet,

    /// Bitcoin testnet and signet
    Testnet,

    /// Bitcoin regtest networks
    Regtest,
}

impl AddressNetwork {
    /// Detects whether the network is a kind of test network (testnet, signet,
    /// regtest).
    pub fn is_testnet(self) -> bool { self != Self::Mainnet }

    pub fn bech32_hrp(self) -> &'static str {
        match self {
            AddressNetwork::Mainnet => "bc",
            AddressNetwork::Testnet => "tb",
            AddressNetwork::Regtest => "bcrt",
        }
    }
}

#[cfg(feature = "serde")]
mod _serde {
    use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for Address {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            serializer.serialize_str(&self.to_string())
        }
    }

    impl<'de> Deserialize<'de> for Address {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            let s = String::deserialize(deserializer)?;
            Address::from_str(&s).map_err(|err| {
                de::Error::custom(format!(
                    "invalid xpub specification string representation; {err}"
                ))
            })
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn display_from_str() {
        let b32 = "tb1p5kgdjdf99vfa2xwufd2cx2qru468z79s2arn3jf5feg95d9m62gqzpnjjk";
        assert_eq!(Address::from_str(b32).unwrap().to_string(), b32);
    }

    #[test]
    fn address_payload_parse() {
        let p = AddressPayload::Pkh([0xff; 20].into());
        assert_eq!(AddressPayload::from_str(&p.to_string()).unwrap(), p);

        let p = AddressPayload::Sh([0xff; 20].into());
        assert_eq!(AddressPayload::from_str(&p.to_string()).unwrap(), p);

        let p = AddressPayload::Wpkh([0xff; 20].into());
        assert_eq!(AddressPayload::from_str(&p.to_string()).unwrap(), p);

        let p = AddressPayload::Wsh([0xff; 32].into());
        assert_eq!(AddressPayload::from_str(&p.to_string()).unwrap(), p);

        let p = AddressPayload::Tr(
            OutputPk::from_byte_array([
                0x85, 0xa6, 0x42, 0x59, 0x8b, 0xfe, 0x2e, 0x42, 0xa3, 0x78, 0xcb, 0xb5, 0x3b, 0xf1,
                0x4a, 0xbe, 0x77, 0xf8, 0x1a, 0xef, 0xed, 0xf7, 0x3b, 0x66, 0x7b, 0x42, 0x85, 0xaf,
                0x7c, 0xf1, 0xc8, 0xa3,
            ])
            .unwrap(),
        );
        assert_eq!(AddressPayload::from_str(&p.to_string()).unwrap(), p);
    }
}
