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

use std::str::FromStr;

use crate::{DerivationIndex, DerivationPath, HardenedIndex, Idx, IdxBase, NormalIndex};

/// Errors in parsing derivation scheme string representation
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Error, Display)]
#[display(doc_comments)]
pub enum ParseBip43Error {
    /// invalid blockchain name {0}; it must be either `bitcoin`, `testnet` or
    /// hardened index number
    InvalidBlockchainName(String),

    /// LNPBP-43 blockchain index {0} must be hardened
    UnhardenedBlockchainIndex(u32),

    /// invalid LNPBP-43 identity representation {0}
    InvalidIdentityIndex(String),

    /// invalid BIP-43 purpose {0}
    InvalidPurposeIndex(String),

    /// BIP-{0} support is not implemented (of BIP with this number does not
    /// exist)
    UnimplementedBip(u16),

    /// derivation path can't be recognized as one of BIP-43-based standards
    UnrecognizedBipScheme,

    /// BIP-43 scheme must have form of `bip43/<purpose>h`
    InvalidBip43Scheme,

    /// BIP-48 scheme must have form of `bip48-native` or `bip48-nested`
    InvalidBip48Scheme,

    /// invalid derivation path `{0}`
    InvalidDerivationPath(String),
}

/// Specific derivation scheme after BIP-43 standards
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display)]
#[cfg_attr(feature = "clap", derive(ValueEnum))]
#[non_exhaustive]
pub enum Bip43 {
    /// Account-based P2PKH derivation.
    ///
    /// `m / 44' / coin_type' / account'`
    #[display("bip44", alt = "m/44h")]
    Bip44,

    /// Account-based native P2WPKH derivation.
    ///
    /// `m / 84' / coin_type' / account'`
    #[display("bip84", alt = "m/84h")]
    Bip84,

    /// Account-based legacy P2WPH-in-P2SH derivation.
    ///
    /// `m / 49' / coin_type' / account'`
    #[display("bip49", alt = "m/49h")]
    Bip49,

    /// Account-based single-key P2TR derivation.
    ///
    /// `m / 86' / coin_type' / account'`
    #[display("bip86", alt = "m/86h")]
    Bip86,

    /// Cosigner-index-based multisig derivation.
    ///
    /// `m / 45' / cosigner_index
    #[display("bip45", alt = "m/45h")]
    Bip45,

    /// Account-based multisig derivation with sorted keys & P2WSH nested.
    /// scripts
    ///
    /// `m / 48' / coin_type' / account' / 1'`
    #[display("bip48-nested", alt = "m/48h//1h")]
    Bip48Nested,

    /// Account-based multisig derivation with sorted keys & P2WSH native.
    /// scripts
    ///
    /// `m / 48' / coin_type' / account' / 2'`
    #[display("bip48-native", alt = "m/48h//2h")]
    Bip48Native,

    /// Account- & descriptor-based derivation for multi-sig wallets.
    ///
    /// `m / 87' / coin_type' / account'`
    #[display("bip87", alt = "m/87h")]
    Bip87,

    /// Generic BIP43 derivation with custom (non-standard) purpose value.
    ///
    /// `m / purpose'`
    #[display("bip43/{purpose}", alt = "m/{purpose}")]
    #[cfg_attr(feature = "clap", clap(skip))]
    Bip43 {
        /// Purpose value
        purpose: HardenedIndex,
    },
}

impl FromStr for Bip43 {
    type Err = ParseBip43Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_lowercase();
        let bip = s.strip_prefix("bip").or_else(|| s.strip_prefix("m/"));
        Ok(match bip {
            Some("44") => Bip43::Bip44,
            Some("84") => Bip43::Bip84,
            Some("49") => Bip43::Bip49,
            Some("86") => Bip43::Bip86,
            Some("45") => Bip43::Bip45,
            Some(bip48) if bip48.starts_with("48//") => match bip48
                .strip_prefix("48//")
                .and_then(|index| HardenedIndex::from_str(index).ok())
            {
                Some(script_type) if script_type == 1u8 => Bip43::Bip48Nested,
                Some(script_type) if script_type == 2u8 => Bip43::Bip48Native,
                _ => {
                    return Err(ParseBip43Error::InvalidBip48Scheme);
                }
            },
            Some("48-nested") => Bip43::Bip48Nested,
            Some("48-native") => Bip43::Bip48Native,
            Some("87") => Bip43::Bip87,
            Some(bip43) if bip43.starts_with("43/") => match bip43.strip_prefix("43/") {
                Some(purpose) => {
                    let purpose = HardenedIndex::from_str(purpose)
                        .map_err(|_| ParseBip43Error::InvalidPurposeIndex(purpose.to_owned()))?;
                    Bip43::Bip43 { purpose }
                }
                None => return Err(ParseBip43Error::InvalidBip43Scheme),
            },
            Some(_) | None => return Err(ParseBip43Error::UnrecognizedBipScheme),
        })
    }
}

impl Bip43 {
    /// Constructs derivation standard corresponding to a single-sig P2PKH.
    pub const PKH: Bip43 = Bip43::Bip44;
    /// Constructs derivation standard corresponding to a single-sig
    /// P2WPKH-in-P2SH.
    pub const WPKH_SH: Bip43 = Bip43::Bip49;
    /// Constructs derivation standard corresponding to a single-sig P2WPKH.
    pub const WPKH: Bip43 = Bip43::Bip84;
    /// Constructs derivation standard corresponding to a single-sig P2TR.
    pub const TR_SINGLE: Bip43 = Bip43::Bip86;
    /// Constructs derivation standard corresponding to a multi-sig P2SH BIP45.
    pub const MULTI_SH_SORTED: Bip43 = Bip43::Bip45;
    /// Constructs derivation standard corresponding to a multi-sig sorted
    /// P2WSH-in-P2SH.
    pub const MULTI_WSH_SH: Bip43 = Bip43::Bip48Nested;
    /// Constructs derivation standard corresponding to a multi-sig sorted
    /// P2WSH.
    pub const MULTI_WSH: Bip43 = Bip43::Bip48Native;
    /// Constructs derivation standard corresponding to a multi-sig BIP87.
    pub const DESCRIPTOR: Bip43 = Bip43::Bip87;
}

/// Methods for derivation standard enumeration types.
pub trait DerivationStandard: Eq + Clone {
    /// Deduces derivation standard used by the provided derivation path, if
    /// possible.
    fn deduce(derivation: &DerivationPath) -> Option<Self>
    where Self: Sized;

    /// Get hardened index matching BIP-43 purpose value, if any.
    fn purpose(&self) -> Option<HardenedIndex>;

    /// Depth of the account extended public key according to the given
    /// standard.
    ///
    /// Returns `None` if the standard does not provide information on
    /// account-level xpubs.
    fn account_depth(&self) -> Option<u8>;

    /// Depth of the derivation path defining `coin_type` key, i.e. the used
    /// blockchain.
    ///
    /// Returns `None` if the standard does not provide information on
    /// blockchain/coin type.
    fn coin_type_depth(&self) -> Option<u8>;

    /// Returns information whether the account xpub in this standard is the
    /// last hardened derivation path step, or there might be more hardened
    /// steps (like `script_type` in BIP-48).
    ///
    /// Returns `None` if the standard does not provide information on
    /// account-level xpubs.
    fn is_account_last_hardened(&self) -> Option<bool>;

    /// Checks which bitcoin network corresponds to a given derivation path
    /// according to the used standard requirements.
    fn is_testnet(&self, path: &DerivationPath) -> Result<bool, Option<DerivationIndex>>;

    /// Extracts hardened index from a derivation path position defining coin
    /// type information (used blockchain), if present.
    ///
    /// # Returns
    ///
    /// - `Err(None)` error if the path doesn't contain any coin index information;
    /// - `Err(`[`NormalIndex`]`)` error if the coin type in the derivation path was an unhardened
    ///   index.
    /// - `Ok(`[`HardenedIndex`]`)` with the coin type index otherwise.
    fn extract_coin_type(
        &self,
        path: &DerivationPath,
    ) -> Result<HardenedIndex, Option<NormalIndex>> {
        let coin = self.coin_type_depth().and_then(|i| path.get(i as usize)).ok_or(None)?;
        match coin {
            DerivationIndex::Normal(idx) => Err(Some(*idx)),
            DerivationIndex::Hardened(idx) => Ok(*idx),
        }
    }

    /// Extracts hardened index from a derivation path position defining account
    /// number, if present.
    ///
    /// # Returns
    ///
    /// - `Err(None)` error if the path doesn't contain any account number information;
    /// - `Err(`[`NormalIndex`]`)` error if the account number in the derivation path was an
    ///   unhardened index.
    /// - `Ok(`[`HardenedIndex`]`)` with the account number otherwise.
    fn extract_account_index(
        &self,
        path: &DerivationPath,
    ) -> Result<HardenedIndex, Option<NormalIndex>> {
        let coin = self.account_depth().and_then(|i| path.get(i as usize)).ok_or(None)?;
        match coin {
            DerivationIndex::Normal(idx) => Err(Some(*idx)),
            DerivationIndex::Hardened(idx) => Ok(*idx),
        }
    }

    /// Returns string representation of the template derivation path for an
    /// account-level keys. Account key is represented by `*` wildcard fragment.
    fn account_template_string(&self, testnet: bool) -> String;

    /// Construct derivation path for the account xpub.
    fn to_origin_derivation(&self, testnet: bool) -> DerivationPath<HardenedIndex>;

    /// Construct derivation path up to the provided account index segment.
    fn to_account_derivation(
        &self,
        account_index: HardenedIndex,
        testnet: bool,
    ) -> DerivationPath<HardenedIndex>;

    /// Construct full derivation path including address index and case
    /// (main, change etc).
    fn to_key_derivation(
        &self,
        account_index: HardenedIndex,
        testnet: bool,
        keychain: NormalIndex,
        index: NormalIndex,
    ) -> DerivationPath;
}

impl DerivationStandard for Bip43 {
    fn deduce(derivation: &DerivationPath<HardenedIndex>) -> Option<Bip43> {
        let mut iter = derivation.into_iter();
        let first = iter.next().map(HardenedIndex::try_from).transpose().ok()??;
        let fourth = iter.nth(3).map(HardenedIndex::try_from);
        Some(match (first.child_number(), fourth) {
            (44, ..) => Bip43::Bip44,
            (84, ..) => Bip43::Bip84,
            (49, ..) => Bip43::Bip49,
            (86, ..) => Bip43::Bip86,
            (45, ..) => Bip43::Bip45,
            (87, ..) => Bip43::Bip87,
            (48, Some(Ok(script_type))) if script_type == 1u8 => Bip43::Bip48Nested,
            (48, Some(Ok(script_type))) if script_type == 2u8 => Bip43::Bip48Native,
            (48, _) => return None,
            (purpose, ..) if derivation.len() > 2 && purpose > 2 => Bip43::Bip43 {
                purpose: HardenedIndex::hardened(purpose as u16),
            },
            _ => return None,
        })
    }

    fn purpose(&self) -> Option<HardenedIndex> {
        Some(match self {
            Bip43::Bip44 => HardenedIndex::hardened(44),
            Bip43::Bip84 => HardenedIndex::hardened(84),
            Bip43::Bip49 => HardenedIndex::hardened(49),
            Bip43::Bip86 => HardenedIndex::hardened(86),
            Bip43::Bip45 => HardenedIndex::hardened(45),
            Bip43::Bip48Nested | Bip43::Bip48Native => HardenedIndex::hardened(48),
            Bip43::Bip87 => HardenedIndex::hardened(87),
            Bip43::Bip43 { purpose } => *purpose,
        })
    }

    fn account_depth(&self) -> Option<u8> {
        Some(match self {
            Bip43::Bip45 => return None,
            Bip43::Bip44
            | Bip43::Bip84
            | Bip43::Bip49
            | Bip43::Bip86
            | Bip43::Bip87
            | Bip43::Bip48Nested
            | Bip43::Bip48Native
            | Bip43::Bip43 { .. } => 3,
        })
    }

    fn coin_type_depth(&self) -> Option<u8> {
        Some(match self {
            Bip43::Bip45 => return None,
            Bip43::Bip44
            | Bip43::Bip84
            | Bip43::Bip49
            | Bip43::Bip86
            | Bip43::Bip87
            | Bip43::Bip48Nested
            | Bip43::Bip48Native
            | Bip43::Bip43 { .. } => 2,
        })
    }

    fn is_account_last_hardened(&self) -> Option<bool> {
        Some(match self {
            Bip43::Bip45 => false,
            Bip43::Bip44
            | Bip43::Bip84
            | Bip43::Bip49
            | Bip43::Bip86
            | Bip43::Bip87
            | Bip43::Bip43 { .. } => true,
            Bip43::Bip48Nested | Bip43::Bip48Native => false,
        })
    }

    fn is_testnet(&self, path: &DerivationPath) -> Result<bool, Option<DerivationIndex>> {
        match self.extract_coin_type(path) {
            Err(None) => Err(None),
            Err(Some(idx)) => Err(Some(idx.into())),
            Ok(HardenedIndex::ZERO) => Ok(false),
            Ok(HardenedIndex::ONE) => Ok(true),
            Ok(idx) => Err(Some(idx.into())),
        }
    }

    fn account_template_string(&self, testnet: bool) -> String {
        let coin_type = if testnet { HardenedIndex::ONE } else { HardenedIndex::ZERO };
        match self {
            Bip43::Bip45
            | Bip43::Bip44
            | Bip43::Bip84
            | Bip43::Bip49
            | Bip43::Bip86
            | Bip43::Bip87
            | Bip43::Bip43 { .. } => format!("{:#}/{}/*h", self, coin_type),
            Bip43::Bip48Nested => {
                format!("{:#}", self).replace("//", &format!("/{}/*h/", coin_type))
            }
            Bip43::Bip48Native => {
                format!("{:#}", self).replace("//", &format!("/{}/*h/", coin_type))
            }
        }
    }

    fn to_origin_derivation(&self, testnet: bool) -> DerivationPath<HardenedIndex> {
        let mut path = Vec::with_capacity(2);
        if let Some(purpose) = self.purpose() {
            path.push(purpose.into())
        }
        path.push(if testnet { HardenedIndex::ONE } else { HardenedIndex::ZERO });
        path.into()
    }

    fn to_account_derivation(
        &self,
        account_index: HardenedIndex,
        testnet: bool,
    ) -> DerivationPath<HardenedIndex> {
        let mut path = Vec::with_capacity(4);
        path.push(account_index);
        if self == &Bip43::Bip48Native {
            path.push(HardenedIndex::from(2u8).into());
        } else if self == &Bip43::Bip48Nested {
            path.push(HardenedIndex::from(1u8).into());
        }
        let mut derivation = self.to_origin_derivation(testnet);
        derivation.extend(&path);
        derivation
    }

    fn to_key_derivation(
        &self,
        account_index: HardenedIndex,
        testnet: bool,
        keychain: NormalIndex,
        index: NormalIndex,
    ) -> DerivationPath {
        let mut derivation = self
            .to_account_derivation(account_index, testnet)
            .into_iter()
            .map(DerivationIndex::from)
            .collect::<DerivationPath>();
        derivation.push(keychain.into());
        derivation.push(index.into());
        derivation
    }
}
