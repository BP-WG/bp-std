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

use bc::secp256k1::{ecdsa, schnorr as bip340};
use bc::{
    InternalPk, LegacyPk, Sighash, TapLeafHash, TapMerklePath, TapNodeHash, TapSighash, XOnlyPk,
};

use crate::KeyOrigin;

/// Trait used for signing transactions.
pub trait Sign {
    /// Create signature with a given key for inputs requiring ECDSA signatures (bare, pre-segwit
    /// and segwit v0).
    fn sign_ecdsa(
        &self,
        message: Sighash,
        pk: LegacyPk,
        origin: Option<&KeyOrigin>,
    ) -> Option<ecdsa::Signature>;

    /// Create signature with a given internal key using Schnorr signatures with BIP-340 signing
    /// scheme (taproot).
    fn sign_bip340_key_only(
        &self,
        message: TapSighash,
        pk: InternalPk,
        origin: Option<&KeyOrigin>,
        merkle_root: Option<TapNodeHash>,
    ) -> Option<bip340::Signature>;

    /// Create signature with a given script path and x-only public key using Schnorr signatures
    /// with BIP-340 signing scheme (taproot).
    fn sign_bip340_script_path(
        &self,
        message: TapSighash,
        pk: XOnlyPk,
        origin: Option<&KeyOrigin>,
    ) -> Option<bip340::Signature>;

    /// Detect whether a given taproot script spending path should be signed for a given input
    /// `index`.
    #[must_use]
    fn should_sign_script_path(
        &self,
        index: usize,
        merkle_path: &TapMerklePath,
        leaf: TapLeafHash,
    ) -> bool;

    /// Detect whether taproot key spending path should be signed for a given input `index`.
    #[must_use]
    fn should_sign_key_path(&self, index: usize) -> bool;
}
