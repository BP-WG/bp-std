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

use std::collections::HashMap;

use amplify::Wrapper;
use bc::secp256k1::{ecdsa, schnorr as bip340, SECP256K1};
use bc::{LegacyPk, Sighash, TapLeafHash, TapMerklePath, TapSighash, XOnlyPk};
use derive::{KeyOrigin, Satisfy, XkeyOrigin, Xpriv, XprivAccount};
use psbt::{Psbt, Rejected, Sign};

#[derive(Clone)]
pub struct TestSigner<'a> {
    pub keys: HashMap<&'a XkeyOrigin, &'a Xpriv>,
    pub key_path: bool,
    pub script_path: Option<TapLeafHash>,
}

impl<'a> TestSigner<'a> {
    pub fn new(account: &'a XprivAccount) -> Self { Self::with(true, None, [account]) }

    pub fn new_legacy(iter: impl IntoIterator<Item = &'a XprivAccount>) -> Self {
        Self::with(false, None, iter)
    }

    pub fn new_key_spend(iter: impl IntoIterator<Item = &'a XprivAccount>) -> Self {
        Self::with(true, None, iter)
    }

    pub fn new_script_spent(
        leaf: impl Into<TapLeafHash>,
        iter: impl IntoIterator<Item = &'a XprivAccount>,
    ) -> Self {
        Self::with(false, Some(leaf.into()), iter)
    }

    pub fn with(
        key_path: bool,
        script_path: Option<TapLeafHash>,
        iter: impl IntoIterator<Item = &'a XprivAccount>,
    ) -> Self {
        Self {
            keys: iter
                .into_iter()
                .map(|account| (account.origin(), account.xpriv()))
                .filter(|(origin, xpriv)| {
                    if xpriv.is_testnet() {
                        true
                    } else {
                        eprintln!(
                            "Extended private key with origin {origin} will not be used for \
                             signing since it belongs to mainnet"
                        );
                        false
                    }
                })
                .collect(),
            key_path,
            script_path,
        }
    }
}

impl<'a> Sign for TestSigner<'a> {
    type Satisfier<'s> = Self where Self: 's;

    fn approve(&self, _: &Psbt) -> Result<Self::Satisfier<'_>, Rejected> { Ok(self.clone()) }
}

impl<'a> TestSigner<'a> {
    fn get(&self, origin: Option<&KeyOrigin>) -> Option<Xpriv> {
        let origin = origin?;
        self.keys.iter().find_map(|(xo, xpriv)| {
            if let Some(derivation) = xo.child_derivation(origin) {
                return Some(xpriv.derive_priv(derivation));
            }
            None
        })
    }
}

impl<'a> Satisfy for TestSigner<'a> {
    fn signature_ecdsa(
        &self,
        message: Sighash,
        pk: LegacyPk,
        origin: Option<&KeyOrigin>,
    ) -> Option<ecdsa::Signature> {
        if !pk.compressed {
            return None;
        }
        let xpriv = self.get(origin)?;
        let sk = xpriv.to_private_ecdsa();
        if sk.public_key(SECP256K1) != pk.pubkey {
            return None;
        }
        Some(sk.sign_ecdsa(message.into()))
    }

    fn signature_bip340(
        &self,
        message: TapSighash,
        pk: XOnlyPk,
        origin: Option<&KeyOrigin>,
    ) -> Option<bip340::Signature> {
        let xpriv = self.get(origin)?;
        let sk = xpriv.to_keypair_bip340();
        if sk.x_only_public_key().0 != pk.into_inner() {
            return None;
        }
        Some(sk.sign_schnorr(message.into()))
    }

    fn should_satisfy_script_path(
        &self,
        _index: usize,
        _merkle_path: &TapMerklePath,
        leaf: TapLeafHash,
    ) -> bool {
        self.script_path == Some(leaf)
    }

    fn should_satisfy_key_path(&self, _index: usize) -> bool { self.key_path }
}
