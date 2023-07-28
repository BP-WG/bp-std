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

use secp256k1::PublicKey;

use crate::{DerivationIndex, DerivationPath};

/// BIP32 chain code used for hierarchical derivation
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(RangeOps)]
pub struct ChainCode([u8; 32]);

/// Deterministic part of the extended public key.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct XpubCore {
    /// Public key
    pub public_key: PublicKey,
    /// BIP32 chain code used for hierarchical derivation
    pub chain_code: ChainCode,
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug, From)]
#[wrapper(RangeOps)]
pub struct XpubFp([u8; 4]);

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug, From)]
#[wrapper(RangeOps)]
pub struct XpubId([u8; 20]);

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct XpubMeta {
    pub depth: u8,
    pub parent_fp: XpubFp,
    pub child_number: DerivationIndex,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct Xpub {
    testnet: bool,
    meta: XpubMeta,
    core: XpubCore,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct XpubDescriptor {
    master_fp: XpubFp,
    derivation: DerivationPath,
    xpub: Xpub,
}
