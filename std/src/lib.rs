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
pub extern crate bitcoin_hashes as hashes;

mod base58;
mod address;
mod network;

mod taptree;

mod index;
mod path;
mod xpub;
mod derive;

#[cfg(feature = "core")]
pub use ::bp::{dbc, seals};
pub use address::{
    Address, AddressError, AddressNetwork, AddressParseError, AddressPayload, AddressType,
};
pub use bc::{secp256k1, *};
pub use derive::{
    Derive, DeriveCompr, DeriveKey, DeriveScripts, DeriveSet, DeriveXOnly, DerivedAddr,
    DerivedAddrParseError, DerivedScript, Keychain, Terminal, TerminalParseError,
};
pub use index::{
    DerivationIndex, HardenedIndex, Idx, IdxBase, IndexError, IndexParseError, NormalIndex,
    HARDENED_INDEX_BOUNDARY,
};
pub use network::{Network, UnknownNetwork};
pub use path::{DerivationParseError, DerivationPath, DerivationSeg, SegParseError};
pub use taptree::{
    ControlBlockFactory, FinalizedTree, InvalidTree, LeafInfo, TapDerivation, TapTree,
    TapTreeBuilder, UnfinalizedTree,
};
pub use xpub::{
    KeyOrigin, OriginParseError, Xpub, XpubDecodeError, XpubDerivable, XpubFp, XpubId, XpubMeta,
    XpubOrigin, XpubSpec,
};
