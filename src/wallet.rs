// Modern, lightweight, standard-compliant read-only wallet library
// based on descriptors
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

use std::collections::BTreeMap;

pub struct TapretKeyOnly {
    key_path: String,
    taprets: BTreeMap<TerminalPath, Vec<mpc::Commitment>>,
}

pub enum Descr {
    TapretKeyOnly(TapretKeyOnly),
}

pub struct AccountXpub {
    master_fp: Option<Fingerprint>,
    derivation: Option<DerivationPath>,
    xpub: Xpub,
}

pub struct Actor {
    name: String,
    description: Option<String>,
}

pub struct Signer {
    actor: String,
    name: String,
    description: Option<String>,
    account: AccountXpub,
    terminal: TerminalPath,
}

pub struct Wallet {
    name: String,
    description: Option<String>,
    created: Date<Utc>,
    testnet: bool,
    rgb: bool,
    actors: BTreeMap<String, Actor>,
    signers: BTreeMap<String, Signer>,
    variables: BTreeMap<String, String>,
    descriptor: Descr,
}
