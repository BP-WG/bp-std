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

use psbt::Psbt;

fn parse_roundtrip(s: &str) {
    let psbt = Psbt::from_str(s).unwrap();
    Psbt::from_str(&psbt.to_string()).unwrap();
}

/// Case: PSBT with one P2TR key only input with internal key and its derivation path
#[test]
fn keyonly_in() { parse_roundtrip(include_str!("valid.tr/keyonly_in.psbt")); }

/// Case: PSBT with one P2TR key only input with internal key, its derivation path, and signature
#[test]
fn keyonly_out() { parse_roundtrip(include_str!("valid.tr/keyonly_out.psbt")); }

/// Case: PSBT with one P2TR key only output with internal key and its derivation path
#[test]
fn keyonly_signed() { parse_roundtrip(include_str!("valid.tr/keyonly_signed.psbt")); }

/// Case: PSBT with one P2TR script path only input with dummy internal key, scripts, derivation
/// paths for keys in the scripts, and merkle root
#[test]
fn script_in() { parse_roundtrip(include_str!("valid.tr/script_in.psbt")); }

/// Case: PSBT with one P2TR script path only output with dummy internal key, taproot tree, and
/// script key derivation paths
#[test]
fn script_out() { parse_roundtrip(include_str!("valid.tr/script_out.psbt")); }

/// Case: PSBT with one P2TR script path only input with dummy internal key, scripts, script key
/// derivation paths, merkle root, and script path signatures
#[test]
fn script_signed() { parse_roundtrip(include_str!("valid.tr/script_signed.psbt")); }
