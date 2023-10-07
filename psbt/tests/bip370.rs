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

use psbt::Psbt;

fn parse_roundtrip(s: &str) {
    let psbt = Psbt::from_str(s).unwrap();
    Psbt::from_str(&psbt.to_string()).unwrap();
}

#[test]
fn base() { parse_roundtrip(include_str!("valid.v2/base.psbt")); }

#[test]
fn updated() { parse_roundtrip(include_str!("valid.v2/updated.psbt")); }

#[test]
fn nseq() { parse_roundtrip(include_str!("valid.v2/nseq.psbt")); }

#[test]
fn locks() { parse_roundtrip(include_str!("valid.v2/locks.psbt")); }

#[test]
fn in_modifiable() { parse_roundtrip(include_str!("valid.v2/in_modifiable.psbt")); }

#[test]
fn out_modifiable() { parse_roundtrip(include_str!("valid.v2/out_modifiable.psbt")); }

#[test]
fn sighash_single() { parse_roundtrip(include_str!("valid.v2/sighash_single.psbt")); }

#[test]
fn undefined_flag() { parse_roundtrip(include_str!("valid.v2/undefined_flag.psbt")); }

#[test]
fn all_modifiable() { parse_roundtrip(include_str!("valid.v2/all_modifiable.psbt")); }

/// Case: 1 input, 2 output updated PSBTv2, with all PSBTv2 fields
#[test]
fn all() { parse_roundtrip(include_str!("valid.v2/all.psbt")); }
