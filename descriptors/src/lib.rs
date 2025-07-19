// Modern, minimalistic & standard-compliant Bitcoin library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Labs, Institute for Distributed and Cognitive Systems (InDCS).
// Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
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
extern crate serde;

mod script;
mod descriptor;
mod singlesig;
mod multisig;
mod tr;

pub mod compiler;

pub use descriptor::{DescrId, Descriptor, LegacyKeySig, SpkClass, StdDescr, TaprootKeySig};
pub use multisig::{
    ShMulti, ShSortedMulti, ShWshMulti, ShWshSortedMulti, WshMulti, WshSortedMulti,
};
pub use script::{
    Raw, ScriptDescr, ScriptItem, Sh, ShScript, ShWsh, ShWshScript, WitnessItem, Wsh, WshScript,
};
pub use singlesig::{Pkh, ShWpkh, Wpkh};
pub use tr::{Tr, TrKey, TrMulti, TrScript, TrSortedMulti};
