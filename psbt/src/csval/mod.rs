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

//! Managing client-side-validation-related proprietary keys inside PSBT.
//!
//! Supports deterministic bitcoin commitments with tapret and opret schemes and multi-protocol
//! commitment structures used by all of them.

mod mmb;
mod mpc;
mod dbc;
pub mod opret;
pub mod tapret;

pub use dbc::DbcPsbtError;
pub use mmb::{MmbPsbtError, PSBT_IN_MMB_MESSAGE, PSBT_MMB_PREFIX};
pub use mpc::{
    MpcPsbtError, PSBT_MPC_PREFIX, PSBT_OUT_MPC_COMMITMENT, PSBT_OUT_MPC_ENTROPY,
    PSBT_OUT_MPC_MESSAGE, PSBT_OUT_MPC_MIN_TREE_DEPTH, PSBT_OUT_MPC_PROOF,
};
pub use opret::{OpretKeyError, PSBT_OPRET_PREFIX, PSBT_OUT_OPRET_COMMITMENT, PSBT_OUT_OPRET_HOST};
pub use tapret::{
    TapretKeyError, PSBT_IN_TAPRET_TWEAK, PSBT_OUT_TAPRET_COMMITMENT, PSBT_OUT_TAPRET_HOST,
    PSBT_OUT_TAPRET_PROOF, PSBT_TAPRET_PREFIX,
};
