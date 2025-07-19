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

use bp::dbc::tapret::TapretProof;
use commit_verify::mpc;

use crate::{MmbPsbtError, MpcPsbtError, OpretKeyError, Psbt, TapretKeyError};

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum DbcPsbtError {
    /// the first output valid for a DBC commitment is not marked as a commitment host.
    NoHostOutput,

    /// the transaction contains no output valid for a DBC commitment.
    NoProperOutput,

    /// DBC commitment is already present.
    AlreadyPresent,

    /// transaction outputs are marked as modifiable, thus deterministic bitcoin commitment can't
    /// be created.
    TxOutputsModifiable,

    #[from]
    #[display(inner)]
    Mmb(MmbPsbtError),

    #[from]
    #[display(inner)]
    Mpc(MpcPsbtError),

    #[from]
    #[display(inner)]
    Tapret(TapretKeyError),

    #[from]
    #[display(inner)]
    Opret(OpretKeyError),
}

impl Psbt {
    pub fn dbc_commit(&mut self) -> Result<(mpc::MerkleBlock, Option<TapretProof>), DbcPsbtError> {
        if self.are_outputs_modifiable() {
            return Err(DbcPsbtError::TxOutputsModifiable);
        }

        let map = self.mmb_complete()?;
        let output = self
            .outputs_mut()
            .find(|out| out.script.is_op_return() || out.script.is_p2tr())
            .ok_or(DbcPsbtError::NoProperOutput)?;

        for (id, msg) in map {
            output.set_mpc_message(id, msg)?;
        }
        let (commitment, mpc_proof) = output.mpc_commit()?;

        if output.script.is_op_return() {
            if !output.is_opret_host() {
                return Err(DbcPsbtError::NoHostOutput);
            }
            output.opret_commit(commitment)?;
            Ok((mpc_proof, None))
        } else {
            if !output.is_tapret_host() {
                return Err(DbcPsbtError::NoHostOutput);
            }
            let tapret_proof = output.tapret_commit(commitment)?;
            Ok((mpc_proof, Some(tapret_proof)))
        }
    }
}
