// RGB wallet library for smart contracts on Bitcoin & Lightning network
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
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

use bp::dbc::opret::OpretProof;
use bp::dbc::tapret::TapretProof;
use bp::dbc::{self, Method};
use commit_verify::mpc;

use crate::{MpcPsbtError, OpretKeyError, Output, Psbt, TapretKeyError};

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum DbcPsbtError {
    /// the first output valid for a DBC commitment is not marked as a commitment host.
    NoHostOutput,

    /// the transactions contains no output valid for {0} DBC commitment.
    NoProperOutput(Method),

    /// DBC commitment is already present.
    AlreadyPresent,

    /// transaction outputs are marked as modifiable, thus deterministic bitcoin commitment can't
    /// be created.
    TxOutputsModifiable,

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
    pub fn dbc_output<D: DbcPsbtProof>(&mut self) -> Option<&Output> {
        self.outputs().find(|output| {
            (output.script.is_p2tr() && D::METHOD == Method::TapretFirst)
                || (output.script.is_op_return() && D::METHOD == Method::OpretFirst)
        })
    }

    pub fn dbc_output_mut<D: DbcPsbtProof>(&mut self) -> Option<&mut Output> {
        self.outputs_mut().find(|output| {
            (output.script.is_p2tr() && D::METHOD == Method::TapretFirst)
                || (output.script.is_op_return() && D::METHOD == Method::OpretFirst)
        })
    }

    pub fn dbc_commit<D: DbcPsbtProof>(&mut self) -> Result<(mpc::MerkleBlock, D), DbcPsbtError> {
        if self.are_outputs_modifiable() {
            return Err(DbcPsbtError::TxOutputsModifiable);
        }

        let output = self.dbc_output_mut::<D>().ok_or(DbcPsbtError::NoProperOutput(D::METHOD))?;

        D::dbc_commit(output)
    }
}

pub trait DbcPsbtProof: dbc::Proof {
    const METHOD: Method;
    fn dbc_commit(output: &mut Output) -> Result<(mpc::MerkleBlock, Self), DbcPsbtError>;
}

impl DbcPsbtProof for TapretProof {
    const METHOD: Method = Method::TapretFirst;

    fn dbc_commit(output: &mut Output) -> Result<(mpc::MerkleBlock, Self), DbcPsbtError> {
        let (commitment, mpc_proof) = output.mpc_commit()?;
        if !output.is_tapret_host() {
            return Err(DbcPsbtError::NoHostOutput);
        }
        let tapret_proof = output.tapret_commit(commitment)?;

        Ok((mpc_proof, tapret_proof))
    }
}

impl DbcPsbtProof for OpretProof {
    const METHOD: Method = Method::OpretFirst;

    fn dbc_commit(output: &mut Output) -> Result<(mpc::MerkleBlock, Self), DbcPsbtError> {
        let (commitment, mpc_proof) = output.mpc_commit()?;
        if !output.is_opret_host() {
            return Err(DbcPsbtError::NoHostOutput);
        }
        output.opret_commit(commitment)?;
        Ok((mpc_proof, OpretProof::default()))
    }
}
