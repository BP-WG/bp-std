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

use amplify::confinement::SmallOrdMap;
use amplify::ByteArray;
use bp::seals::mmb::BundleProof;
use bp::seals::{mmb, mpc};
use commit_verify::CommitId;
use derive::ByteStr;

use crate::{Input, KeyAlreadyPresent, KeyMap, PropKey, Psbt};

/// PSBT proprietary key prefix used for MMB commitment-related data.
pub const PSBT_MMB_PREFIX: &str = "MMB";

/// Proprietary key subtype for storing MMB single commitment message under some protocol in global
/// map.
pub const PSBT_IN_MMB_MESSAGE: u64 = 0x01;

impl PropKey {
    /// Constructs [`PSBT_IN_MMB_MESSAGE`] proprietary key.
    pub fn mmb_message(protocol_id: mpc::ProtocolId) -> PropKey {
        PropKey {
            identifier: PSBT_MMB_PREFIX.to_owned(),
            subtype: PSBT_IN_MMB_MESSAGE,
            data: ByteStr::from(protocol_id.to_vec()),
        }
    }
}

impl Input {
    pub fn mmb_protocols(&self) -> impl Iterator<Item = mpc::ProtocolId> + use<'_> {
        self.proprietary
            .keys()
            .filter(|key| key.identifier == PSBT_MMB_PREFIX && key.subtype == PSBT_IN_MMB_MESSAGE)
            .filter_map(|key| mpc::ProtocolId::from_slice(&key.data).ok())
    }

    /// Returns a valid [`mmb::Message`] associated with the given [`mpc::ProtocolId`], if any.
    ///
    /// We do not error on invalid data in order to support future update of this proprietary key to
    /// a standard one. In this case, the invalid data will be filtered at the moment of PSBT
    /// deserialization and this function will return `None` only in situations when the key is
    /// absent.
    pub fn mmb_message(&self, protocol_id: mpc::ProtocolId) -> Option<mmb::Message> {
        let key = PropKey::mmb_message(protocol_id);
        let data = self.proprietary(&key)?;
        mmb::Message::from_slice(data).ok()
    }

    /// Sets [`mmb::Message`] for the given [`mpc::ProtocolId`].
    ///
    /// # Returns
    ///
    /// `true`, if the message was set successfully, `false` if this message was already present for
    /// this protocol.
    ///
    /// # Errors
    ///
    /// If the key for the given [`mpc::ProtocolId`] is already present but the message is
    /// different.
    pub fn set_mmb_message(
        &mut self,
        protocol_id: mpc::ProtocolId,
        message: mmb::Message,
    ) -> Result<bool, KeyAlreadyPresent> {
        let key = PropKey::mmb_message(protocol_id);
        let val = message.to_vec();
        self.push_proprietary(key, val)
    }
}

impl Psbt {
    pub fn mmb_protocols(&self) -> impl Iterator<Item = mpc::ProtocolId> + use<'_> {
        self.inputs().flat_map(|inp| inp.mmb_protocols())
    }

    pub fn mmb_complete(&mut self) -> Result<commit_verify::mpc::MessageMap, MmbPsbtError> {
        let mut map = medium_bmap!();
        for id in self.mmb_protocols() {
            let iter = self
                .inputs()
                .filter_map(|inp| inp.mmb_message(id).map(|msg| (inp.index as u32, msg)));
            let proof = BundleProof {
                map: SmallOrdMap::try_from_iter(iter)
                    .map_err(|_| MmbPsbtError::TooManyInputs(id))?,
            };
            map.insert(id, mpc::Message::from(proof.commit_id()))
                .map_err(|_| MmbPsbtError::TooManyProtocols)?;
        }
        Ok(map)
    }
}

/// Errors processing MMB-related proprietary PSBT keys and their values.
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum MmbPsbtError {
    /// too many inputs for multi-message bundle in protocol {0}.
    TooManyInputs(mpc::ProtocolId),

    /// too many protocols is used in multi-message commitment.
    TooManyProtocols,
}
