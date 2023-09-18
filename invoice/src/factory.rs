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

use bp::{Address, AddressError, AddressNetwork, DeriveSpk, Idx, NormalIndex};

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct AddressFactory<D: DeriveSpk> {
    pub descriptor: D,
    pub network: AddressNetwork,
    pub keychain: u8,
    pub unused_tip: NormalIndex,
}

impl<D: DeriveSpk> Iterator for AddressFactory<D> {
    type Item = Address;

    fn next(&mut self) -> Option<Self::Item> {
        let addr =
            self.descriptor.derive_address(self.network, self.keychain, self.unused_tip).ok()?;
        self.unused_tip.wrapping_inc_assign();
        Some(addr)
    }
}

impl<D: DeriveSpk> AddressFactory<D> {
    pub fn address(&self, index: NormalIndex) -> Result<Address, AddressError> {
        self.descriptor.derive_address(self.network, self.keychain, index)
    }
}
