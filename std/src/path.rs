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

use core::fmt::{self, Display, Formatter};
use core::str::FromStr;

use crate::{DerivationIndex, IndexParseError};

#[derive(Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum DerivationParseError {
    /// unable to parse derivation path '{0}' - {1}
    InvalidIndex(String, IndexParseError),
    /// invalid derivation path format '{0}'
    InvalidFormat(String),
}

/// Derivation path that consisting only of single type of segments.
///
/// Useful in specifying concrete derivation from a provided extended public key
/// without extended private key accessible.
///
/// Type guarantees that the number of derivation path segments is non-zero.
#[derive(Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
pub struct DerivationPath<I = DerivationIndex>(Vec<I>);

impl<I: Clone> From<&[I]> for DerivationPath<I> {
    fn from(path: &[I]) -> Self { Self(path.to_vec()) }
}

impl<I: Display> Display for DerivationPath<I> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for segment in &self.0 {
            f.write_str("/")?;
            Display::fmt(segment, f)?;
        }
        Ok(())
    }
}

impl<I: FromStr> FromStr for DerivationPath<I>
where IndexParseError: From<<I as FromStr>::Err>
{
    type Err = DerivationParseError;

    fn from_str(mut s: &str) -> Result<Self, Self::Err> {
        if s.starts_with('/') {
            s = &s[1..];
        }
        let inner = s
            .split('/')
            .map(I::from_str)
            .collect::<Result<Vec<_>, I::Err>>()
            .map_err(|err| DerivationParseError::InvalidIndex(s.to_owned(), err.into()))?;
        if inner.is_empty() {
            return Err(DerivationParseError::InvalidFormat(s.to_owned()));
        }
        Ok(Self(inner))
    }
}

impl<I> IntoIterator for DerivationPath<I> {
    type Item = I;
    type IntoIter = std::vec::IntoIter<I>;

    fn into_iter(self) -> Self::IntoIter { self.0.into_iter() }
}

impl<'path, I: Copy> IntoIterator for &'path DerivationPath<I> {
    type Item = I;
    type IntoIter = std::iter::Copied<std::slice::Iter<'path, I>>;

    fn into_iter(self) -> Self::IntoIter { self.0.iter().copied() }
}

impl<I> FromIterator<I> for DerivationPath<I> {
    fn from_iter<T: IntoIterator<Item = I>>(iter: T) -> Self { Self(iter.into_iter().collect()) }
}

impl<I> DerivationPath<I> {
    /// Constructs empty derivation path.
    pub fn new() -> Self { Self(vec![]) }
}
