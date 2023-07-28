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

use std::cmp::Ordering;
use std::num::ParseIntError;
use std::ops::Range;
use std::str::FromStr;

/// Constant determining BIP32 boundary for u32 values after which index
/// is treated as hardened
pub const HARDENED_INDEX_BOUNDARY: u32 = 1 << 31;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display("provided {what} {invalid} is invalid: it lies outside allowed range {start}..={end}")]
pub struct IndexError {
    pub what: &'static str,
    pub invalid: u32,
    pub start: u32,
    pub end: u32,
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum IndexParseError {
    #[from]
    #[display(inner)]
    Invalid(IndexError),

    #[from]
    /// invalid index string representation - {0}
    Parse(ParseIntError),
}

/// Trait defining common API for different types of indexes which may be
/// present in a certain derivation path segment: hardened, unhardened, mixed.
pub trait Idx
where Self: Sized + Eq + Ord + Copy
{
    /// Derivation path segment with index equal to minimal value.
    const MIN: Self = Self::ZERO;

    /// Derivation path segment with index equal to zero.
    const ZERO: Self;

    /// Derivation path segment with index equal to one.
    const ONE: Self;

    /// Derivation path segment with index equal to maximum value.
    const MAX: Self;

    /// Range covering all possible index values.
    const RANGE: Range<Self> = Range {
        start: Self::MIN,
        end: Self::MAX,
    };

    /// Counts number of derivation indexes in this derivation path segment.
    fn count(&self) -> usize { Self::MAX.index() as usize - Self::MIN.index() as usize }

    /// Constructs derivation path segment with specific index.
    ///
    /// Index is always a value in range of `0..`[`HARDENED_INDEX_BOUNDARY`]
    fn from_index(index: impl Into<u16>) -> Self;

    /// Constructs derivation path segment with specific index.
    ///
    /// Index is always a value in range of `0..`[`HARDENED_INDEX_BOUNDARY`]
    fn try_from_index(index: impl Into<u32>) -> Result<Self, IndexError>;

    /// Returns index representation of this derivation path segment.
    ///
    /// Index is always a value in range of `0..`[`HARDENED_INDEX_BOUNDARY`]
    fn index(&self) -> u32;

    /// Constructs derivation path segment with specific derivation value, which
    /// for normal indexes must lie in range `0..`[`HARDENED_INDEX_BOUNDARY`]
    /// and for hardened in range of [`HARDENED_INDEX_BOUNDARY`]`..=u32::MAX`
    fn try_from_derivation(value: u32) -> Result<Self, IndexError>;

    /// Returns value used during derivation, which for normal indexes must lie
    /// in range `0..`[`HARDENED_INDEX_BOUNDARY`] and for hardened in range
    /// of [`HARDENED_INDEX_BOUNDARY`]`..=u32::MAX`
    fn derivation(&self) -> u32;

    /// Increases the index on one step; fails if the index value is already
    /// maximum value - or if multiple indexes are present at the path segment
    fn checked_inc(&self) -> Option<Self> { self.checked_add(1u8) }

    /// Decreases the index on one step; fails if the index value is already
    /// minimum value - or if multiple indexes are present at the path segment
    fn checked_dec(&self) -> Option<Self> { self.checked_sub(1u8) }

    /// Mutates the self by increasing the index on one step; fails if the index
    /// value is already maximum value - or if multiple indexes are present at
    /// the path segment
    fn checked_inc_assign(&mut self) -> Option<u32> { self.checked_add_assign(1u8) }

    /// Mutates the self by decreasing the index on one step; fails if the index
    /// value is already maximum value - or if multiple indexes are present at
    /// the path segment
    fn checked_dec_assign(&mut self) -> Option<u32> { self.checked_sub_assign(1u8) }

    /// Adds value the index; fails if the index value overflow happens - or if
    /// multiple indexes are present at the path segment
    fn checked_add(&self, add: impl Into<u32>) -> Option<Self> {
        let mut res = self.clone();
        res.checked_add_assign(add)?;
        Some(res)
    }

    /// Subtracts value the index; fails if the index value overflow happens -
    /// or if multiple indexes are present at the path segment
    fn checked_sub(&self, sub: impl Into<u32>) -> Option<Self> {
        let mut res = self.clone();
        res.checked_sub_assign(sub)?;
        Some(res)
    }

    /// Mutates the self by adding value the index; fails if the index value
    /// overflow happens - or if multiple indexes are present at the path
    /// segment
    fn checked_add_assign(&mut self, add: impl Into<u32>) -> Option<u32>;

    /// Mutates the self by subtracting value the index; fails if the index
    /// value overflow happens - or if multiple indexes are present at the
    /// path segment
    fn checked_sub_assign(&mut self, sub: impl Into<u32>) -> Option<u32>;

    /// Detects whether path segment uses hardened index(es)
    fn is_hardened(&self) -> bool;
}

fn checked_add_assign(index: &mut u32, add: impl Into<u32>) -> Option<u32> {
    let add: u32 = add.into();
    *index = index.checked_add(add)?;
    if *index >= HARDENED_INDEX_BOUNDARY {
        return None;
    }
    Some(*index)
}

fn checked_sub_assign(index: &mut u32, sub: impl Into<u32>) -> Option<u32> {
    let sub: u32 = sub.into();
    *index = index.checked_sub(sub)?;
    Some(*index)
}

/// Index for unhardened children derivation; ensures that the inner value
/// is always < 2^31
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Default, Display, From)]
#[display(inner)]
pub struct NormalIndex(
    #[from(u8)]
    #[from(u16)]
    u32,
);

impl PartialEq<u8> for NormalIndex {
    fn eq(&self, other: &u8) -> bool { self.0 == *other as u32 }
}

impl PartialEq<u16> for NormalIndex {
    fn eq(&self, other: &u16) -> bool { self.0 == *other as u32 }
}

impl PartialOrd<u8> for NormalIndex {
    fn partial_cmp(&self, other: &u8) -> Option<Ordering> { self.0.partial_cmp(&(*other as u32)) }
}

impl PartialOrd<u16> for NormalIndex {
    fn partial_cmp(&self, other: &u16) -> Option<Ordering> { self.0.partial_cmp(&(*other as u32)) }
}

impl From<&NormalIndex> for NormalIndex {
    fn from(index: &NormalIndex) -> Self { *index }
}

impl Idx for NormalIndex {
    const ZERO: Self = Self(0);

    const ONE: Self = Self(1);

    const MAX: Self = Self(HARDENED_INDEX_BOUNDARY - 1);

    #[inline]
    fn from_index(index: impl Into<u16>) -> Self { Self(index.into() as u32) }

    #[inline]
    fn try_from_index(index: impl Into<u32>) -> Result<Self, IndexError> {
        let index = index.into();
        if index >= HARDENED_INDEX_BOUNDARY {
            Err(IndexError {
                what: "index",
                invalid: index,
                start: 0,
                end: HARDENED_INDEX_BOUNDARY,
            })
        } else {
            Ok(Self(index))
        }
    }

    /// Returns unhardened index number.
    #[inline]
    fn index(&self) -> u32 { self.0 }

    #[inline]
    fn try_from_derivation(value: u32) -> Result<Self, IndexError> {
        Self::try_from_index(value).map_err(|mut err| {
            err.what = "derivation value";
            err
        })
    }

    #[inline]
    fn derivation(&self) -> u32 { self.index() }

    #[inline]
    fn checked_add_assign(&mut self, add: impl Into<u32>) -> Option<u32> {
        checked_add_assign(&mut self.0, add)
    }

    #[inline]
    fn checked_sub_assign(&mut self, sub: impl Into<u32>) -> Option<u32> {
        checked_sub_assign(&mut self.0, sub)
    }

    #[inline]
    fn is_hardened(&self) -> bool { false }
}

impl FromStr for NormalIndex {
    type Err = IndexParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(NormalIndex::try_from_index(u32::from_str(s)?)?)
    }
}

/// Index for hardened children derivation; ensures that the index always >=
/// 2^31.
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default, Display, From)]
#[display("{0}h", alt = "{0}'")]
pub struct HardenedIndex(
    /// The inner index value; always reduced by [`HARDENED_INDEX_BOUNDARY`]
    #[from(u8)]
    #[from(u16)]
    pub(crate) u32,
);

impl PartialEq<u8> for HardenedIndex {
    fn eq(&self, other: &u8) -> bool { self.0 == *other as u32 }
}

impl PartialEq<u16> for HardenedIndex {
    fn eq(&self, other: &u16) -> bool { self.0 == *other as u32 }
}

impl PartialOrd<u8> for HardenedIndex {
    fn partial_cmp(&self, other: &u8) -> Option<Ordering> { self.0.partial_cmp(&(*other as u32)) }
}

impl PartialOrd<u16> for HardenedIndex {
    fn partial_cmp(&self, other: &u16) -> Option<Ordering> { self.0.partial_cmp(&(*other as u32)) }
}

impl Idx for HardenedIndex {
    const ZERO: Self = Self(HARDENED_INDEX_BOUNDARY);

    const ONE: Self = Self(1);

    const MAX: Self = Self(u32::MAX);

    #[inline]
    fn from_index(index: impl Into<u16>) -> Self { Self(index.into() as u32) }

    #[inline]
    fn try_from_index(index: impl Into<u32>) -> Result<Self, IndexError> {
        let index = index.into();
        if index < HARDENED_INDEX_BOUNDARY {
            Ok(Self(index - HARDENED_INDEX_BOUNDARY))
        } else {
            Err(IndexError {
                what: "index",
                invalid: index,
                start: 0,
                end: HARDENED_INDEX_BOUNDARY,
            })
        }
    }

    /// Returns hardened index number offset by [`HARDENED_INDEX_BOUNDARY`]
    /// (i.e. zero-based).
    #[inline]
    fn index(&self) -> u32 { self.0 }

    #[inline]
    fn try_from_derivation(value: u32) -> Result<Self, IndexError> {
        Self::try_from_index(value - HARDENED_INDEX_BOUNDARY).map_err(|_| IndexError {
            what: "derivation value",
            invalid: value,
            start: HARDENED_INDEX_BOUNDARY,
            end: u32::MAX,
        })
    }

    #[inline]
    fn derivation(&self) -> u32 { self.0 + HARDENED_INDEX_BOUNDARY }

    #[inline]
    fn checked_add_assign(&mut self, add: impl Into<u32>) -> Option<u32> {
        checked_add_assign(&mut self.0, add)
    }

    #[inline]
    fn checked_sub_assign(&mut self, sub: impl Into<u32>) -> Option<u32> {
        checked_sub_assign(&mut self.0, sub)
    }

    #[inline]
    fn is_hardened(&self) -> bool { true }
}

impl FromStr for HardenedIndex {
    type Err = IndexParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(HardenedIndex::try_from_index(u32::from_str(s)?)?)
    }
}
