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

use std::cmp::Ordering;
use std::hash::Hash;
use std::num::ParseIntError;
use std::ops::Range;
use std::str::FromStr;

/// Constant determining BIP32 boundary for u32 values after which index
/// is treated as hardened
pub const HARDENED_INDEX_BOUNDARY: u32 = 1 << 31;

#[macro_export]
macro_rules! h {
    ($idx:literal) => {
        HardenedIndex::from(idx as u16).into()
    };
}

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

    /// expected hardened index value instead of the provided unhardened {0}
    HardenedRequired(String),
}

/// Trait defining basic index functionality without mathematics operations.
pub trait IdxBase: Sized + Eq + Ord + Copy {
    /// Detects whether path segment uses hardened index(es)
    fn is_hardened(&self) -> bool;

    /// Returns child number corresponding to this index.
    ///
    /// Child number is always a value in range of `0..`[`HARDENED_INDEX_BOUNDARY`]
    fn child_number(&self) -> u32;

    /// Returns value used during derivation, which for normal indexes must lie
    /// in range `0..`[`HARDENED_INDEX_BOUNDARY`] and for hardened in range
    /// of [`HARDENED_INDEX_BOUNDARY`]`..=u32::MAX`
    fn index(&self) -> u32;
}

/// Trait defining common API for different types of indexes which may be
/// present in a certain derivation path segment: hardened, unhardened, mixed.
pub trait Idx: IdxBase {
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

    /// Constructs index from a given child number.
    ///
    /// Child number is always a value in range of `0..`[`HARDENED_INDEX_BOUNDARY`]
    fn from_child_number(no: impl Into<u16>) -> Self;

    /// Constructs index from a given child number.
    ///
    /// Child number is always a value in range of `0..`[`HARDENED_INDEX_BOUNDARY`]
    fn try_from_child_number(index: impl Into<u32>) -> Result<Self, IndexError>;

    /// Constructs derivation path segment with specific derivation value, which
    /// for normal indexes must lie in range `0..`[`HARDENED_INDEX_BOUNDARY`]
    /// and for hardened in range of [`HARDENED_INDEX_BOUNDARY`]`..=u32::MAX`
    fn try_from_index(value: u32) -> Result<Self, IndexError>;

    fn to_be_bytes(&self) -> [u8; 4] { self.index().to_be_bytes() }

    /// Increments the index on one step; fails if the index value is already
    /// maximum value.
    #[must_use]
    fn checked_inc(&self) -> Option<Self> { self.checked_add(1u8) }

    /// Decrements the index on one step; fails if the index value is already
    /// minimum value.
    #[must_use]
    fn checked_dec(&self) -> Option<Self> { self.checked_sub(1u8) }

    /// Increments the index on one step saturating at the `Self::MAX` bounds
    /// instead of overflowing.
    #[must_use]
    fn saturating_inc(&self) -> Self { self.saturating_add(1u8) }

    /// Decrements the index on one step saturating at the `Self::MIN` bounds
    /// instead of overflowing.
    #[must_use]
    fn saturating_dec(&self) -> Self { self.saturating_sub(1u8) }

    /// Increments the index on one step; fails if the index value is already
    /// maximum value.
    #[must_use]
    fn wrapping_inc(&self) -> Self { self.checked_add(1u8).unwrap_or(Self::MIN) }

    /// Decrements the index on one step; fails if the index value is already
    /// minimum value.
    #[must_use]
    fn wrapping_dec(&self) -> Self { self.checked_sub(1u8).unwrap_or(Self::MAX) }

    /// Mutates the self by incrementing the index on one step; fails if the index
    /// value is already maximum value.
    fn checked_inc_assign(&mut self) -> Option<Self> { self.checked_add_assign(1u8) }

    /// Mutates the self by decrementing the index on one step; fails if the index
    /// value is already maximum value.
    fn checked_dec_assign(&mut self) -> Option<Self> { self.checked_sub_assign(1u8) }

    /// Mutates the self by incrementing the index on one step, saturating at the
    /// `Self::MAX` bounds instead of overflowing.
    fn saturating_inc_assign(&mut self) -> bool { self.saturating_add_assign(1u8) }

    /// Mutates the self by decrementing the index on one step, saturating at the
    /// `Self::MIN` bounds instead of overflowing.
    fn saturating_dec_assign(&mut self) -> bool { self.saturating_sub_assign(1u8) }

    /// Mutates the self by incrementing the index on one step; fails if the index
    /// value is already maximum value.
    fn wrapping_inc_assign(&mut self) { *self = self.wrapping_inc(); }

    /// Mutates the self by decrementing the index on one step; fails if the index
    /// value is already maximum value.
    fn wrapping_dec_assign(&mut self) { *self = self.wrapping_inc(); }

    /// Adds value the index; fails if the index value overflow happens.
    #[must_use]
    fn checked_add(&self, add: impl Into<u32>) -> Option<Self> {
        let mut res = *self;
        res.checked_add_assign(add)?;
        Some(res)
    }

    /// Subtracts value the index; fails if the index value overflow happens.
    #[must_use]
    fn checked_sub(&self, sub: impl Into<u32>) -> Option<Self> {
        let mut res = *self;
        res.checked_sub_assign(sub)?;
        Some(res)
    }

    /// Saturating index addition. Computes `self + add`, saturating at the
    /// `Self::MAX` bounds instead of overflowing.
    #[must_use]
    fn saturating_add(&self, add: impl Into<u32>) -> Self {
        let mut res = *self;
        let _ = res.saturating_add_assign(add);
        res
    }

    /// Saturating index subtraction. Computes `self - add`, saturating at
    /// the `Self::MIN` bounds instead of overflowing.
    #[must_use]
    fn saturating_sub(&self, sub: impl Into<u32>) -> Self {
        let mut res = *self;
        let _ = res.saturating_sub_assign(sub);
        res
    }

    /// Mutates the self by adding value the index; fails if the index value
    /// overflow happens.
    fn checked_add_assign(&mut self, add: impl Into<u32>) -> Option<Self>;

    /// Mutates the self by subtracting value the index; fails if the index
    /// value overflow happens.
    fn checked_sub_assign(&mut self, sub: impl Into<u32>) -> Option<Self>;

    /// Mutates the self by adding value the index saturating it at the
    /// `Self::MAX` value in case of overflow. Returns boolean value
    /// indicating if no overflow had happened.
    fn saturating_add_assign(&mut self, add: impl Into<u32>) -> bool {
        if self.checked_add_assign(add).is_none() {
            *self = Self::MAX;
            false
        } else {
            true
        }
    }

    /// Mutates the self by subtracting value from the index saturating
    /// it at the `Self::MIN` value in case of overflow. Returns boolean value
    /// indicating if no overflow had happened.
    fn saturating_sub_assign(&mut self, sub: impl Into<u32>) -> bool {
        if self.checked_sub_assign(sub).is_none() {
            *self = Self::MIN;
            false
        } else {
            true
        }
    }
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
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Default, Display, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
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

impl NormalIndex {
    pub const fn normal(child_number: u16) -> Self { NormalIndex(child_number as u32) }
}

impl IdxBase for NormalIndex {
    #[inline]
    fn index(&self) -> u32 { self.child_number() }

    /// Returns unhardened index number.
    #[inline]
    fn child_number(&self) -> u32 { self.0 }

    #[inline]
    fn is_hardened(&self) -> bool { false }
}

impl Idx for NormalIndex {
    const ZERO: Self = Self(0);

    const ONE: Self = Self(1);

    const MAX: Self = Self(HARDENED_INDEX_BOUNDARY - 1);

    #[inline]
    fn from_child_number(index: impl Into<u16>) -> Self { Self(index.into() as u32) }

    #[inline]
    fn try_from_child_number(index: impl Into<u32>) -> Result<Self, IndexError> {
        let index = index.into();
        if index >= HARDENED_INDEX_BOUNDARY {
            Err(IndexError {
                what: "child number",
                invalid: index,
                start: 0,
                end: HARDENED_INDEX_BOUNDARY,
            })
        } else {
            Ok(Self(index))
        }
    }

    #[inline]
    fn try_from_index(value: u32) -> Result<Self, IndexError> {
        Self::try_from_child_number(value).map_err(|mut err| {
            err.what = "index";
            err
        })
    }

    #[inline]
    fn checked_add_assign(&mut self, add: impl Into<u32>) -> Option<Self> {
        checked_add_assign(&mut self.0, add).map(|_| *self)
    }

    #[inline]
    fn checked_sub_assign(&mut self, sub: impl Into<u32>) -> Option<Self> {
        checked_sub_assign(&mut self.0, sub).map(|_| *self)
    }
}

impl TryFrom<DerivationIndex> for NormalIndex {
    type Error = IndexError;

    fn try_from(idx: DerivationIndex) -> Result<Self, Self::Error> {
        NormalIndex::try_from_index(idx.index())
    }
}

impl FromStr for NormalIndex {
    type Err = IndexParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(NormalIndex::try_from_child_number(u32::from_str(s)?)?)
    }
}

/// Index for hardened children derivation; ensures that the index always >=
/// 2^31.
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default, Display, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
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

impl HardenedIndex {
    pub const fn hardened(child_number: u16) -> Self { HardenedIndex(child_number as u32) }
}

impl IdxBase for HardenedIndex {
    /// Returns hardened index number not offset by [`HARDENED_INDEX_BOUNDARY`]
    /// (i.e. zero-based).
    #[inline]
    fn child_number(&self) -> u32 { self.0 }

    /// Returns hardened index number offset by [`HARDENED_INDEX_BOUNDARY`]
    /// (i.e. zero-based).
    #[inline]
    fn index(&self) -> u32 { self.0 + HARDENED_INDEX_BOUNDARY }

    #[inline]
    fn is_hardened(&self) -> bool { true }
}

impl Idx for HardenedIndex {
    const ZERO: Self = Self(HARDENED_INDEX_BOUNDARY);

    const ONE: Self = Self(1);

    const MAX: Self = Self(u32::MAX);

    #[inline]
    fn from_child_number(child_no: impl Into<u16>) -> Self { Self(child_no.into() as u32) }

    #[inline]
    fn try_from_child_number(child_no: impl Into<u32>) -> Result<Self, IndexError> {
        let index = child_no.into();
        if index < HARDENED_INDEX_BOUNDARY {
            Ok(Self(index))
        } else {
            Err(IndexError {
                what: "child number",
                invalid: index,
                start: 0,
                end: HARDENED_INDEX_BOUNDARY,
            })
        }
    }

    #[inline]
    fn try_from_index(child_no: u32) -> Result<Self, IndexError> {
        if child_no < HARDENED_INDEX_BOUNDARY {
            return Ok(Self(child_no));
        }
        Self::try_from_child_number(child_no - HARDENED_INDEX_BOUNDARY).map_err(|_| IndexError {
            what: "index",
            invalid: child_no,
            start: HARDENED_INDEX_BOUNDARY,
            end: u32::MAX,
        })
    }

    #[inline]
    fn checked_add_assign(&mut self, add: impl Into<u32>) -> Option<Self> {
        checked_add_assign(&mut self.0, add).map(|_| *self)
    }

    #[inline]
    fn checked_sub_assign(&mut self, sub: impl Into<u32>) -> Option<Self> {
        checked_sub_assign(&mut self.0, sub).map(|_| *self)
    }
}

impl TryFrom<DerivationIndex> for HardenedIndex {
    type Error = IndexError;

    fn try_from(idx: DerivationIndex) -> Result<Self, Self::Error> {
        HardenedIndex::try_from_index(idx.index())
    }
}

impl FromStr for HardenedIndex {
    type Err = IndexParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_suffix(['h', 'H', '\''])
            .ok_or_else(|| IndexParseError::HardenedRequired(s.to_owned()))?;
        Ok(HardenedIndex::try_from_child_number(u32::from_str(s)?)?)
    }
}

#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display(inner)]
pub enum DerivationIndex {
    #[from]
    Normal(NormalIndex),
    #[from]
    Hardened(HardenedIndex),
}

impl From<u32> for DerivationIndex {
    fn from(value: u32) -> Self { Self::from_index(value) }
}

impl DerivationIndex {
    pub const fn normal(child_number: u16) -> Self {
        Self::Normal(NormalIndex::normal(child_number))
    }

    pub const fn hardened(child_number: u16) -> Self {
        Self::Hardened(HardenedIndex::hardened(child_number))
    }

    pub const fn from_index(value: u32) -> Self {
        match value {
            0..=0x0FFFFFFF => DerivationIndex::Normal(NormalIndex(value)),
            _ => DerivationIndex::Hardened(HardenedIndex(value - HARDENED_INDEX_BOUNDARY)),
        }
    }
}

impl IdxBase for DerivationIndex {
    fn child_number(&self) -> u32 {
        match self {
            DerivationIndex::Normal(idx) => idx.child_number(),
            DerivationIndex::Hardened(idx) => idx.child_number(),
        }
    }

    fn index(&self) -> u32 {
        match self {
            DerivationIndex::Normal(idx) => idx.index(),
            DerivationIndex::Hardened(idx) => idx.index(),
        }
    }

    fn is_hardened(&self) -> bool {
        match self {
            DerivationIndex::Normal(_) => false,
            DerivationIndex::Hardened(_) => true,
        }
    }
}

impl Idx for DerivationIndex {
    const ZERO: Self = DerivationIndex::Normal(NormalIndex::ZERO);
    const ONE: Self = DerivationIndex::Normal(NormalIndex::ONE);
    const MAX: Self = DerivationIndex::Normal(NormalIndex::MAX);

    #[doc(hidden)]
    fn from_child_number(_no: impl Into<u16>) -> Self { panic!("method must not be used") }

    #[doc(hidden)]
    fn try_from_child_number(_index: impl Into<u32>) -> Result<Self, IndexError> {
        panic!("method must not be used")
    }

    fn try_from_index(index: u32) -> Result<Self, IndexError> { Ok(Self::from_index(index)) }

    fn checked_add_assign(&mut self, add: impl Into<u32>) -> Option<Self> {
        match self {
            DerivationIndex::Normal(idx) => {
                idx.checked_add_assign(add).map(DerivationIndex::Normal)
            }
            DerivationIndex::Hardened(idx) => {
                idx.checked_add_assign(add).map(DerivationIndex::Hardened)
            }
        }
    }

    fn checked_sub_assign(&mut self, sub: impl Into<u32>) -> Option<Self> {
        match self {
            DerivationIndex::Normal(idx) => {
                idx.checked_sub_assign(sub).map(DerivationIndex::Normal)
            }
            DerivationIndex::Hardened(idx) => {
                idx.checked_sub_assign(sub).map(DerivationIndex::Hardened)
            }
        }
    }
}

impl FromStr for DerivationIndex {
    type Err = IndexParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.strip_suffix(['h', 'H', '*']) {
            Some(_) => HardenedIndex::from_str(s).map(Self::Hardened),
            None => NormalIndex::from_str(s).map(Self::Normal),
        }
    }
}
