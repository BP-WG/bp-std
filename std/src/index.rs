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
use std::fmt::Display;
use std::hash::Hash;
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

    /// expected hardened index value instead of the provided unhardened {0}
    HardenedRequired(String),
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

    /// Constructs index from a given child number.
    ///
    /// Child number is always a value in range of `0..`[`HARDENED_INDEX_BOUNDARY`]
    fn from_child_number(no: impl Into<u16>) -> Self;

    /// Constructs index from a given child number.
    ///
    /// Child number is always a value in range of `0..`[`HARDENED_INDEX_BOUNDARY`]
    fn try_from_child_number(index: impl Into<u32>) -> Result<Self, IndexError>;

    /// Returns child number corresponding to this index.
    ///
    /// Child number is always a value in range of `0..`[`HARDENED_INDEX_BOUNDARY`]
    fn child_number(&self) -> u32;

    /// Constructs derivation path segment with specific derivation value, which
    /// for normal indexes must lie in range `0..`[`HARDENED_INDEX_BOUNDARY`]
    /// and for hardened in range of [`HARDENED_INDEX_BOUNDARY`]`..=u32::MAX`
    fn try_from_index(value: u32) -> Result<Self, IndexError>;

    /// Returns value used during derivation, which for normal indexes must lie
    /// in range `0..`[`HARDENED_INDEX_BOUNDARY`] and for hardened in range
    /// of [`HARDENED_INDEX_BOUNDARY`]`..=u32::MAX`
    fn index(&self) -> u32;

    fn to_be_bytes(&self) -> [u8; 4] { self.index().to_be_bytes() }

    /// Increases the index on one step; fails if the index value is already
    /// maximum value - or if multiple indexes are present at the path segment
    fn checked_inc(&self) -> Option<Self> { self.checked_add(1u8) }

    /// Decreases the index on one step; fails if the index value is already
    /// minimum value - or if multiple indexes are present at the path segment
    fn checked_dec(&self) -> Option<Self> { self.checked_sub(1u8) }

    /// Increases the index on one step; fails if the index value is already
    /// maximum value - or if multiple indexes are present at the path segment
    fn wrapping_inc(&self) -> Self { self.checked_add(1u8).unwrap_or(Self::MIN) }

    /// Decreases the index on one step; fails if the index value is already
    /// minimum value - or if multiple indexes are present at the path segment
    fn wrapping_dec(&self) -> Self { self.checked_sub(1u8).unwrap_or(Self::MAX) }

    /// Mutates the self by increasing the index on one step; fails if the index
    /// value is already maximum value - or if multiple indexes are present at
    /// the path segment
    #[must_use]
    fn checked_inc_assign(&mut self) -> Option<Self> { self.checked_add_assign(1u8) }

    /// Mutates the self by decreasing the index on one step; fails if the index
    /// value is already maximum value - or if multiple indexes are present at
    /// the path segment
    #[must_use]
    fn checked_dec_assign(&mut self) -> Option<Self> { self.checked_sub_assign(1u8) }

    /// Mutates the self by increasing the index on one step; fails if the index
    /// value is already maximum value - or if multiple indexes are present at
    /// the path segment
    fn wrapping_inc_assign(&mut self) { *self = self.wrapping_inc(); }

    /// Mutates the self by decreasing the index on one step; fails if the index
    /// value is already maximum value - or if multiple indexes are present at
    /// the path segment
    fn wrapping_dec_assign(&mut self) { *self = self.wrapping_inc(); }

    /// Adds value the index; fails if the index value overflow happens - or if
    /// multiple indexes are present at the path segment
    fn checked_add(&self, add: impl Into<u32>) -> Option<Self> {
        let mut res = *self;
        res.checked_add_assign(add)?;
        Some(res)
    }

    /// Subtracts value the index; fails if the index value overflow happens -
    /// or if multiple indexes are present at the path segment
    fn checked_sub(&self, sub: impl Into<u32>) -> Option<Self> {
        let mut res = *self;
        res.checked_sub_assign(sub)?;
        Some(res)
    }

    /// Saturating index addition. Computes `self + add`, saturating at the
    /// `Self::MAX` bounds instead of overflowing.
    fn saturating_add(&self, add: impl Into<u32>) -> Self {
        let mut res = *self;
        let _ = res.saturating_add_assign(add);
        res
    }

    /// Saturating index subtraction. Computes `self - add`, saturating at
    /// the `Self::MIN` bounds instead of overflowing.
    fn saturating_sub(&self, sub: impl Into<u32>) -> Self {
        let mut res = *self;
        let _ = res.saturating_sub_assign(sub);
        res
    }

    /// Mutates the self by adding value the index; fails if the index value
    /// overflow happens.
    #[must_use]
    fn checked_add_assign(&mut self, add: impl Into<u32>) -> Option<Self>;

    /// Mutates the self by subtracting value the index; fails if the index
    /// value overflow happens.
    #[must_use]
    fn checked_sub_assign(&mut self, sub: impl Into<u32>) -> Option<Self>;

    /// Mutates the self by adding value the index saturating it at the
    /// `Self::MAX` value in case of overflow. Returns boolean value
    /// indicating if no overflow had happened.
    #[must_use]
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
    #[must_use]
    fn saturating_sub_assign(&mut self, sub: impl Into<u32>) -> bool {
        if self.checked_sub_assign(sub).is_none() {
            *self = Self::MIN;
            false
        } else {
            true
        }
    }

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

impl NormalIndex {
    pub const fn normal(child_number: u16) -> Self { NormalIndex(child_number as u32) }
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

    /// Returns unhardened index number.
    #[inline]
    fn child_number(&self) -> u32 { self.0 }

    #[inline]
    fn try_from_index(value: u32) -> Result<Self, IndexError> {
        Self::try_from_child_number(value).map_err(|mut err| {
            err.what = "index";
            err
        })
    }

    #[inline]
    fn index(&self) -> u32 { self.child_number() }

    #[inline]
    fn checked_add_assign(&mut self, add: impl Into<u32>) -> Option<Self> {
        checked_add_assign(&mut self.0, add).map(|_| *self)
    }

    #[inline]
    fn checked_sub_assign(&mut self, sub: impl Into<u32>) -> Option<Self> {
        checked_sub_assign(&mut self.0, sub).map(|_| *self)
    }

    #[inline]
    fn is_hardened(&self) -> bool { false }
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

    /// Returns hardened index number offset by [`HARDENED_INDEX_BOUNDARY`]
    /// (i.e. zero-based).
    #[inline]
    fn child_number(&self) -> u32 { self.0 }

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
    fn index(&self) -> u32 { self.0 + HARDENED_INDEX_BOUNDARY }

    #[inline]
    fn checked_add_assign(&mut self, add: impl Into<u32>) -> Option<Self> {
        checked_add_assign(&mut self.0, add).map(|_| *self)
    }

    #[inline]
    fn checked_sub_assign(&mut self, sub: impl Into<u32>) -> Option<Self> {
        checked_sub_assign(&mut self.0, sub).map(|_| *self)
    }

    #[inline]
    fn is_hardened(&self) -> bool { true }
}

impl FromStr for HardenedIndex {
    type Err = IndexParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_suffix(['h', 'H', '*'])
            .ok_or_else(|| IndexParseError::HardenedRequired(s.to_owned()))?;
        Ok(HardenedIndex::try_from_child_number(u32::from_str(s)?)?)
    }
}

#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
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

    pub fn from_index(value: u32) -> Self {
        match value {
            0..=0x0FFFFFFF => NormalIndex(value).into(),
            _ => HardenedIndex(value - HARDENED_INDEX_BOUNDARY).into(),
        }
    }

    pub fn index(&self) -> u32 {
        match self {
            DerivationIndex::Normal(normal) => normal.index(),
            DerivationIndex::Hardened(hardened) => hardened.index(),
        }
    }

    pub const fn is_hardened(&self) -> bool {
        match self {
            DerivationIndex::Normal(_) => false,
            DerivationIndex::Hardened(_) => true,
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

pub trait Keychain
where Self: Sized + Copy + Eq + Ord + Hash + Display + FromStr<Err = IndexParseError> + 'static
{
    const STANDARD_SET: &'static [Self];
    fn from_derivation(index: NormalIndex) -> Option<Self>;
    fn derivation(self) -> NormalIndex;
}

impl Keychain for NormalIndex {
    const STANDARD_SET: &'static [Self] = &[Self::ZERO, Self::ONE];

    fn from_derivation(index: NormalIndex) -> Option<Self> { Some(index) }

    fn derivation(self) -> NormalIndex { self }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[repr(u8)]
pub enum Bip32Keychain {
    #[display("0", alt = "0")]
    External = 0,

    #[display("1", alt = "1")]
    Internal = 1,
}

impl Keychain for Bip32Keychain {
    const STANDARD_SET: &'static [Self] = &[Self::External, Self::Internal];

    fn from_derivation(index: NormalIndex) -> Option<Self> {
        match index.index() {
            0 => Some(Self::External),
            1 => Some(Self::Internal),
            _ => None,
        }
    }

    fn derivation(self) -> NormalIndex { NormalIndex::from(self as u8) }
}

impl FromStr for Bip32Keychain {
    type Err = IndexParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match NormalIndex::from_str(s)? {
            NormalIndex::ZERO => Ok(Bip32Keychain::External),
            NormalIndex::ONE => Ok(Bip32Keychain::Internal),
            val => Err(IndexError {
                what: "non-standard keychain",
                invalid: val.index(),
                start: 0,
                end: 1,
            }
            .into()),
        }
    }
}
