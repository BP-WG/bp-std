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

pub const SEQ_NO_MAX_VALUE: u32 = 0xFFFFFFFF;
pub const SEQ_NO_SUBMAX_VALUE: u32 = 0xFFFFFFFE;

pub trait SeqNoExt {
    /// Classifies type of `nSeq` value (see [`SeqNoClass`]).
    #[inline]
    fn classify(self) -> SeqNoClass;

    /// Checks if `nSeq` value opts-in for replace-by-fee (also always true for
    /// relative time locks).
    #[inline]
    fn is_rbf(self) -> bool;
}

impl SeqNoExt for SeqNo {
    #[inline]
    fn classify(self) -> SeqNoClass {
        match self.0 {
            SEQ_NO_MAX_VALUE | SEQ_NO_SUBMAX_VALUE => SeqNoClass::Unencumbered,
            no if no & SEQ_NO_CSV_DISABLE_MASK != 0 => SeqNoClass::RbfOnly,
            no if no & SEQ_NO_CSV_TYPE_MASK != 0 => SeqNoClass::RelativeTime,
            _ => SeqNoClass::RelativeHeight,
        }
    }

    #[inline]
    fn is_rbf(self) -> bool { self.0 < SEQ_NO_SUBMAX_VALUE }
}

/// Classes for `nSeq` values
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum SeqNoClass {
    /// No RBF (opt-out) and timelocks.
    ///
    /// Corresponds to `0xFFFFFFFF` and `0xFFFFFFFE` values
    Unencumbered,

    /// RBF opt-in, but no timelock applied.
    ///
    /// Values from `0x80000000` to `0xFFFFFFFD` inclusively
    RbfOnly,

    /// Both RBF and relative height-based lock is applied.
    RelativeTime,

    /// Both RBF and relative time-based lock is applied.
    RelativeHeight,
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct Rbf(SeqNo);

impl Rbf {
    /// Creates `nSeq` value which is not encumbered by either RBF not relative
    /// time locks.
    ///
    /// # Arguments
    /// - `max` defines whether `nSeq` should be set to the `0xFFFFFFFF` (`true`) or `0xFFFFFFFe`.
    #[inline]
    pub fn unencumbered(max: bool) -> SeqNo {
        SeqNo(if max { SEQ_NO_MAX_VALUE } else { SEQ_NO_SUBMAX_VALUE })
    }

    /// Creates `nSeq` in replace-by-fee mode with the specified order number.
    #[inline]
    pub fn from_rbf(order: u16) -> SeqNo { SeqNo(order as u32 | SEQ_NO_CSV_DISABLE_MASK) }

    /// Creates `nSeq` in replace-by-fee mode with value 0xFFFFFFFD.
    ///
    /// This value is the value supported by the BitBox software.
    #[inline]
    pub fn rbf() -> SeqNo { SeqNo(SEQ_NO_SUBMAX_VALUE - 1) }
}

#[derive(Debug, Clone, PartialEq, Eq, From, Display)]
#[display(doc_comments)]
pub enum ParseError {
    /// invalid number in time lock descriptor
    #[from]
    InvalidNumber(ParseIntError),

    /// block height `{0}` is too large for time lock
    InvalidHeight(u32),

    /// timestamp `{0}` is too small for time lock
    InvalidTimestamp(u32),

    /// time lock descriptor `{0}` is not recognized
    InvalidDescriptor(String),

    /// use of randomly-generated RBF sequence numbers requires compilation
    /// with `rand` feature
    NoRand,
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseError::InvalidNumber(err) => Some(err),
            _ => None,
        }
    }
}

impl Display for Rbf {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.classify() {
            SeqNoClass::Unencumbered if self.0 == SEQ_NO_MAX_VALUE => {
                f.write_str("final(0xFFFFFFFF)")
            }
            SeqNoClass::Unencumbered if self.0 == SEQ_NO_SUBMAX_VALUE => {
                f.write_str("non-rbf(0xFFFFFFFE)")
            }
            SeqNoClass::Unencumbered => unreachable!(),
            SeqNoClass::RbfOnly => {
                f.write_str("rbf(")?;
                Display::fmt(&(self.0 ^ SEQ_NO_CSV_DISABLE_MASK), f)?;
                f.write_str(")")
            }
            _ if self.0 >> 16 & 0xFFBF > 0 => Display::fmt(&self.0, f),
            SeqNoClass::RelativeTime => {
                let value = self.0 & 0xFFFF;
                f.write_str("time(")?;
                Display::fmt(&value, f)?;
                f.write_str(")")
            }
            SeqNoClass::RelativeHeight => {
                let value = self.0 & 0xFFFF;
                f.write_str("height(")?;
                Display::fmt(&value, f)?;
                f.write_str(")")
            }
        }
    }
}

impl FromStr for Rbf {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_lowercase();
        if s == "rbf" {
            #[cfg(feature = "rand")]
            {
                Ok(SeqNo::rbf())
            }
            #[cfg(not(feature = "rand"))]
            {
                Err(ParseError::NoRand)
            }
        } else if s.starts_with("rbf(") && s.ends_with(')') {
            let no = s[4..].trim_end_matches(')').parse()?;
            Ok(SeqNo::from_rbf(no))
        } else if s.starts_with("time(") && s.ends_with(')') {
            let no = s[5..].trim_end_matches(')').parse()?;
            Ok(SeqNo::from_intervals(no))
        } else if s.starts_with("height(") && s.ends_with(')') {
            let no = s[7..].trim_end_matches(')').parse()?;
            Ok(SeqNo::from_height(no))
        } else {
            let no = s.parse()?;
            Ok(SeqNo(no))
        }
    }
}
