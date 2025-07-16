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

use core::fmt::Display;
use core::str::FromStr;

use derive::{DeriveCompr, DeriveLegacy, DeriveSet, DeriveXOnly};
use indexmap::{indexmap, IndexMap};

use crate::compiler::{DescrAst, DescrParseError, ScriptExpr};
use crate::{Pkh, ShWpkh, StdDescr, Tr, TrKey, Wpkh};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DescrExpr {
    Script,
    Key,
    Tree,
}

impl<K: Display + FromStr> DescrAst<'_, K>
where K::Err: core::error::Error
{
    pub fn expr(&self) -> DescrExpr {
        match self {
            DescrAst::Key(_, _) => DescrExpr::Key,
            DescrAst::Script(_) => DescrExpr::Script,
            DescrAst::Tree(_) => DescrExpr::Tree,
        }
    }
}

pub fn check_forms<'s, 'f, K: Display + FromStr>(
    ast: ScriptExpr<'s, K>,
    ident: &str,
    forms: IndexMap<&'static str, &'f [DescrExpr]>,
) -> Option<(&'static str, Vec<DescrAst<'s, K>>)>
where
    K::Err: core::error::Error,
{
    for (name, form) in forms {
        if ast.name != ident {
            continue;
        }
        if ast.children.len() != form.len() {
            continue;
        }
        if ast.children.iter().zip(form).any(|(a, b)| &a.expr() != b) {
            continue;
        }
        return Some((name, ast.children));
    }
    None
}

impl<K: DeriveLegacy + FromStr> FromStr for Pkh<K>
where K::Err: core::error::Error
{
    type Err = DescrParseError<K::Err>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ast = ScriptExpr::<K>::from_str(s)?;
        let (_, mut form) = check_forms(ast, "pkh", indexmap! { "" => &[DescrExpr::Key][..] })
            .ok_or(DescrParseError::InvalidArgs("pkh"))?;
        let Some(DescrAst::Key(key, _)) = form.pop() else {
            unreachable!();
        };
        Ok(Pkh::from(key))
    }
}

impl<K: DeriveCompr + FromStr> FromStr for Wpkh<K>
where K::Err: core::error::Error
{
    type Err = DescrParseError<K::Err>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ast = ScriptExpr::<K>::from_str(s)?;
        let (_, mut form) = check_forms(ast, "wpkh", indexmap! { "" => &[DescrExpr::Key][..] })
            .ok_or(DescrParseError::InvalidArgs("wpkh"))?;
        let Some(DescrAst::Key(key, _)) = form.pop() else {
            unreachable!();
        };
        Ok(Wpkh::from(key))
    }
}

impl<K: DeriveCompr + FromStr> FromStr for ShWpkh<K>
where K::Err: core::error::Error
{
    type Err = DescrParseError<K::Err>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ast = ScriptExpr::<K>::from_str(s)?;
        let (_, mut form) = check_forms(ast, "sh", indexmap! { "" => &[DescrExpr::Script][..] })
            .ok_or(DescrParseError::InvalidArgs("sh"))?;
        let Some(DescrAst::Script(inner)) = form.pop() else {
            unreachable!();
        };

        let (_, mut form) = check_forms(*inner, "wpkh", indexmap! { "" => &[DescrExpr::Key][..] })
            .ok_or(DescrParseError::InvalidArgs("wpkh"))?;
        let Some(DescrAst::Key(key, _)) = form.pop() else {
            unreachable!();
        };
        Ok(ShWpkh::from(key))
    }
}

impl<K: DeriveXOnly + FromStr> FromStr for TrKey<K>
where K::Err: core::error::Error
{
    type Err = DescrParseError<K::Err>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ast = ScriptExpr::<K>::from_str(s)?;
        let (_, mut form) = check_forms(ast, "tr", indexmap! { "" => &[DescrExpr::Key][..] })
            .ok_or(DescrParseError::InvalidArgs("tr"))?;
        let Some(DescrAst::Key(key, _)) = form.pop() else {
            unreachable!();
        };
        Ok(TrKey::from(key))
    }
}

impl<K: DeriveSet + Display + FromStr> FromStr for StdDescr<K>
where
    K::Err: core::error::Error,
    K::Legacy: Display + FromStr<Err = K::Err>,
    K::Compr: Display + FromStr<Err = K::Err>,
    K::XOnly: Display + FromStr<Err = K::Err>,
{
    type Err = DescrParseError<K::Err>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let prefix =
            s.split_once("(").ok_or_else(|| DescrParseError::InvalidScriptExpr(s.to_owned()))?.0;
        Ok(match prefix {
            "pkh" => Self::Pkh(Pkh::from_str(s)?),
            "wpkh" => Self::Wpkh(Wpkh::from_str(s)?),
            _ => return Err(DescrParseError::InvalidScriptExpr(s.to_owned())),
        })
    }
}
