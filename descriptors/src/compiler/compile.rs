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

use amplify::confinement::ConfinedVec;
use amplify::num::u4;
use derive::{DeriveCompr, DeriveLegacy, DeriveSet, DeriveXOnly};
use indexmap::{indexmap, IndexMap};

use crate::compiler::{DescrAst, DescrParseError, ScriptExpr};
use crate::{
    Pkh, ShMulti, ShScript, ShSortedMulti, ShWpkh, ShWsh, StdDescr, Tr, TrKey, TrMulti, TrScript,
    TrSortedMulti, Wpkh, WshMulti, WshScript, WshSortedMulti,
};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DescrExpr {
    Script,
    Lit,
    Key,
    Tree,
    VariadicKey,
}

impl DescrExpr {
    pub fn check_expr<K: Display + FromStr>(&self, expr: &DescrAst<K>) -> bool
    where K::Err: core::error::Error {
        match (self, expr) {
            (DescrExpr::Lit, DescrAst::Lit(_, _)) => true,
            (DescrExpr::Key | DescrExpr::VariadicKey, DescrAst::Key(_, _)) => true,
            (DescrExpr::Script, DescrAst::Script(_)) => true,
            (DescrExpr::Tree, DescrAst::Tree(_)) => true,
            _ => false,
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
        if ast.children.iter().zip(form).any(|(a, b)| b.check_expr(a)) {
            continue;
        }
        return Some((name, ast.children));
    }
    None
}

////////////////////////////////////////
// Key-only pre-taproot

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

////////////////////////////////////////
// Multisigs pre-taproot

fn parse_multi_form<K: Display + FromStr>(
    s: &str,
    outer: &'static str,
    medium: Option<&'static str>,
    inner: &'static str,
) -> Result<(u4, ConfinedVec<K, 1, 16>), DescrParseError<K::Err>>
where
    K::Err: core::error::Error,
{
    let ast = ScriptExpr::<K>::from_str(s)?;

    let (_, mut form) = check_forms(ast, outer, indexmap! { "" => &[DescrExpr::Script][..] })
        .ok_or(DescrParseError::InvalidArgs(outer))?;
    let Some(DescrAst::Script(mut script)) = form.pop() else {
        unreachable!();
    };

    if let Some(medium) = medium {
        let (_, mut form) =
            check_forms(*script, medium, indexmap! { "" => &[DescrExpr::Script][..] })
                .ok_or(DescrParseError::InvalidArgs(medium))?;
        let Some(DescrAst::Script(script2)) = form.pop() else {
            unreachable!();
        };
        script = script2;
    }

    let (_, mut form) = check_forms(
        *script,
        inner,
        indexmap! { "" => &[DescrExpr::Lit, DescrExpr::VariadicKey][..] },
    )
    .ok_or(DescrParseError::InvalidArgs(inner))?;
    let DescrAst::Lit(thresh, _) = form.remove(0) else {
        unreachable!();
    };
    let threshold = u4::from_str(thresh)?;
    let keys = ConfinedVec::try_from_iter(form.into_iter().map(|el| {
        let DescrAst::Key(key, _) = el else {
            unreachable!()
        };
        key
    }))?;
    Ok((threshold, keys))
}

impl<K: DeriveLegacy + FromStr> FromStr for ShMulti<K>
where K::Err: core::error::Error
{
    type Err = DescrParseError<K::Err>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (threshold, keys) = parse_multi_form(s, "sh", None, "multi")?;
        Ok(ShMulti { threshold, keys })
    }
}

impl<K: DeriveLegacy + FromStr> FromStr for ShSortedMulti<K>
where K::Err: core::error::Error
{
    type Err = DescrParseError<K::Err>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (threshold, keys) = parse_multi_form(s, "sh", None, "sortedmulti")?;
        Ok(ShSortedMulti { threshold, keys })
    }
}

impl<K: DeriveCompr + FromStr> FromStr for WshMulti<K>
where K::Err: core::error::Error
{
    type Err = DescrParseError<K::Err>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (threshold, keys) = parse_multi_form(s, "wsh", None, "multi")?;
        Ok(WshMulti { threshold, keys })
    }
}

impl<K: DeriveCompr + FromStr> FromStr for WshSortedMulti<K>
where K::Err: core::error::Error
{
    type Err = DescrParseError<K::Err>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (threshold, keys) = parse_multi_form(s, "wsh", None, "sortedmulti")?;
        Ok(WshSortedMulti { threshold, keys })
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

////////////////////////////////////////
// Scripts pre-taproot

// TODO: Implement with support for script templates and miniscript

impl<K: DeriveLegacy + FromStr> FromStr for ShScript<K>
where K::Err: core::error::Error
{
    type Err = DescrParseError<K::Err>;

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        Err(DescrParseError::NotSupported("scripts"))
    }
}

impl<K: DeriveCompr + FromStr> FromStr for WshScript<K>
where K::Err: core::error::Error
{
    type Err = DescrParseError<K::Err>;

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        Err(DescrParseError::NotSupported("scripts"))
    }
}

////////////////////////////////////////
// Taproot

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

fn parse_tr_form<K: Display + FromStr>(
    s: &str,
    inner: &'static str,
) -> Result<(K, u16, ConfinedVec<K, 1, 999>), DescrParseError<K::Err>>
where
    K::Err: core::error::Error,
{
    let ast = ScriptExpr::<K>::from_str(s)?;

    let (_, mut form) =
        check_forms(ast, "tr", indexmap! { "" => &[DescrExpr::Key, DescrExpr::Script][..] })
            .ok_or(DescrParseError::InvalidArgs("tr"))?;
    let Some(DescrAst::Key(internal_key, _)) = form.pop() else {
        unreachable!();
    };
    let Some(DescrAst::Script(script)) = form.pop() else {
        unreachable!();
    };

    let (_, mut form) = check_forms(
        *script,
        inner,
        indexmap! { "" => &[DescrExpr::Lit, DescrExpr::VariadicKey][..] },
    )
    .ok_or(DescrParseError::InvalidArgs(inner))?;
    let DescrAst::Lit(thresh, _) = form.remove(0) else {
        unreachable!();
    };
    let threshold = u16::from_str(thresh)?;
    let script_keys = ConfinedVec::try_from_iter(form.into_iter().map(|el| {
        let DescrAst::Key(key, _) = el else {
            unreachable!()
        };
        key
    }))?;
    Ok((internal_key, threshold, script_keys))
}

impl<K: DeriveXOnly + FromStr> FromStr for TrMulti<K>
where K::Err: core::error::Error
{
    type Err = DescrParseError<K::Err>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (internal_key, threshold, script_keys) = parse_tr_form(s, "multi_a")?;
        Ok(TrMulti {
            internal_key,
            threshold,
            script_keys,
        })
    }
}

impl<K: DeriveXOnly + FromStr> FromStr for TrSortedMulti<K>
where K::Err: core::error::Error
{
    type Err = DescrParseError<K::Err>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (internal_key, threshold, script_keys) = parse_tr_form(s, "sortedmulti_a")?;
        Ok(TrSortedMulti {
            internal_key,
            threshold,
            script_keys,
        })
    }
}

impl<K: DeriveXOnly + FromStr> FromStr for TrScript<K>
where K::Err: core::error::Error
{
    type Err = DescrParseError<K::Err>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ast = ScriptExpr::<K>::from_str(s)?;

        let (_, mut form) =
            check_forms(ast, "tr", indexmap! { "" => &[DescrExpr::Key, DescrExpr::Tree][..] })
                .ok_or(DescrParseError::InvalidArgs("tr"))?;
        let Some(DescrAst::Key(_internal_key, _)) = form.pop() else {
            unreachable!();
        };
        let Some(DescrAst::Tree(_tree)) = form.pop() else {
            unreachable!();
        };

        // TODO: Process taproot tree

        Err(DescrParseError::NotSupported("scripts"))
    }
}

////////////////////////////////////////
// Combinators

impl<K: DeriveCompr + FromStr> FromStr for ShWsh<K>
where K::Err: core::error::Error
{
    type Err = DescrParseError<K::Err>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("sh(wsh(multi(") {
            let (threshold, keys) = parse_multi_form(s, "sh", Some("wsh"), "multi")?;
            Ok(ShWsh::Multi(WshMulti { threshold, keys }))
        } else if s.starts_with("sh(wsh(sortedmulti(") {
            let (threshold, keys) = parse_multi_form(s, "sh", Some("wsh"), "sortedmulti")?;
            Ok(ShWsh::SortedMulti(WshSortedMulti { threshold, keys }))
        } else if s.starts_with("sh(wsh(") {
            Err(DescrParseError::NotSupported("scripts"))
        } else {
            Err(DescrParseError::InvalidScriptExpr(s.to_owned()))
        }
    }
}

impl<K: DeriveXOnly + FromStr> FromStr for Tr<K>
where K::Err: core::error::Error
{
    type Err = DescrParseError<K::Err>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(tr_key) = TrKey::from_str(s) {
            Ok(Self::KeyOnly(tr_key))
        } else if let Ok(tr_multi) = TrMulti::from_str(s) {
            Ok(Self::Multi(tr_multi))
        } else if let Ok(tr_sorted_multi) = TrSortedMulti::from_str(s) {
            Ok(Self::SortedMulti(tr_sorted_multi))
        } else {
            TrScript::from_str(s).map(Self::Script)
        }
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
