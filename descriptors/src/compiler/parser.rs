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

use core::str::FromStr;
use std::fmt::Display;
use std::num::ParseIntError;

use amplify::confinement;
use derive::XpubDerivable;

use super::{parse_descr_str, DescrToken};

impl<'s, K: Display + FromStr> ScriptExpr<'s, K>
where K::Err: core::error::Error
{
    pub(super) fn from_str(s: &'s str) -> Result<Self, DescrParseError<K::Err>> {
        let tokens = parse_descr_str(s);
        Self::parse_tokens(s, &tokens)
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum DescrParseError<E: core::error::Error> {
    /// empty descriptor expression.
    Empty,

    /// script expression '{0}' must have a name.
    NoName(String),

    /// unexpected token '{token}' when {expected} is expected.
    UnexpectedToken {
        descr: String,
        pos: usize,
        token: String,
        expected: &'static str,
    },

    /// no matching bracket for '{bracket}' in position {pos} inside the descriptor '{descr}'.
    MismatchedBrackets {
        descr: String,
        pos: usize,
        bracket: String,
    },

    /// invalid descriptor script expression '{0}'.
    InvalidScriptExpr(String),

    /// invalid descriptor tree expression '{0}'.
    InvalidTreeExpr(String),

    /// invalid key expression: {0}.
    Key(E),

    /// invalid number literal: {0}.
    #[from]
    Lit(ParseIntError),

    /// too many keys.
    #[from]
    Confinement(confinement::Error),

    /// invalid arguments are given for the descriptor script expression {0}.
    InvalidArgs(&'static str),

    /// parsing {0} is not yet supported.
    NotSupported(&'static str),
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display(inner)]
pub enum DescrAst<'s, K: Display + FromStr = XpubDerivable>
where K::Err: core::error::Error
{
    /// Key expression
    #[display("{0}")]
    Key(K, usize),

    /// Literal expression (like number or a keyword `unspendable`)
    Lit(&'s str, usize),

    /// Statement, like miniscript or descriptor overall
    Script(Box<ScriptExpr<'s, K>>),

    /// Expression, like taproot script tree
    Tree(Box<TreeExpr<'s, K>>),
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display("{full}")]
pub struct ScriptExpr<'s, K: Display + FromStr = XpubDerivable>
where K::Err: core::error::Error
{
    pub name: &'s str,
    pub children: Vec<DescrAst<'s, K>>,
    pub full: &'s str,
    pub offset: usize,
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display("{full}")]
pub struct TreeExpr<'s, K: Display + FromStr = XpubDerivable>
where K::Err: core::error::Error
{
    pub first: DescrAst<'s, K>,
    pub second: DescrAst<'s, K>,
    pub full: &'s str,
}

impl<'s, K: Display + FromStr> DescrAst<'s, K>
where K::Err: core::error::Error
{
    fn parse_from_token_stream(
        descr: &'s str,
        tokens: &mut &[DescrToken<'s>],
    ) -> Result<Self, DescrParseError<K::Err>> {
        let Some(first) = tokens.first() else {
            return Err(DescrParseError::Empty);
        };

        Ok(match first {
            DescrToken::Ident(_, _)
                if matches!(tokens.get(1), Some(DescrToken::OpeningParenthesis(_))) =>
            {
                let matched_bracket = matching_bracket_close::<K>(descr, &tokens[1..])?;
                let (subtokens, remaining) = tokens.split_at(matched_bracket + 2);
                *tokens = remaining;
                Self::Script(Box::new(ScriptExpr::parse_tokens(descr, subtokens)?))
            }
            DescrToken::OpeningBraces(_) => {
                let matched_bracket = matching_bracket_close::<K>(descr, tokens)?;
                let (subtokens, remaining) = tokens.split_at(matched_bracket + 1);
                *tokens = remaining;
                Self::Tree(Box::new(TreeExpr::parse_tokens(descr, subtokens)?))
            }
            DescrToken::Ident(s, pos) | DescrToken::Lit(s, pos) => {
                tokens.split_off_first();
                if let Ok(key) = K::from_str(s) {
                    Self::Key(key, *pos)
                } else {
                    Self::Lit(s, *pos)
                }
            }
            _ => {
                return Err(DescrParseError::UnexpectedToken {
                    descr: descr.to_string(),
                    pos: first.pos(),
                    token: first.to_string(),
                    expected: "key, script or tree expression",
                })
            }
        })
    }
}

impl<'s, K: Display + FromStr> ScriptExpr<'s, K>
where K::Err: core::error::Error
{
    /// Parses a part of the token stream as a script expression.
    ///
    /// # Arguments
    ///
    /// - `descr` is the complete original descriptor string.
    /// - `tokens` must contain part of the lexer output specific to the expression
    fn parse_tokens(
        descr: &'s str,
        mut tokens: &[DescrToken<'s>],
    ) -> Result<Self, DescrParseError<K::Err>> {
        let full = descr_substr(descr, tokens);

        let Some(DescrToken::Ident(name, offset)) = tokens.split_off_first() else {
            return Err(DescrParseError::NoName(descr.to_string()));
        };
        if !matches!(tokens.split_off_first(), Some(DescrToken::OpeningParenthesis(_)))
            || !matches!(tokens.split_off_last(), Some(DescrToken::ClosingParenthesis(_)))
        {
            return Err(DescrParseError::InvalidScriptExpr(full.to_string()));
        }
        if tokens.is_empty() {
            return Ok(Self {
                name,
                children: vec![],
                full,
                offset: *offset,
            });
        }

        let mut children = vec![];

        loop {
            let node = DescrAst::parse_from_token_stream(descr, &mut tokens)?;
            children.push(node);
            // All children must be separated by comma
            let Some(token) = tokens.split_off_first() else {
                break;
            };
            match token {
                DescrToken::Comma(_) => continue,
                _ => {
                    return Err(DescrParseError::UnexpectedToken {
                        descr: descr.to_string(),
                        pos: token.pos(),
                        token: token.to_string(),
                        expected: "comma",
                    })
                }
            }
        }

        Ok(Self {
            name,
            children,
            full,
            offset: *offset,
        })
    }
}

impl<'s, K: Display + FromStr> TreeExpr<'s, K>
where K::Err: core::error::Error
{
    /// Parses a part of the token stream as a tree expression.
    ///
    /// # Arguments
    ///
    /// - `descr` is the complete original descriptor string.
    /// - `tokens` must contain part of the lexer output specific to the expression
    fn parse_tokens(
        descr: &'s str,
        mut tokens: &[DescrToken<'s>],
    ) -> Result<Self, DescrParseError<K::Err>> {
        let full = descr_substr(descr, tokens);

        if !matches!(tokens.split_off_first(), Some(DescrToken::OpeningBraces(_)))
            || !matches!(tokens.split_off_last(), Some(DescrToken::ClosingBraces(_)))
        {
            return Err(DescrParseError::InvalidTreeExpr(full.to_string()));
        }

        let first = DescrAst::parse_from_token_stream(descr, &mut tokens)?;
        match tokens.split_off_first() {
            Some(DescrToken::Comma(_)) => {}
            Some(token) => {
                return Err(DescrParseError::UnexpectedToken {
                    descr: descr.to_string(),
                    pos: token.pos(),
                    token: token.to_string(),
                    expected: "comma",
                })
            }
            None => return Err(DescrParseError::InvalidTreeExpr(full.to_string())),
        }
        let second = DescrAst::parse_from_token_stream(descr, &mut tokens)?;

        Ok(Self {
            first,
            second,
            full,
        })
    }
}

fn descr_substr<'s>(descr: &'s str, tokens: &[DescrToken]) -> &'s str {
    &descr[tokens.first().map(DescrToken::pos).unwrap_or_default()
        ..=tokens.last().map(DescrToken::pos).unwrap_or(descr.len() - 1)]
}

fn matching_bracket_close<K: Display + FromStr>(
    descr: &str,
    tokens: &[DescrToken],
) -> Result<usize, DescrParseError<K::Err>>
where
    K::Err: core::error::Error,
{
    let mut stack: Vec<DescrToken> = vec![];
    for (pos, token) in tokens.iter().enumerate() {
        let mut check = |paren: bool| {
            if let Some(open_token) = stack.pop() {
                if (!matches!(open_token, DescrToken::OpeningParenthesis(_)) && paren)
                    || (!matches!(open_token, DescrToken::OpeningBraces(_)) && !paren)
                {
                    return Err(DescrParseError::MismatchedBrackets {
                        descr: descr.to_string(),
                        pos: open_token.pos(),
                        bracket: open_token.to_string(),
                    });
                }
                if stack.is_empty() {
                    return Ok(Some(pos));
                }
            } else {
                return Err(DescrParseError::MismatchedBrackets {
                    descr: descr.to_string(),
                    pos: token.pos(),
                    bracket: token.to_string(),
                });
            }
            Ok(None)
        };
        match token {
            DescrToken::OpeningParenthesis(_) | DescrToken::OpeningBraces(_) => {
                stack.push(*token);
            }
            DescrToken::ClosingParenthesis(_) => {
                if let Some(pos) = check(true)? {
                    return Ok(pos);
                }
            }
            DescrToken::ClosingBraces(_) => {
                if let Some(pos) = check(false)? {
                    return Ok(pos);
                }
            }
            _ => {}
        }
    }
    if let Some(opening) = stack.pop() {
        Err(DescrParseError::MismatchedBrackets {
            descr: descr.to_string(),
            pos: opening.pos(),
            bracket: opening.to_string(),
        })
    } else {
        Ok(tokens.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_script_expr() {
        let ast = ScriptExpr::<String>::from_str("a(b,c)").unwrap();
        assert_eq!(ast.name, "a");
        assert_eq!(ast.children.len(), 2);
        assert_eq!(ast.children[0], DescrAst::Key(s!("b"), 2));
        assert_eq!(ast.children[1], DescrAst::Key(s!("c"), 4));
        assert_eq!(ast.full, "a(b,c)");
        assert_eq!(ast.offset, 0);
    }

    #[test]
    fn nested_script_expr() {
        let ast = ScriptExpr::<String>::from_str("a(b,c(d))").unwrap();
        assert_eq!(ast.name, "a");
        assert_eq!(ast.children.len(), 2);
        assert_eq!(ast.children[0], DescrAst::Key(s!("b"), 2));
        assert_eq!(
            ast.children[1],
            DescrAst::Script(Box::new(ScriptExpr {
                name: "c",
                children: vec![DescrAst::Key(s!("d"), 6)],
                full: "c(d)",
                offset: 4,
            }))
        );
        assert_eq!(ast.full, "a(b,c(d))");
        assert_eq!(ast.offset, 0);
    }

    #[test]
    fn simple_tree_expr() {
        let ast = ScriptExpr::<String>::from_str("tree({a, b})").unwrap();
        assert_eq!(ast.name, "tree");
        assert_eq!(ast.children.len(), 1);
        assert_eq!(
            ast.children[0],
            DescrAst::Tree(Box::new(TreeExpr {
                first: DescrAst::Key(s!("a"), 6),
                second: DescrAst::Key(s!("b"), 9),
                full: "{a, b}",
            }))
        );
        assert_eq!(ast.full, "tree({a, b})");
        assert_eq!(ast.offset, 0);
        assert_eq!(ast.to_string(), "tree({a, b})");
    }

    #[test]
    #[should_panic(expected = "Empty")]
    fn empty_braces() { ScriptExpr::<String>::from_str("tree({})").unwrap(); }
}
