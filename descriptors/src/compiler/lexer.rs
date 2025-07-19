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

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Error, From)]
#[display(inner)]
pub enum DescrLexerError {
    /// unexpected character '{1}' at position {2} in the descriptor name
    InvalidDescrChar(String, char, usize),
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Display)]
pub enum DescrToken<'s> {
    #[display(inner)]
    Ident(&'s str, usize),

    #[display(inner)]
    Lit(&'s str, usize),

    #[display("(")]
    OpeningParenthesis(usize),

    #[display(")")]
    ClosingParenthesis(usize),

    #[display("{{")]
    OpeningBraces(usize),

    #[display("}}")]
    ClosingBraces(usize),

    #[display(",")]
    Comma(usize),
}

impl<'s> DescrToken<'s> {
    pub fn pos(&self) -> usize {
        match self {
            DescrToken::Ident(_, pos) => *pos,
            DescrToken::Lit(_, pos) => *pos,
            DescrToken::OpeningParenthesis(pos) => *pos,
            DescrToken::ClosingParenthesis(pos) => *pos,
            DescrToken::OpeningBraces(pos) => *pos,
            DescrToken::ClosingBraces(pos) => *pos,
            DescrToken::Comma(pos) => *pos,
        }
    }
}

pub fn parse_descr_str(s: &str) -> Result<Vec<DescrToken<'_>>, DescrLexerError> {
    let mut tokens = vec![];

    #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
    enum TokenTy {
        Ident,
        Expr,
    }

    let mut state: Option<TokenTy> = None;
    let mut start = 0;
    for (idx, ch) in s.chars().chain([' ']).enumerate() {
        let next_token = match ch {
            '(' => Some(DescrToken::OpeningParenthesis(idx)),
            ')' => Some(DescrToken::ClosingParenthesis(idx)),
            '{' => Some(DescrToken::OpeningBraces(idx)),
            '}' => Some(DescrToken::ClosingBraces(idx)),
            ',' => Some(DescrToken::Comma(idx)),
            ' ' | '\t' | '\n' | '\r' => None,
            'A'..='Z' | 'a'..='z' | '_' => {
                state = state.or(Some(TokenTy::Ident));
                continue;
            }
            // Allowed chars
            // 0123456789()[],'/*abcdefgh@:$%{}
            // IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~
            // ijklmnopqrstuvwxyzABCDEFGH`#"\<space>
            '0'..='9'
            | '['
            | ']'
            | '\''
            | '/'
            | '*'
            | '@'
            | ':'
            | '$'
            | '%'
            | '&'
            | '+'
            | '-'
            | '.'
            | ';'
            | '<'
            | '='
            | '>'
            | '?'
            | '!'
            | '^'
            | '|'
            | '~'
            | '`'
            | '#'
            | '"'
            | '\\' => {
                state = state.map(|prev| prev.max(TokenTy::Expr)).or(Some(TokenTy::Expr));
                continue;
            }
            _ => {
                return Err(DescrLexerError::InvalidDescrChar(s.to_string(), ch, idx));
            }
        };
        let prev_token = match state {
            None => None,
            Some(TokenTy::Ident) => Some(DescrToken::Ident(&s[start..idx], start)),
            Some(TokenTy::Expr) => Some(DescrToken::Lit(&s[start..idx], start)),
        };
        start = idx + 1;
        state = None;
        if let Some(token) = prev_token {
            tokens.push(token);
        }
        if let Some(token) = next_token {
            tokens.push(token);
        }
    }

    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use DescrToken::*;

    use super::*;

    fn test(sample: &str, expect: Vec<DescrToken<'_>>) {
        let parsed = parse_descr_str(sample).unwrap();
        assert_eq!(parsed, expect);
        let s = parsed.iter().map(DescrToken::to_string).collect::<String>();
        assert_eq!(sample.replace(' ', ""), s);
    }

    #[test]
    fn empty() { test("", vec![]); }

    #[test]
    fn ident() { test("ident", vec![Ident("ident", 0)]); }

    #[test]
    fn whitespace() {
        test(" ident", vec![Ident("ident", 1)]);
        test("ident ", vec![Ident("ident", 0)]);
        test("ident ()", vec![Ident("ident", 0), OpeningParenthesis(6), ClosingParenthesis(7)]);
        test("ident () ", vec![Ident("ident", 0), OpeningParenthesis(6), ClosingParenthesis(7)]);
        test("ident ( )", vec![Ident("ident", 0), OpeningParenthesis(6), ClosingParenthesis(8)]);
        test("ident( )", vec![Ident("ident", 0), OpeningParenthesis(5), ClosingParenthesis(7)]);
        test("ident ( ) ", vec![Ident("ident", 0), OpeningParenthesis(6), ClosingParenthesis(8)]);
    }

    #[test]
    fn wsh_sortedmulti() {
        let sample = "wsh(sortedmulti(1,\
        [34cf0925/87h/1h/1h]xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa/<0;1>/*,\
        [deadcafe/87h/1h/1h]xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m/<0;1>/*,\
        [beeffeed/87h/1h/1h]xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt/<0;1>/*))";
        let expect = vec![
            Ident("wsh", 0),
            OpeningParenthesis(3),
            Ident("sortedmulti", 4),
            OpeningParenthesis(15),
            Lit("1", 16),
            Comma(17),
            Lit("[34cf0925/87h/1h/1h]xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa/<0;1>/*", 18),
            Comma(157),
            Lit("[deadcafe/87h/1h/1h]xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m/<0;1>/*", 158),
            Comma(297),
            Lit("[beeffeed/87h/1h/1h]xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt/<0;1>/*", 298),
            ClosingParenthesis(437),
            ClosingParenthesis(438),
        ];
        test(sample, expect)
    }
}
