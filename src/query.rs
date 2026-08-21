//! OQL, the Oracle Query Language. A small hand-written lexer and recursive
//! descent parser. No parser-combinator dependency: this is our language.
//!
//! Grammar (v1):
//!   query     := paths | escalate | blast
//!   paths     := "PATHS" "FROM" node_ref "TO" target
//!   escalate  := "ESCALATE" "FROM" node_ref
//!   blast     := "BLAST" node_ref
//!   node_ref  := WORD "(" STRING ")"          e.g. user("alice")
//!   target    := node_ref | action_ref
//!   action_ref:= "action" "(" STRING ")"       e.g. action("*")

use anyhow::{bail, Result};

#[derive(Debug, Clone, PartialEq)]
pub enum Target {
    Node { kind: String, id: String },
    Action(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Query {
    Paths {
        from_kind: String,
        from_id: String,
        to: Target,
    },
    Escalate {
        from_kind: String,
        from_id: String,
    },
    Blast {
        from_kind: String,
        from_id: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Str(String),
    LParen,
    RParen,
}

fn lex(src: &str) -> Result<Vec<Tok>> {
    let is_word = |c: char| c.is_alphanumeric() || matches!(c, '_' | '-' | ':' | '*' | '.' | '/');
    let mut toks = Vec::new();
    let mut chars = src.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            c if c.is_whitespace() => {
                chars.next();
            }
            '(' => {
                chars.next();
                toks.push(Tok::LParen);
            }
            ')' => {
                chars.next();
                toks.push(Tok::RParen);
            }
            '"' | '\'' => {
                let quote = c;
                chars.next();
                let mut s = String::new();
                let mut closed = false;
                for ch in chars.by_ref() {
                    if ch == quote {
                        closed = true;
                        break;
                    }
                    s.push(ch);
                }
                if !closed {
                    bail!("unterminated string literal");
                }
                toks.push(Tok::Str(s));
            }
            c if is_word(c) => {
                let mut w = String::new();
                while let Some(&ch) = chars.peek() {
                    if is_word(ch) {
                        w.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                toks.push(Tok::Word(w));
            }
            _ => bail!("unexpected character '{c}'"),
        }
    }
    Ok(toks)
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn expect(&mut self, t: Tok) -> Result<()> {
        match self.next() {
            Some(ref g) if *g == t => Ok(()),
            other => bail!("expected {t:?}, found {other:?}"),
        }
    }

    fn expect_word(&mut self, kw: &str) -> Result<()> {
        match self.next() {
            Some(Tok::Word(w)) if w.eq_ignore_ascii_case(kw) => Ok(()),
            other => bail!("expected `{kw}`, found {other:?}"),
        }
    }

    fn word(&mut self) -> Result<String> {
        match self.next() {
            Some(Tok::Word(w)) => Ok(w),
            other => bail!("expected a keyword or identifier, found {other:?}"),
        }
    }

    fn string(&mut self) -> Result<String> {
        match self.next() {
            Some(Tok::Str(s)) => Ok(s),
            other => bail!("expected a quoted string, found {other:?}"),
        }
    }

    /// node_ref := WORD "(" STRING ")"
    fn node_ref(&mut self) -> Result<(String, String)> {
        let kind = self.word()?;
        self.expect(Tok::LParen)?;
        let id = self.string()?;
        self.expect(Tok::RParen)?;
        Ok((kind, id))
    }
}

pub fn parse(src: &str) -> Result<Query> {
    let toks = lex(src)?;
    let mut p = Parser { toks, pos: 0 };
    let head = p.word()?;
    let query = match head.to_ascii_uppercase().as_str() {
        "PATHS" => {
            p.expect_word("FROM")?;
            let (from_kind, from_id) = p.node_ref()?;
            p.expect_word("TO")?;
            let (tk, ti) = p.node_ref()?;
            let to = if tk.eq_ignore_ascii_case("action") {
                Target::Action(ti)
            } else {
                Target::Node { kind: tk, id: ti }
            };
            Query::Paths {
                from_kind,
                from_id,
                to,
            }
        }
        "ESCALATE" => {
            p.expect_word("FROM")?;
            let (from_kind, from_id) = p.node_ref()?;
            Query::Escalate { from_kind, from_id }
        }
        "BLAST" => {
            let (from_kind, from_id) = p.node_ref()?;
            Query::Blast { from_kind, from_id }
        }
        other => bail!("unknown query `{other}` (expected PATHS, ESCALATE, or BLAST)"),
    };
    if p.pos != p.toks.len() {
        bail!("unexpected trailing input after query");
    }
    Ok(query)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_paths_to_node() {
        let q = parse(r#"PATHS FROM user("alice") TO resource("prod")"#).unwrap();
        assert_eq!(
            q,
            Query::Paths {
                from_kind: "user".into(),
                from_id: "alice".into(),
                to: Target::Node {
                    kind: "resource".into(),
                    id: "prod".into()
                },
            }
        );
    }

    #[test]
    fn parses_paths_to_action() {
        let q = parse(r#"paths from user("alice") to action("*")"#).unwrap();
        assert_eq!(
            q,
            Query::Paths {
                from_kind: "user".into(),
                from_id: "alice".into(),
                to: Target::Action("*".into()),
            }
        );
    }

    #[test]
    fn parses_escalate_and_blast() {
        assert!(matches!(
            parse(r#"ESCALATE FROM user("alice")"#).unwrap(),
            Query::Escalate { .. }
        ));
        assert!(matches!(
            parse(r#"BLAST role("deployer")"#).unwrap(),
            Query::Blast { .. }
        ));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(r#"PATHS FROM user("alice")"#).is_err()); // missing TO
        assert!(parse(r#"FOO FROM user("x") TO resource("y")"#).is_err());
        assert!(parse(r#"PATHS FROM user("alice") TO resource("y") extra"#).is_err());
        assert!(parse(r#"PATHS FROM user(alice) TO resource("y")"#).is_err()); // unquoted
    }
}
