// SPDX-License-Identifier: GPL-3.0-or-later
//! The rule form: five fields, and the rule they make, in words and in nft
//! syntax, updated as you type.
//!
//! ```text
//!   Action    ‹ Allow ›
//!   Protocol  ‹ TCP ›
//!   Ports     8080▏
//!   From      ‹ the network on wlan0 (192.168.10.0/24) ›
//!   Comment   dev server
//! ```
//!
//! ←→ change a choice, typing fills a text field (typing on From switches it
//! to an address of your own), Tab and ↑↓ move, Enter reviews, Esc cancels.

use super::screen::Key;
use crate::edit::{Action, Change, Op, Proto, Spec};
use crate::ruleset::ChainKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Action,
    Proto,
    Ports,
    From,
    Comment,
}

impl Field {
    pub const ALL: [Field; 5] = [Field::Action, Field::Proto, Field::Ports, Field::From, Field::Comment];

    pub fn label(self) -> &'static str {
        match self {
            Field::Action => "Action",
            Field::Proto => "Protocol",
            Field::Ports => "Ports",
            Field::From => "From",
            Field::Comment => "Comment",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Form {
    pub title: String,
    pub chain: ChainKey,
    /// Insert above this rule (None: at the end), or replace it.
    pub replace: Option<u64>,
    pub before: Option<u64>,
    /// Where it goes, in words: "above rule 7".
    pub place: String,
    pub spec: Spec,
    pub field: usize,
    /// (label, range); the first is anywhere, the last an address typed in.
    pub froms: Vec<(String, String)>,
    pub from: usize,
    pub error: Option<String>,
}

pub enum Outcome {
    Stay,
    Cancel,
    Submit(Change),
}

impl Form {
    pub fn new(title: String, chain: ChainKey, spec: Spec, networks: Vec<(String, String)>) -> Form {
        let mut froms = vec![("anywhere".to_owned(), String::new())];
        froms.extend(networks);
        froms.push(("an address or range of your own".to_owned(), String::new()));
        let custom = froms.len() - 1;
        let from = match spec.from.trim() {
            "" => 0,
            text => froms.iter().position(|(_, r)| r == text).unwrap_or(custom),
        };
        let mut form = Form {
            title,
            chain,
            replace: None,
            before: None,
            place: String::new(),
            spec,
            field: 0,
            froms,
            from,
            error: None,
        };
        if from == custom {
            form.froms[custom].1 = form.spec.from.clone();
        }
        form
    }

    pub fn current(&self) -> Field {
        Field::ALL[self.field]
    }

    pub fn custom(&self) -> bool {
        self.from == self.froms.len() - 1
    }

    fn sync_from(&mut self) {
        self.spec.from = self.froms[self.from].1.clone();
    }

    fn cycle(&mut self, delta: isize) {
        let step = |i: usize, n: usize| (i as isize + delta).rem_euclid(n as isize) as usize;
        match self.current() {
            Field::Action => {
                let i = Action::ALL.iter().position(|a| *a == self.spec.action).unwrap_or(0);
                self.spec.action = Action::ALL[step(i, Action::ALL.len())];
            }
            Field::Proto => {
                let i = Proto::ALL.iter().position(|p| *p == self.spec.proto).unwrap_or(0);
                self.spec.proto = Proto::ALL[step(i, Proto::ALL.len())];
            }
            Field::From => {
                self.from = step(self.from, self.froms.len());
                self.sync_from();
            }
            Field::Ports | Field::Comment => {}
        }
    }

    fn text(&mut self) -> Option<&mut String> {
        match self.current() {
            Field::Ports => Some(&mut self.spec.ports),
            Field::Comment => Some(&mut self.spec.comment),
            Field::From => {
                let custom = self.froms.len() - 1;
                if self.from != custom {
                    // Typing an address of your own starts it fresh.
                    self.from = custom;
                    self.froms[custom].1.clear();
                }
                Some(&mut self.froms[custom].1)
            }
            _ => None,
        }
    }

    pub fn key(&mut self, key: Key) -> Outcome {
        self.error = None;
        let n = Field::ALL.len();
        match key {
            Key::Esc => return Outcome::Cancel,
            Key::Tab | Key::Down => self.field = (self.field + 1) % n,
            Key::BackTab | Key::Up => self.field = (self.field + n - 1) % n,
            Key::Left => self.cycle(-1),
            Key::Right => self.cycle(1),
            Key::Char(' ') if matches!(self.current(), Field::Action | Field::Proto) => self.cycle(1),
            Key::Char(c) => {
                if let Some(text) = self.text() {
                    text.push(c);
                }
                self.sync_custom();
            }
            Key::Backspace => {
                if let Some(text) = self.text() {
                    text.pop();
                }
                self.sync_custom();
            }
            Key::Enter => {
                return match self.spec.to_nft() {
                    Ok(rule) => Outcome::Submit(Change {
                        chain: self.chain.clone(),
                        op: match self.replace {
                            Some(handle) => Op::Replace { handle, rule },
                            None => Op::Insert { before: self.before, rule },
                        },
                        title: self.title.clone(),
                    }),
                    Err(e) => {
                        self.error = Some(e.0);
                        Outcome::Stay
                    }
                };
            }
            _ => {}
        }
        Outcome::Stay
    }

    fn sync_custom(&mut self) {
        if self.current() == Field::From {
            self.sync_from();
        }
    }

    /// The field's value as shown, and whether it is a choice (‹ ›).
    pub fn value(&self, field: Field) -> (String, bool) {
        match field {
            Field::Action => (self.spec.action.name().into(), true),
            Field::Proto => (self.spec.proto.name().into(), true),
            Field::Ports => (self.spec.ports.clone(), false),
            Field::Comment => (self.spec.comment.clone(), false),
            Field::From if self.custom() => (self.froms[self.from].1.clone(), false),
            Field::From => (self.froms[self.from].0.clone(), true),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form() -> Form {
        let chain = ChainKey { family: "inet".into(), table: "filter".into(), chain: "input".into() };
        Form::new(
            "Add".into(),
            chain,
            Spec::default(),
            vec![("home (192.168.10.0/24)".into(), "192.168.10.0/24".into())],
        )
    }

    fn typed(f: &mut Form, text: &str) {
        for c in text.chars() {
            f.key(Key::Char(c));
        }
    }

    #[test]
    fn fill_in_and_submit() {
        let mut f = form();
        assert!(matches!(f.key(Key::Enter), Outcome::Stay));
        assert!(f.error.as_deref().unwrap().contains("ports or an address"));
        f.key(Key::Right); // Block
        f.key(Key::Tab);
        f.key(Key::Right); // UDP
        f.key(Key::Tab);
        typed(&mut f, "53");
        f.key(Key::Tab);
        f.key(Key::Right); // home
        assert_eq!(f.spec.from, "192.168.10.0/24");
        match f.key(Key::Enter) {
            Outcome::Submit(c) => assert_eq!(
                c.op,
                Op::Insert {
                    before: None,
                    rule: "ip saddr 192.168.10.0/24 udp dport 53 counter drop".into()
                }
            ),
            _ => panic!("not submitted"),
        }
    }

    #[test]
    fn typing_on_from_is_your_own_address() {
        let mut f = form();
        f.field = 3;
        f.key(Key::Right);
        typed(&mut f, "10.0.0.5");
        assert!(f.custom());
        assert_eq!(f.spec.from, "10.0.0.5");
        f.key(Key::Backspace);
        assert_eq!(f.spec.from, "10.0.0.");
        f.key(Key::Right); // wraps to anywhere
        assert_eq!((f.from, f.spec.from.as_str()), (0, ""));
    }

    #[test]
    fn opens_on_an_existing_rule() {
        let chain = ChainKey { family: "inet".into(), table: "filter".into(), chain: "input".into() };
        let spec = Spec { from: "10.9.0.0/16".into(), ports: "22".into(), ..Spec::default() };
        let f = Form::new("Edit".into(), chain, spec, vec![]);
        assert!(f.custom());
        assert_eq!(f.value(Field::From), ("10.9.0.0/16".into(), false));
    }
}
