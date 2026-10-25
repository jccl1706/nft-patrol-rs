// SPDX-License-Identifier: GPL-3.0-or-later
//! The ruleset, as nft reports it: tables, chains, rules and named sets.
//!
//! Read from `nft -j list ruleset`, the stable JSON form, so nothing here
//! parses nft's own language. Each rule also gets its line from
//! `nft -a list ruleset`, matched by handle, because that is what a person
//! would write and what the detail panel shows.

use std::collections::HashMap;

use serde_json::Value;

use crate::err;
use crate::error::Result;

#[derive(Debug, Clone, Default)]
pub struct Ruleset {
    pub tables: Vec<Table>,
    pub sets: Vec<Set>,
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct Table {
    pub family: String,
    pub name: String,
    pub chains: Vec<Chain>,
}

#[derive(Debug, Clone)]
pub struct Chain {
    pub family: String,
    pub table: String,
    pub name: String,
    /// Present for base chains, the ones packets enter from a hook.
    pub base: Option<Base>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Base {
    /// filter, nat or route
    pub kind: String,
    pub hook: String,
    pub priority: i64,
    pub policy: String,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub handle: u64,
    pub comment: Option<String>,
    pub expr: Vec<Value>,
    /// The rule in nft's syntax, without the handle.
    pub text: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Set {
    pub family: String,
    pub table: String,
    pub name: String,
    pub kind: String,
    pub elements: Vec<String>,
}

/// A chain's identity, which survives a reload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChainKey {
    pub family: String,
    pub table: String,
    pub chain: String,
}

impl Chain {
    pub fn key(&self) -> ChainKey {
        ChainKey { family: self.family.clone(), table: self.table.clone(), chain: self.name.clone() }
    }

    /// `inet filter input`
    pub fn path(&self) -> String {
        format!("{} {} {}", self.family, self.table, self.name)
    }
}

impl Rule {
    /// Packets and bytes, when the rule has a counter.
    pub fn counter(&self) -> Option<(u64, u64)> {
        self.expr.iter().find_map(|e| {
            let c = e.get("counter")?;
            Some((c.get("packets")?.as_u64()?, c.get("bytes")?.as_u64()?))
        })
    }
}

impl Ruleset {
    pub fn chains(&self) -> impl Iterator<Item = &Chain> {
        self.tables.iter().flat_map(|t| &t.chains)
    }

    pub fn chain(&self, family: &str, table: &str, name: &str) -> Option<&Chain> {
        self.chains().find(|c| c.family == family && c.table == table && c.name == name)
    }

    pub fn set(&self, family: &str, table: &str, name: &str) -> Option<&Set> {
        self.sets.iter().find(|s| s.family == family && s.table == table && s.name == name)
    }

    pub fn rule_count(&self) -> usize {
        self.chains().map(|c| c.rules.len()).sum()
    }

    /// Base chains on a hook, in the order the kernel runs them.
    pub fn hooked(&self, hook: &str) -> Vec<&Chain> {
        let mut chains: Vec<&Chain> =
            self.chains().filter(|c| c.base.as_ref().is_some_and(|b| b.hook == hook)).collect();
        chains.sort_by_key(|c| c.base.as_ref().map(|b| b.priority));
        chains
    }

    /// Whether any rule logs, which is what the Blocked tab reads.
    pub fn logs(&self) -> bool {
        self.chains().flat_map(|c| &c.rules).any(|r| r.expr.iter().any(|e| e.get("log").is_some()))
    }
}

/// A JSON value as nft would print it: `22`, `192.168.10.0/24`, `8000-8100`,
/// `@allowed`; a set gives one string per element.
pub fn value_strings(value: &Value) -> Vec<String> {
    match value {
        Value::Object(map) => {
            if let Some(Value::Array(items)) = map.get("set") {
                return items.iter().flat_map(value_strings).collect();
            }
            vec![value_text(value)]
        }
        Value::Array(items) => items.iter().flat_map(value_strings).collect(),
        _ => vec![value_text(value)],
    }
}

pub fn value_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        Value::Array(items) => items.iter().map(value_text).collect::<Vec<_>>().join(", "),
        Value::Object(map) => {
            if let Some(p) = map.get("prefix") {
                return format!("{}/{}", value_text(&p["addr"]), value_text(&p["len"]));
            }
            if let Some(Value::Array(r)) = map.get("range")
                && r.len() == 2
            {
                return format!("{}-{}", value_text(&r[0]), value_text(&r[1]));
            }
            if let Some(Value::Array(items)) = map.get("set") {
                return format!("{{ {} }}", items.iter().map(value_text).collect::<Vec<_>>().join(", "));
            }
            serde_json::to_string(value).unwrap_or_default()
        }
    }
}

/// Parse `nft -j list ruleset`, and attach `nft -a list ruleset`'s lines.
pub fn parse(json: &str, text: &str) -> Result<Ruleset> {
    let root: Value = serde_json::from_str(json).map_err(|e| err!("nft's JSON: {e}"))?;
    let items = root
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(|| err!("nft's JSON has no \"nftables\" list"))?;
    let lines = rule_lines(text);
    let mut ruleset = Ruleset::default();
    let str_of = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or_default().to_owned();
    for item in items {
        if let Some(m) = item.get("metainfo") {
            ruleset.version = str_of(m, "version");
        } else if let Some(t) = item.get("table") {
            ruleset.tables.push(Table {
                family: str_of(t, "family"),
                name: str_of(t, "name"),
                chains: vec![],
            });
        } else if let Some(c) = item.get("chain") {
            let base = c.get("hook").map(|_| Base {
                kind: str_of(c, "type"),
                hook: str_of(c, "hook"),
                priority: c.get("prio").and_then(Value::as_i64).unwrap_or(0),
                policy: Some(str_of(c, "policy"))
                    .filter(|p| !p.is_empty())
                    .unwrap_or_else(|| "accept".into()),
            });
            let chain = Chain {
                family: str_of(c, "family"),
                table: str_of(c, "table"),
                name: str_of(c, "name"),
                base,
                rules: vec![],
            };
            match ruleset.tables.iter_mut().find(|t| t.family == chain.family && t.name == chain.table) {
                Some(table) => table.chains.push(chain),
                None => return Err(err!("chain {} before its table", chain.path())),
            }
        } else if let Some(s) = item.get("set") {
            let elements = s.get("elem").map(value_strings).unwrap_or_default();
            let kind = match s.get("type") {
                Some(Value::Array(parts)) => parts.iter().map(value_text).collect::<Vec<_>>().join(" . "),
                Some(v) => value_text(v),
                None => String::new(),
            };
            ruleset.sets.push(Set {
                family: str_of(s, "family"),
                table: str_of(s, "table"),
                name: str_of(s, "name"),
                kind,
                elements,
            });
        } else if let Some(r) = item.get("rule") {
            let (family, table, chain) = (str_of(r, "family"), str_of(r, "table"), str_of(r, "chain"));
            let handle = r.get("handle").and_then(Value::as_u64).unwrap_or(0);
            let rule = Rule {
                handle,
                comment: r.get("comment").and_then(Value::as_str).map(str::to_owned),
                expr: r.get("expr").and_then(Value::as_array).cloned().unwrap_or_default(),
                text: lines.get(&(family.clone(), table.clone(), chain.clone(), handle)).cloned(),
            };
            let owner = ruleset
                .tables
                .iter_mut()
                .flat_map(|t| t.chains.iter_mut())
                .find(|c| c.family == family && c.table == table && c.name == chain);
            match owner {
                Some(c) => c.rules.push(rule),
                None => return Err(err!("rule {handle} before its chain {family} {table} {chain}")),
            }
        }
    }
    Ok(ruleset)
}

/// Rule lines from `nft -a list ruleset`, by (family, table, chain, handle).
fn rule_lines(text: &str) -> HashMap<(String, String, String, u64), String> {
    let mut lines = HashMap::new();
    let (mut family, mut table, mut chain) = (String::new(), String::new(), String::new());
    for line in text.lines() {
        let line = line.trim();
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.first() == Some(&"table") && words.len() >= 3 {
            (family, table) = (words[1].to_owned(), words[2].to_owned());
            chain.clear();
        } else if words.first() == Some(&"chain") && words.len() >= 2 && line.contains('{') {
            chain = words[1].to_owned();
        } else if line == "}" {
            chain.clear();
        } else if !chain.is_empty()
            && let Some((rule, handle)) = line.rsplit_once(" # handle ")
            && let Ok(handle) = handle.trim().parse()
        {
            lines.insert((family.clone(), table.clone(), chain.clone(), handle), rule.trim().to_owned());
        }
    }
    lines
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub const ARCHYDOTS_JSON: &str = include_str!("../tests/data/archydots.json");
    pub const ARCHYDOTS_TEXT: &str = include_str!("../tests/data/archydots.txt");
    pub const RICH_JSON: &str = include_str!("../tests/data/rich.json");
    pub const RICH_TEXT: &str = include_str!("../tests/data/rich.txt");

    pub fn archydots() -> Ruleset {
        parse(ARCHYDOTS_JSON, ARCHYDOTS_TEXT).unwrap()
    }

    pub fn rich() -> Ruleset {
        parse(RICH_JSON, RICH_TEXT).unwrap()
    }

    #[test]
    fn parses_tables_chains_rules() {
        let r = archydots();
        assert_eq!(r.tables.len(), 1);
        let input = r.chain("inet", "filter", "input").unwrap();
        assert_eq!(input.base.as_ref().unwrap().policy, "drop");
        assert_eq!(input.rules.len(), 8);
        let ssh = input.rules.iter().find(|r| r.comment.as_deref() == Some("sshd - home LAN only")).unwrap();
        assert_eq!(
            ssh.text.as_deref(),
            Some("ip saddr 192.168.10.0/24 tcp dport 22 accept comment \"sshd - home LAN only\"")
        );
        assert_eq!(r.hooked("input").len(), 1);
        assert!(!r.logs());
    }

    #[test]
    fn sets_and_regular_chains() {
        let r = rich();
        let set = r.set("inet", "t", "allowed").unwrap();
        assert_eq!(set.elements, ["1.2.3.4", "10.0.0.0/8"]);
        assert!(r.chain("inet", "t", "wg").unwrap().base.is_none());
        assert_eq!(r.hooked("prerouting")[0].base.as_ref().unwrap().priority, -100);
        assert!(r.logs());
        let counted = r.chain("inet", "t", "input").unwrap().rules[0].counter();
        assert_eq!(counted, Some((0, 0)));
    }

    #[test]
    fn values() {
        let v: Value = serde_json::from_str(r#"{"set": [80, 443, {"range": [8000, 8100]}]}"#).unwrap();
        assert_eq!(value_strings(&v), ["80", "443", "8000-8100"]);
        let v: Value = serde_json::from_str(r#"{"prefix": {"addr": "fe80::", "len": 10}}"#).unwrap();
        assert_eq!(value_text(&v), "fe80::/10");
    }
}
