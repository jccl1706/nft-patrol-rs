// SPDX-License-Identifier: GPL-3.0-or-later
//! Changes to the ruleset: what can be asked for, and the table it makes.
//!
//! A rule is written from a [`Spec`] - the form's few fields - never typed
//! as nft syntax, so what the form shows is what the rule does. A change
//! does not send nft commands by handle; it rewrites the whole table it
//! touches, from nft's own listing with one line added, replaced or taken
//! out. That text is what the preview loads into a private namespace, what
//! `nft -c` checks and what is applied, in one transaction - so the preview
//! is exactly what gets applied. Other tables (docker's, libvirt's) are
//! never part of it.

use crate::error::Result;
use crate::names::Cidr;
use crate::ruleset::{Chain, ChainKey};
use crate::words::{Analysis, Cond, Dir, Verdict, analyse};
use crate::{bail, err};

/// The comment on the rule `L` adds, which is also how it is found again.
pub const LOG_COMMENT: &str = "nft-patrol: log what is blocked";
pub const LOG_PREFIX: &str = "nft-patrol blocked: ";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Block,
    Refuse,
}

impl Action {
    pub const ALL: [Action; 3] = [Action::Allow, Action::Block, Action::Refuse];

    pub fn name(self) -> &'static str {
        match self {
            Action::Allow => "Allow",
            Action::Block => "Block (drop silently)",
            Action::Refuse => "Refuse (tell the sender)",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
    Both,
    /// Any protocol: no ports.
    Any,
}

impl Proto {
    pub const ALL: [Proto; 4] = [Proto::Tcp, Proto::Udp, Proto::Both, Proto::Any];

    pub fn name(self) -> &'static str {
        match self {
            Proto::Tcp => "TCP",
            Proto::Udp => "UDP",
            Proto::Both => "TCP and UDP",
            Proto::Any => "any protocol",
        }
    }
}

/// A rule as the form has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    pub action: Action,
    pub proto: Proto,
    /// "22", "80, 443", "8000-8100"; empty for every port.
    pub ports: String,
    /// An address or range; empty for anywhere.
    pub from: String,
    pub comment: String,
}

impl Default for Spec {
    fn default() -> Spec {
        Spec {
            action: Action::Allow,
            proto: Proto::Tcp,
            ports: String::new(),
            from: String::new(),
            comment: String::new(),
        }
    }
}

/// "22, 80 8000-8100" -> ["22", "80", "8000-8100"], each checked.
pub fn parse_ports(text: &str) -> Result<Vec<String>> {
    let mut ports = Vec::new();
    for item in text.split(|c: char| c == ',' || c.is_whitespace()).filter(|s| !s.is_empty()) {
        let number = |s: &str| -> Result<u16> {
            match s.parse::<u16>() {
                Ok(n) if n > 0 => Ok(n),
                _ => bail!("\"{s}\" is not a port (1 to 65535)"),
            }
        };
        match item.split_once('-') {
            Some((a, b)) => {
                let (a, b) = (number(a)?, number(b)?);
                if a >= b {
                    bail!("the range {item} runs backwards");
                }
                ports.push(format!("{a}-{b}"));
            }
            None => ports.push(number(item)?.to_string()),
        }
    }
    Ok(ports)
}

impl Spec {
    /// The rule in nft's syntax; an error says which field is wrong.
    pub fn to_nft(&self) -> Result<String> {
        let mut parts = Vec::new();
        let from = self.from.trim();
        if !from.is_empty() {
            let Some(cidr) = Cidr::parse(from) else {
                bail!("from: \"{from}\" is not an address or a range like 192.168.1.0/24");
            };
            let family = if cidr.addr.is_ipv4() { "ip" } else { "ip6" };
            let host = if cidr.addr.is_ipv4() { 32 } else { 128 };
            let text =
                if cidr.len == host { cidr.addr.to_string() } else { format!("{}/{}", cidr.addr, cidr.len) };
            parts.push(format!("{family} saddr {text}"));
        }
        let ports = parse_ports(&self.ports).map_err(|e| err!("ports: {e}"))?;
        // A protocol alone ("all of TCP, from anywhere") decides nearly every
        // packet: too much for one form.
        if ports.is_empty() && from.is_empty() {
            bail!("give ports or an address: a rule for everything would decide every packet");
        }
        let ports_text = match ports.len() {
            0 => String::new(),
            1 => ports[0].clone(),
            _ => format!("{{ {} }}", ports.join(", ")),
        };
        match (self.proto, ports.is_empty()) {
            (Proto::Any, false) => bail!("ports: pick TCP or UDP - ports belong to a protocol"),
            (Proto::Any, true) => {}
            (Proto::Tcp, false) => parts.push(format!("tcp dport {ports_text}")),
            (Proto::Udp, false) => parts.push(format!("udp dport {ports_text}")),
            (Proto::Both, false) => parts.push(format!("meta l4proto {{ tcp, udp }} th dport {ports_text}")),
            (Proto::Tcp, true) => parts.push("meta l4proto tcp".into()),
            (Proto::Udp, true) => parts.push("meta l4proto udp".into()),
            (Proto::Both, true) => parts.push("meta l4proto { tcp, udp }".into()),
        }
        parts.push("counter".into());
        parts.push(
            match self.action {
                Action::Allow => "accept",
                Action::Block => "drop",
                Action::Refuse => "reject with icmpx admin-prohibited",
            }
            .into(),
        );
        let comment = self.comment.trim();
        if !comment.is_empty() {
            if comment.chars().any(|c| c == '"' || c == '\\' || c.is_control()) {
                bail!("comment: no quotes, backslashes or control characters");
            }
            if comment.chars().count() > 120 {
                bail!("comment: 120 characters at most");
            }
            parts.push(format!("comment \"{comment}\""));
        }
        Ok(parts.join(" "))
    }

    /// What the rule would be, for its sentence; None while a field is wrong.
    pub fn analysis(&self) -> Option<Analysis> {
        self.to_nft().ok()?;
        let mut conds = Vec::new();
        if let Some(cidr) = Cidr::parse(self.from.trim()) {
            let family = if cidr.addr.is_ipv4() { "ip" } else { "ip6" };
            let host = if cidr.addr.is_ipv4() { 32 } else { 128 };
            let text =
                if cidr.len == host { cidr.addr.to_string() } else { format!("{}/{}", cidr.addr, cidr.len) };
            conds.push(Cond::Addr {
                family: family.into(),
                dir: Dir::Src,
                values: vec![text],
                negated: false,
            });
        }
        let ports = parse_ports(&self.ports).ok()?;
        let protos = |p: &[&str]| p.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        match (self.proto, ports.is_empty()) {
            (Proto::Tcp, false) => {
                conds.push(Cond::Port { proto: "tcp".into(), dir: Dir::Dst, ports, negated: false })
            }
            (Proto::Udp, false) => {
                conds.push(Cond::Port { proto: "udp".into(), dir: Dir::Dst, ports, negated: false })
            }
            (Proto::Both, false) => {
                conds.push(Cond::Proto { protos: protos(&["tcp", "udp"]), negated: false });
                conds.push(Cond::Port { proto: "th".into(), dir: Dir::Dst, ports, negated: false });
            }
            (Proto::Tcp, true) => conds.push(Cond::Proto { protos: protos(&["tcp"]), negated: false }),
            (Proto::Udp, true) => conds.push(Cond::Proto { protos: protos(&["udp"]), negated: false }),
            (Proto::Both, true) => {
                conds.push(Cond::Proto { protos: protos(&["tcp", "udp"]), negated: false })
            }
            (Proto::Any, _) => {}
        }
        let verdict = match self.action {
            Action::Allow => Verdict::Accept,
            Action::Block => Verdict::Drop,
            Action::Refuse => Verdict::Reject,
        };
        Some(Analysis { conds, verdict, counter: true, log: None, limit: None, other: Vec::new() })
    }

    /// The form for an existing rule, when it is simple enough to be one.
    pub fn from_rule(a: &Analysis, comment: Option<&str>) -> Option<Spec> {
        let action = match a.verdict {
            Verdict::Accept => Action::Allow,
            Verdict::Drop => Action::Block,
            Verdict::Reject => Action::Refuse,
            _ => return None,
        };
        if a.log.is_some() || a.limit.is_some() || !a.other.is_empty() {
            return None;
        }
        let mut spec = Spec {
            action,
            proto: Proto::Any,
            comment: comment.unwrap_or_default().to_owned(),
            ..Spec::default()
        };
        let mut protos: Vec<String> = Vec::new();
        for cond in &a.conds {
            match cond {
                Cond::Addr { dir: Dir::Src, values, negated: false, .. }
                    if values.len() == 1 && !values[0].starts_with('@') && !values[0].contains('-') =>
                {
                    spec.from = values[0].clone();
                }
                Cond::Port { proto, dir: Dir::Dst, ports, negated: false }
                    if matches!(proto.as_str(), "tcp" | "udp" | "th")
                        && ports.iter().all(|p| !p.starts_with('@')) =>
                {
                    protos.push(proto.clone());
                    spec.ports = ports.join(", ");
                }
                Cond::Proto { protos: p, negated: false } if p.iter().all(|x| x == "tcp" || x == "udp") => {
                    protos.extend(p.iter().cloned());
                }
                _ => return None,
            }
        }
        let has = |p: &str| protos.iter().any(|x| x == p);
        spec.proto = match (has("tcp"), has("udp"), has("th")) {
            (true, true, _) => Proto::Both,
            (true, false, false) => Proto::Tcp,
            (false, true, false) => Proto::Udp,
            (false, false, false) => Proto::Any,
            _ => return None,
        };
        Some(spec)
    }
}

/// Where a change goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// Above the rule with this handle; at the end when None.
    Insert {
        before: Option<u64>,
        rule: String,
    },
    Replace {
        handle: u64,
        rule: String,
    },
    Delete {
        handle: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub chain: ChainKey,
    pub op: Op,
    /// What it does, for the review and the message after.
    pub title: String,
}

/// A rule that only finishes off whatever got this far: no address, port,
/// protocol or interface, and it blocks, or only counts or logs.
fn catch_all(a: &Analysis) -> bool {
    matches!(a.verdict, Verdict::Drop | Verdict::Reject | Verdict::None)
        && a.conds.iter().all(|c| matches!(c, Cond::PktType { .. } | Cond::State { .. }))
}

/// Where a new rule goes when no rule is picked: above the catch-all rules
/// at the end of the chain (a rule below them would never be reached), or
/// at the end.
pub fn default_position(chain: &Chain) -> Option<u64> {
    let mut before = None;
    for rule in chain.rules.iter().rev() {
        if !catch_all(&analyse(rule)) {
            break;
        }
        before = Some(rule.handle);
    }
    before
}

/// The logging rule `L` added, if it is there.
pub fn log_rule(chain: &Chain) -> Option<u64> {
    chain.rules.iter().find(|r| r.comment.as_deref() == Some(LOG_COMMENT)).map(|r| r.handle)
}

/// The rule `L` adds: every packet that reaches the catch-all rules is
/// about to be blocked, so logging there logs what is blocked. Rate-limited
/// so a flood cannot flood the journal too.
pub fn log_rule_text() -> String {
    format!(
        "meta pkttype host limit rate 10/second log prefix \"{LOG_PREFIX}\" level info comment \"{LOG_COMMENT}\""
    )
}

/// The table after the change, as an nft script that replaces it in one
/// transaction. `listing` is `nft -s -a list table FAMILY NAME`.
pub fn rewrite(listing: &str, change: &Change) -> Result<String> {
    let mut out = format!("destroy table {} {}\n", change.chain.family, change.chain.table);
    let mut chain = String::new();
    let mut done = false;
    let rule_line = |rule: &str| format!("\t\t{rule}\n");
    for line in listing.lines() {
        let trimmed = line.trim();
        let (body, handle) = match line.rsplit_once(" # handle ") {
            Some((body, h)) => (body, h.trim().parse::<u64>().ok()),
            None => (line, None),
        };
        if trimmed.starts_with("chain ") && trimmed.contains('{') {
            chain = trimmed.split_whitespace().nth(1).unwrap_or_default().to_owned();
        }
        let ours = chain == change.chain.chain && !done;
        if ours && trimmed == "}" {
            if let Op::Insert { before: None, rule } = &change.op {
                out.push_str(&rule_line(rule));
                done = true;
            }
            chain.clear();
        } else if trimmed == "}" {
            chain.clear();
        }
        if ours && handle.is_some() && !trimmed.starts_with("chain ") && !trimmed.starts_with("table ") {
            match &change.op {
                Op::Insert { before: Some(h), rule } if Some(*h) == handle => {
                    out.push_str(&rule_line(rule));
                    done = true;
                }
                Op::Replace { handle: h, rule } if Some(*h) == handle => {
                    out.push_str(&rule_line(rule));
                    done = true;
                    continue;
                }
                Op::Delete { handle: h } if Some(*h) == handle => {
                    done = true;
                    continue;
                }
                _ => {}
            }
        }
        out.push_str(body);
        out.push('\n');
    }
    if !done {
        bail!(
            "{} {} {}: the rule or chain is gone - reload and try again",
            change.chain.family,
            change.chain.table,
            change.chain.chain
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::tests::{archydots, rich};

    const TABLE: &str = include_str!("../tests/data/archydots-table.txt");

    fn spec(action: Action, proto: Proto, ports: &str, from: &str) -> Spec {
        Spec { action, proto, ports: ports.into(), from: from.into(), comment: String::new() }
    }

    #[test]
    fn rules_from_the_form() {
        let s = spec(Action::Allow, Proto::Tcp, "22", "192.168.10.0/24");
        assert_eq!(s.to_nft().unwrap(), "ip saddr 192.168.10.0/24 tcp dport 22 counter accept");
        let s = Spec { comment: "web".into(), ..spec(Action::Refuse, Proto::Both, "80, 443 8000-8100", "") };
        assert_eq!(
            s.to_nft().unwrap(),
            "meta l4proto { tcp, udp } th dport { 80, 443, 8000-8100 } counter reject with icmpx admin-prohibited comment \"web\""
        );
        assert_eq!(
            spec(Action::Block, Proto::Any, "", "fe80::1").to_nft().unwrap(),
            "ip6 saddr fe80::1 counter drop"
        );
        assert_eq!(
            spec(Action::Allow, Proto::Udp, "", "10.0.0.7/8").to_nft().unwrap(),
            "ip saddr 10.0.0.0/8 meta l4proto udp counter accept"
        );
        for (bad, why) in [
            (spec(Action::Allow, Proto::Any, "", ""), "a rule for everything"),
            (spec(Action::Allow, Proto::Tcp, "", ""), "a rule for everything"),
            (spec(Action::Allow, Proto::Any, "22", ""), "pick TCP or UDP"),
            (spec(Action::Allow, Proto::Tcp, "70000", ""), "not a port"),
            (spec(Action::Allow, Proto::Tcp, "90-80", ""), "backwards"),
            (spec(Action::Allow, Proto::Tcp, "22", "home"), "not an address"),
            (Spec { comment: "say \"hi\"".into(), ..spec(Action::Allow, Proto::Tcp, "22", "") }, "no quotes"),
        ] {
            let e = bad.to_nft().unwrap_err();
            assert!(e.0.contains(why), "{bad:?}: {e}");
        }
    }

    #[test]
    fn form_from_a_rule_and_back() {
        let r = archydots();
        let input = r.chain("inet", "filter", "input").unwrap();
        let ssh = &input.rules[5];
        let s = Spec::from_rule(&analyse(ssh), ssh.comment.as_deref()).unwrap();
        assert_eq!(
            s,
            Spec {
                comment: "sshd - home LAN only".into(),
                ..spec(Action::Allow, Proto::Tcp, "22", "192.168.10.0/24")
            }
        );
        assert!(Spec::from_rule(&analyse(&input.rules[1]), None).is_none(), "ct state is not in the form");
        let rich = rich();
        let ports = &rich.chain("inet", "t", "input").unwrap().rules[0];
        assert!(Spec::from_rule(&analyse(ports), None).is_none(), "a set source is not in the form");
        // What the form writes, read back, is the same form.
        for s in
            [spec(Action::Refuse, Proto::Both, "53", ""), spec(Action::Block, Proto::Udp, "", "10.1.0.0/16")]
        {
            let text = s.to_nft().unwrap();
            let json = unshare_json(&text);
            if let Some(rule) = json {
                assert_eq!(Spec::from_rule(&analyse(&rule), None), Some(s), "{text}");
            }
        }
    }

    /// The rule as nft reads it back, through a private namespace; None
    /// where namespaces are not available.
    fn unshare_json(rule: &str) -> Option<crate::ruleset::Rule> {
        let script = format!("table inet x {{ chain y {{ {rule}; }} }}");
        let out = std::process::Command::new("unshare")
            .args(["-rn", "sh", "-c", "echo \"$1\" | nft -f - && nft -j list ruleset", "sh", &script])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let r = crate::ruleset::parse(&String::from_utf8_lossy(&out.stdout), "").ok()?;
        r.chain("inet", "x", "y")?.rules.first().cloned()
    }

    #[test]
    fn where_new_rules_go() {
        let r = archydots();
        let input = r.chain("inet", "filter", "input").unwrap();
        assert_eq!(default_position(input), Some(11), "above the refuse and the counter");
        assert_eq!(default_position(r.chain("inet", "filter", "forward").unwrap()), None);
        assert_eq!(log_rule(input), None);
    }

    fn change(op: Op) -> Change {
        Change {
            chain: ChainKey { family: "inet".into(), table: "filter".into(), chain: "input".into() },
            op,
            title: String::new(),
        }
    }

    #[test]
    fn rewrites_the_table() {
        let new =
            rewrite(TABLE, &change(Op::Insert { before: Some(11), rule: "tcp dport 80 accept".into() }))
                .unwrap();
        assert!(new.starts_with("destroy table inet filter\ntable inet filter {\n"));
        assert!(!new.contains("# handle"));
        let lines: Vec<&str> = new.lines().map(str::trim).collect();
        let at = lines.iter().position(|l| *l == "tcp dport 80 accept").unwrap();
        assert!(lines[at + 1].starts_with("meta pkttype host limit"));
        assert!(lines[at - 1].starts_with("ip saddr 192.168.10.0/24 tcp dport 22"));

        let end =
            rewrite(TABLE, &change(Op::Insert { before: None, rule: "tcp dport 80 accept".into() })).unwrap();
        let lines: Vec<&str> = end.lines().map(str::trim).collect();
        let at = lines.iter().position(|l| *l == "tcp dport 80 accept").unwrap();
        assert_eq!(lines[at - 1], "counter");
        assert_eq!(lines[at + 1], "}", "the end of the input chain, not forward's");

        let gone = rewrite(TABLE, &change(Op::Delete { handle: 10 })).unwrap();
        assert!(!gone.contains("tcp dport 22"));
        assert_eq!(
            gone.lines().count(),
            TABLE.lines().count(),
            "one line more (destroy), one less (the rule)"
        );

        let swapped =
            rewrite(TABLE, &change(Op::Replace { handle: 10, rule: "tcp dport 2222 accept".into() }))
                .unwrap();
        assert!(swapped.contains("\t\ttcp dport 2222 accept\n") && !swapped.contains("dport 22 "));

        assert!(rewrite(TABLE, &change(Op::Delete { handle: 99 })).unwrap_err().0.contains("gone"));
    }
}
