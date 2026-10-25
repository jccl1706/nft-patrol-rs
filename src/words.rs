// SPDX-License-Identifier: GPL-3.0-or-later
//! Rules in plain words.
//!
//! A rule's JSON is read into conditions and a verdict ([`Analysis`]) - the
//! same structure the exposure check walks - and the sentence is built from
//! that: `ip saddr 192.168.10.0/24 tcp dport 22 accept` becomes "Allow SSH
//! (tcp 22) from 192.168.10.0/24 (the network on wlan0)". Anything not
//! understood is kept in nft's own words rather than guessed at.

use serde_json::Value;

use crate::names::Names;
use crate::ruleset::{Rule, Ruleset, value_strings, value_text};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
    Reject,
    Jump(String),
    Goto(String),
    Return,
    Continue,
    Queue,
    /// Address translation, with where to: "to 10.0.0.2:80".
    Nat(String),
    /// No verdict: the packet goes on to the next rule.
    None,
}

impl Verdict {
    /// The badge in the list.
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Accept => "ALLOW",
            Verdict::Drop => "BLOCK",
            Verdict::Reject => "REFUSE",
            Verdict::Jump(_) => "JUMP",
            Verdict::Goto(_) => "GOTO",
            Verdict::Return => "RETURN",
            Verdict::Continue => "CONTINUE",
            Verdict::Queue => "QUEUE",
            Verdict::Nat(_) => "NAT",
            Verdict::None => "",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Src,
    Dst,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cond {
    State {
        states: Vec<String>,
        negated: bool,
    },
    Iface {
        names: Vec<String>,
        negated: bool,
        incoming: bool,
    },
    Proto {
        protos: Vec<String>,
        negated: bool,
    },
    /// IPv4 or IPv6 only (`meta nfproto`).
    Family {
        family: String,
        negated: bool,
    },
    PktType {
        types: Vec<String>,
        negated: bool,
    },
    /// `proto` is tcp, udp, sctp, ... or th (any transport header).
    Port {
        proto: String,
        dir: Dir,
        ports: Vec<String>,
        negated: bool,
    },
    /// `family` is ip or ip6.
    Addr {
        family: String,
        dir: Dir,
        values: Vec<String>,
        negated: bool,
    },
    TcpFlags {
        text: String,
    },
    Other {
        text: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Analysis {
    pub conds: Vec<Cond>,
    pub verdict: Verdict,
    pub counter: bool,
    /// The log prefix, when the rule logs.
    pub log: Option<String>,
    /// "5/second"; "over 5/second" for an inverted limit.
    pub limit: Option<String>,
    /// Statements with no plain-words form, in nft's words.
    pub other: Vec<String>,
}

fn left_text(left: &Value) -> String {
    if let Some(p) = left.get("payload") {
        return format!("{} {}", value_text(&p["protocol"]), value_text(&p["field"]));
    }
    for kind in ["meta", "ct", "fib", "socket", "rt"] {
        if let Some(m) = left.get(kind) {
            return format!("{kind} {}", value_text(&m["key"]));
        }
    }
    value_text(left)
}

fn op_text(op: &str) -> &str {
    match op {
        "==" | "in" => "",
        other => other,
    }
}

fn condition(m: &Value) -> Cond {
    let op = m["op"].as_str().unwrap_or("==");
    let negated = op == "!=";
    let left = &m["left"];
    let right = &m["right"];
    let values = value_strings(right);
    let other = || Cond::Other {
        text: [left_text(left), op_text(op).to_owned(), value_text(right)]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" "),
    };
    if op != "==" && op != "!=" && op != "in" {
        return other();
    }
    if let Some(key) = left.get("ct").and_then(|c| c["key"].as_str()) {
        return if key == "state" { Cond::State { states: values, negated } } else { other() };
    }
    if let Some(key) = left.get("meta").and_then(|c| c["key"].as_str()) {
        return match key {
            "iif" | "iifname" => Cond::Iface { names: values, negated, incoming: true },
            "oif" | "oifname" => Cond::Iface { names: values, negated, incoming: false },
            "l4proto" => Cond::Proto { protos: values, negated },
            "nfproto" => Cond::Family { family: value_text(right), negated },
            "pkttype" => Cond::PktType { types: values, negated },
            _ => other(),
        };
    }
    if let Some(p) = left.get("payload") {
        let protocol = p["protocol"].as_str().unwrap_or_default();
        let field = p["field"].as_str().unwrap_or_default();
        return match (protocol, field) {
            (_, "dport") => Cond::Port { proto: protocol.into(), dir: Dir::Dst, ports: values, negated },
            (_, "sport") => Cond::Port { proto: protocol.into(), dir: Dir::Src, ports: values, negated },
            ("ip" | "ip6", "saddr") => Cond::Addr { family: protocol.into(), dir: Dir::Src, values, negated },
            ("ip" | "ip6", "daddr") => Cond::Addr { family: protocol.into(), dir: Dir::Dst, values, negated },
            ("ip", "protocol") | ("ip6", "nexthdr") => Cond::Proto { protos: values, negated },
            ("tcp", "flags") => Cond::TcpFlags { text: other_text(op, right) },
            _ => other(),
        };
    }
    other()
}

fn other_text(op: &str, right: &Value) -> String {
    let op = op_text(op);
    if op.is_empty() { value_text(right) } else { format!("{op} {}", value_text(right)) }
}

pub fn analyse(rule: &Rule) -> Analysis {
    let mut a = Analysis {
        conds: Vec::new(),
        verdict: Verdict::None,
        counter: false,
        log: None,
        limit: None,
        other: Vec::new(),
    };
    for e in &rule.expr {
        let Some((key, value)) = e.as_object().and_then(|o| o.iter().next()) else { continue };
        match key.as_str() {
            "match" => a.conds.push(condition(value)),
            "accept" => a.verdict = Verdict::Accept,
            "drop" => a.verdict = Verdict::Drop,
            "reject" => a.verdict = Verdict::Reject,
            "return" => a.verdict = Verdict::Return,
            "continue" => a.verdict = Verdict::Continue,
            "queue" => a.verdict = Verdict::Queue,
            "jump" => a.verdict = Verdict::Jump(value_text(&value["target"])),
            "goto" => a.verdict = Verdict::Goto(value_text(&value["target"])),
            "counter" => a.counter = true,
            "log" => a.log = Some(value.get("prefix").map(value_text).unwrap_or_default()),
            "limit" => {
                let rate = format!("{}/{}", value_text(&value["rate"]), value_text(&value["per"]));
                let over = value.get("inv").and_then(Value::as_bool).unwrap_or(false);
                a.limit = Some(if over { format!("over {rate}") } else { rate });
            }
            "dnat" | "snat" | "redirect" | "masquerade" => {
                let addr = value.get("addr").map(value_text).unwrap_or_default();
                let port = value.get("port").map(value_text).unwrap_or_default();
                let target = match (addr.is_empty(), port.is_empty()) {
                    (false, false) => format!("{addr}:{port}"),
                    (false, true) => addr,
                    (true, false) => format!("port {port}"),
                    (true, true) => String::new(),
                };
                a.verdict = Verdict::Nat(match key.as_str() {
                    "dnat" => format!("to {target}"),
                    "snat" => format!("as {target}"),
                    "redirect" if !target.is_empty() => format!("to this machine's {target}"),
                    "redirect" => "to this machine".into(),
                    _ => "as this machine's own address (masquerade)".into(),
                });
            }
            other => a.other.push(other.to_owned()),
        }
    }
    a
}

/// Context for naming things in a rule: services, networks, sets.
pub struct Ctx<'a> {
    pub names: &'a Names,
    pub ruleset: &'a Ruleset,
    pub family: &'a str,
    pub table: &'a str,
}

impl Ctx<'_> {
    /// `@allowed` -> `set allowed (2 entries)`.
    fn value(&self, value: &str, address: bool) -> String {
        if let Some(name) = value.strip_prefix('@') {
            return match self.ruleset.set(self.family, self.table, name) {
                Some(set) => format!(
                    "set {name} ({} entr{})",
                    set.elements.len(),
                    if set.elements.len() == 1 { "y" } else { "ies" }
                ),
                None => format!("set {name}"),
            };
        }
        if address { self.names.address(value) } else { value.to_owned() }
    }

    fn addresses(&self, values: &[String]) -> String {
        join(values.iter().map(|v| self.value(v, true)).collect(), "or")
    }

    /// `SSH (tcp 22)`, `tcp 8000-8100`, `DNS (udp 53)`.
    fn port(&self, proto: &str, port: &str) -> String {
        if port.starts_with('@') {
            return format!("{proto} ports in {}", self.value(port, false));
        }
        let shown = if proto == "th" { "port".to_owned() } else { proto.to_owned() };
        match port.parse().ok().and_then(|p| self.names.service(p, proto)) {
            Some(name) => format!("{name} ({shown} {port})"),
            None => format!("{shown} {port}"),
        }
    }
}

/// "a", "a or b", "a, b or c".
fn join(items: Vec<String>, last: &str) -> String {
    match items.len() {
        0 => String::new(),
        1 => items.into_iter().next().unwrap(),
        n => format!("{} {last} {}", items[..n - 1].join(", "), items[n - 1]),
    }
}

fn is_icmp(proto: &str) -> bool {
    matches!(proto, "icmp" | "ipv6-icmp" | "icmpv6" | "1" | "58")
}

fn proto_name(proto: &str) -> String {
    match proto {
        "ipv6-icmp" | "icmpv6" => "ICMPv6".into(),
        p => p.to_uppercase(),
    }
}

/// One condition in plain words, for the detail panel's list.
pub fn cond_text(cond: &Cond, ctx: &Ctx) -> String {
    let not = |negated: &bool| if *negated { "not " } else { "" };
    match cond {
        Cond::State { states, negated } => {
            format!("connection state is {}{}", not(negated), join(states.clone(), "or"))
        }
        Cond::Iface { names, negated, incoming } => format!(
            "{} {}{}",
            if *incoming { "arrives on" } else { "leaves via" },
            not(negated),
            join(names.clone(), "or")
        ),
        Cond::Proto { protos, negated } => {
            format!("protocol is {}{}", not(negated), join(protos.clone(), "or"))
        }
        Cond::Family { family, negated } => format!("{}{family} only", not(negated)),
        Cond::PktType { types, negated } => format!(
            "packet is {}{}",
            not(negated),
            join(types.iter().map(|t| pkttype(t).to_owned()).collect(), "or")
        ),
        Cond::Port { proto, dir, ports, negated } => format!(
            "{} port {}{}",
            if *dir == Dir::Dst { "destination" } else { "source" },
            not(negated),
            join(ports.iter().map(|p| ctx.port(proto, p)).collect(), "or")
        ),
        Cond::Addr { family, dir, values, negated } => format!(
            "{} {} {}{}",
            if family == "ip6" { "IPv6" } else { "IPv4" },
            if *dir == Dir::Src { "source" } else { "destination" },
            if *negated { "not " } else { "is " },
            ctx.addresses(values)
        ),
        Cond::TcpFlags { text } => format!("TCP flags {text}"),
        Cond::Other { text } => text.clone(),
    }
}

fn pkttype(t: &str) -> &str {
    match t {
        "host" => "addressed to this machine",
        "broadcast" => "broadcast",
        "multicast" => "multicast",
        "other" => "addressed to another machine",
        t => t,
    }
}

/// The rule as one sentence.
pub fn sentence(a: &Analysis, ctx: &Ctx) -> String {
    use Verdict as V;
    let only = |f: &dyn Fn(&Cond) -> bool| a.conds.len() == 1 && f(&a.conds[0]);

    // The rules nearly every ruleset starts with, said the way people say them.
    if a.verdict == V::Accept
        && only(&|c| {
            matches!(c, Cond::State { states, negated: false }
                if states.iter().all(|s| s == "established" || s == "related"))
        })
    {
        return "Allow replies to connections this machine started".into();
    }
    if matches!(a.verdict, V::Drop | V::Reject)
        && only(&|c| matches!(c, Cond::State { states, negated: false } if states == &["invalid"]))
    {
        return "Block broken packets (invalid connection state)".into();
    }
    if a.verdict == V::Accept
        && only(&|c| matches!(c, Cond::Iface { names, negated: false, incoming: true } if names == &["lo"]))
    {
        return "Allow this machine to talk to itself (loopback)".into();
    }
    if a.verdict == V::Accept
        && only(&|c| matches!(c, Cond::Proto { protos, negated: false } if protos.iter().all(|p| is_icmp(p))))
    {
        return "Allow ping and other ICMP messages".into();
    }

    let mut subject = Vec::new();
    let mut extras = Vec::new();
    let mut from = Vec::new();
    let mut ports_seen = Vec::new();
    for cond in &a.conds {
        match cond {
            Cond::Port { proto, dir: Dir::Dst, ports, negated } => {
                ports_seen.push(proto.clone());
                let items = join(ports.iter().map(|p| ctx.port(proto, p)).collect(), "or");
                subject.push(if *negated { format!("traffic except {items}") } else { items });
            }
            Cond::Proto { protos, negated: false } => {
                let names: Vec<String> = protos.iter().map(|p| proto_name(p)).collect();
                subject.push(format!("{} traffic", join(names, "and")));
            }
            Cond::Proto { protos, negated: true } => {
                let names: Vec<String> = protos.iter().map(|p| proto_name(p)).collect();
                subject.push(format!("traffic except {}", join(names, "and")));
            }
            Cond::PktType { types, negated: false } if types == &["host"] => {
                subject.push("packets sent to this machine".into())
            }
            Cond::Addr { dir: Dir::Src, values, negated, .. } => from.push(if *negated {
                format!("from anywhere except {}", ctx.addresses(values))
            } else {
                format!("from {}", ctx.addresses(values))
            }),
            Cond::Addr { dir: Dir::Dst, values, negated, .. } => extras.push(format!(
                "to {}{}",
                if *negated { "anything but " } else { "" },
                ctx.addresses(values)
            )),
            Cond::Iface { names, negated, incoming: true } => extras.push(format!(
                "{}arriving on {}",
                if *negated { "not " } else { "" },
                join(names.clone(), "or")
            )),
            Cond::Iface { names, negated, incoming: false } => extras.push(format!(
                "{}leaving via {}",
                if *negated { "not " } else { "" },
                join(names.clone(), "or")
            )),
            Cond::State { states, negated: false } if states == &["new"] => {
                extras.push("(new connections)".into())
            }
            Cond::Family { family, negated: false } => extras.push(format!("({family} only)")),
            Cond::TcpFlags { text } if text == "syn" => extras.push("(new TCP connections)".into()),
            other => extras.push(format!("where {}", cond_text(other, ctx))),
        }
    }
    // A port names its protocol; "TCP traffic" next to "SSH (tcp 22)" says nothing more.
    if !ports_seen.is_empty() {
        subject.retain(|s| {
            !(s.ends_with(" traffic") && ports_seen.iter().any(|p| s.starts_with(&p.to_uppercase())))
        });
    }
    let subject = if subject.is_empty() {
        if a.conds.is_empty() { "everything else".to_owned() } else { "traffic".to_owned() }
    } else {
        subject.join(", ")
    };
    let mut rest: Vec<String> = from;
    rest.extend(extras);
    if let Some(limit) = &a.limit {
        rest.push(if limit.starts_with("over") {
            format!("when {limit}")
        } else {
            format!("at most {limit}")
        });
    }
    let tail = if rest.is_empty() { String::new() } else { format!(" {}", rest.join(" ")) };
    let tail = tail.replace(" at most", ", at most").replace(" when over", ", when over");

    let logged = a.log.is_some() && a.verdict != V::None;
    let and_log = if logged { ", and log it" } else { "" };
    let mut text = match &a.verdict {
        V::Accept => format!("Allow {subject}{tail}"),
        V::Drop => format!("Block {subject}{tail}"),
        V::Reject => format!("Refuse {subject}{tail}"),
        V::Jump(chain) => format!("Check {subject}{tail} against chain {chain}"),
        V::Goto(chain) => format!("Hand {subject}{tail} over to chain {chain}"),
        V::Return => {
            if a.conds.is_empty() {
                "Go back to the chain that jumped here".into()
            } else {
                format!("Go back to the calling chain for {subject}{tail}")
            }
        }
        V::Continue => format!("Carry on past {subject}{tail}"),
        V::Queue => format!("Pass {subject}{tail} to a program (queue)"),
        V::Nat(target) => format!("Forward {subject}{tail} {target}"),
        V::None if a.log.is_some() => {
            if a.conds.is_empty() {
                "Log what reaches this point".into()
            } else {
                format!("Log {subject}{tail}")
            }
        }
        V::None if a.counter => {
            if a.conds.is_empty() {
                "Count what reaches this point".into()
            } else {
                format!("Count {subject}{tail}")
            }
        }
        V::None => format!("Match {subject}{tail}"),
    };
    text.push_str(and_log);
    if !a.other.is_empty() {
        text.push_str(&format!(" (also: {})", a.other.join(", ")));
    }
    text
}

/// What a chain's policy means for what reaches its end.
pub fn policy_words(hook: &str, policy: &str) -> String {
    let what = match hook {
        "input" => "incoming traffic",
        "forward" => "traffic passing through",
        "output" => "outgoing traffic",
        "prerouting" => "arriving packets",
        "postrouting" => "leaving packets",
        _ => "packets",
    };
    match policy {
        "drop" => format!("block {what} unless a rule allows it"),
        _ => format!("allow {what} unless a rule blocks it"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::tests::{archydots, rich};

    const SERVICES: &str =
        "ssh 22/tcp\nhttp 80/tcp\nhttps 443/tcp\ndomain 53/udp\nmdns 5353/udp\ndhcpv6-client 546/udp\n";

    fn sentences(r: &Ruleset, names: &Names, chain: &str) -> Vec<String> {
        let c = r.chains().find(|c| c.name == chain).unwrap();
        let ctx = Ctx { names, ruleset: r, family: &c.family, table: &c.table };
        c.rules.iter().map(|rule| sentence(&analyse(rule), &ctx)).collect()
    }

    #[test]
    fn archydots_in_words() {
        let names = Names::with(SERVICES, &[("192.168.10.0/24", "home LAN")], &[]);
        assert_eq!(
            sentences(&archydots(), &names, "input"),
            [
                "Block broken packets (invalid connection state)",
                "Allow replies to connections this machine started",
                "Allow this machine to talk to itself (loopback)",
                "Allow ping and other ICMP messages",
                "Allow DHCPv6 client (udp 546) from fe80::/10 (link-local)",
                "Allow SSH (tcp 22) from 192.168.10.0/24 (home LAN)",
                "Refuse packets sent to this machine, at most 5/second",
                "Count what reaches this point",
            ]
        );
    }

    #[test]
    fn rich_in_words() {
        let names = Names::with(SERVICES, &[], &[]);
        let r = rich();
        assert_eq!(
            sentences(&r, &names, "input"),
            [
                "Allow HTTP (tcp 80), HTTPS (tcp 443) or tcp 8000-8100 from set allowed (2 entries) (new connections)",
                "Check traffic arriving on wg0 against chain wg",
                "Block DNS (udp 53), and log it",
                "Refuse traffic except SSH (tcp 22) (new TCP connections)",
                "Allow mDNS (udp 5353) from anywhere except fe80::/10 (link-local)",
            ]
        );
        assert_eq!(sentences(&r, &names, "wg")[1], "Go back to the chain that jumped here");
        assert_eq!(sentences(&r, &names, "pre"), ["Forward tcp 8080 to 10.0.0.2:80"]);
    }

    #[test]
    fn verdicts_and_policies() {
        let r = archydots();
        let input = r.chain("inet", "filter", "input").unwrap();
        let verdicts: Vec<&str> = input.rules.iter().map(|r| analyse(r).verdict.label()).collect();
        assert_eq!(verdicts, ["BLOCK", "ALLOW", "ALLOW", "ALLOW", "ALLOW", "ALLOW", "REFUSE", ""]);
        assert_eq!(policy_words("input", "drop"), "block incoming traffic unless a rule allows it");
    }
}
