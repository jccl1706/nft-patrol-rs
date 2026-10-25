// SPDX-License-Identifier: GPL-3.0-or-later
//! Which listening ports the firewall lets the network reach.
//!
//! Every socket listening on this machine (from /proc/net, no root needed;
//! the program behind it needs root for other users' processes) is put to
//! the input chains as a new connection from somewhere else, once over IPv4
//! and once over IPv6. The walk follows jumps and policies the way the
//! kernel does; a rule that depends on the source address is collected
//! instead ("allowed from 192.168.10.0/24"), and one it cannot reason about
//! makes the answer "probably" rather than a guess passed off as fact.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::names::{Cidr, Names};
use crate::ruleset::{Chain, Ruleset};
use crate::words::{Analysis, Cond, Ctx, Dir, Verdict, analyse, sentence};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {
    /// tcp or udp
    pub proto: String,
    pub addr: IpAddr,
    pub port: u16,
    /// An IPv6 socket on :: that takes IPv4 too (the default).
    pub dual: bool,
    pub inode: u64,
}

/// One port as people think of it: a protocol, a port and its program,
/// on whatever addresses it is bound to.
#[derive(Debug, Clone)]
pub struct Service {
    pub proto: String,
    pub port: u16,
    pub name: Option<String>,
    /// The program and its PID, when it can be seen.
    pub process: Option<(String, u32)>,
    pub addrs: Vec<IpAddr>,
    /// Bound to loopback only: nothing else can reach it, firewall or not.
    pub local_only: bool,
    pub v4: Option<Reach>,
    pub v6: Option<Reach>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Anywhere,
    /// Only from these sources ("from 192.168.10.0/24 (home LAN)").
    From(Vec<String>),
    Nobody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reach {
    pub answer: Answer,
    /// What decided it, in words: a rule's sentence or a chain's policy.
    pub because: String,
    /// A rule on the way could not be reasoned about.
    pub unsure: bool,
}

impl Reach {
    pub fn short(&self) -> String {
        let text = match &self.answer {
            Answer::Anywhere => "anyone".to_owned(),
            Answer::Nobody => "nobody".to_owned(),
            Answer::From(sources) => sources.join(", "),
        };
        if self.unsure { format!("{text}?") } else { text }
    }
}

// --- sockets ---------------------------------------------------------------

/// An address as /proc/net prints it.
pub fn hex_addr(hex: &str, v6: bool) -> Option<IpAddr> {
    if v6 { hex_v6(hex) } else { hex_v4(hex) }
}

fn hex_v4(hex: &str) -> Option<IpAddr> {
    let n = u32::from_str_radix(hex, 16).ok()?;
    // /proc/net prints the address in host byte order (little-endian here).
    Some(IpAddr::V4(Ipv4Addr::from(n.swap_bytes())))
}

fn hex_v6(hex: &str) -> Option<IpAddr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for word in 0..4 {
        let n = u32::from_str_radix(&hex[word * 8..word * 8 + 8], 16).ok()?;
        bytes[word * 4..word * 4 + 4].copy_from_slice(&n.to_le_bytes());
    }
    Some(IpAddr::V6(Ipv6Addr::from(bytes)))
}

/// Listening sockets in one /proc/net table.
pub fn parse_proc(text: &str, proto: &str, v6: bool, dual_default: bool) -> Vec<Socket> {
    let mut sockets = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        // TCP: 0A is LISTEN. UDP has no listening state; 07 is an unconnected
        // socket, which is what a UDP server is.
        let wanted = if proto == "tcp" { "0A" } else { "07" };
        if f[3] != wanted {
            continue;
        }
        let Some((addr, port)) = f[1].split_once(':') else { continue };
        let addr = if v6 { hex_v6(addr) } else { hex_v4(addr) };
        let (Some(addr), Ok(port)) = (addr, u16::from_str_radix(port, 16)) else { continue };
        let dual = v6 && addr.is_unspecified() && dual_default;
        sockets.push(Socket { proto: proto.to_owned(), addr, port, dual, inode: f[9].parse().unwrap_or(0) });
    }
    sockets
}

pub fn sockets() -> Vec<Socket> {
    // net.ipv6.bindv6only=0, the default, makes a socket on :: take IPv4 as
    // well; a program can opt out, which /proc does not show.
    let dual =
        std::fs::read_to_string("/proc/sys/net/ipv6/bindv6only").map(|v| v.trim() == "0").unwrap_or(true);
    let mut all = Vec::new();
    for (file, proto, v6) in
        [("tcp", "tcp", false), ("tcp6", "tcp", true), ("udp", "udp", false), ("udp6", "udp", true)]
    {
        if let Ok(text) = std::fs::read_to_string(format!("/proc/net/{file}")) {
            all.extend(parse_proc(&text, proto, v6, dual));
        }
    }
    all
}

/// Socket inode -> (program, PID), for the processes this user can see.
fn owners() -> HashMap<u64, (String, u32)> {
    let mut map = HashMap::new();
    let Ok(procs) = std::fs::read_dir("/proc") else { return map };
    for p in procs.flatten() {
        let Ok(pid) = p.file_name().to_string_lossy().parse::<u32>() else { continue };
        let Ok(fds) = std::fs::read_dir(p.path().join("fd")) else { continue };
        let comm = std::fs::read_to_string(p.path().join("comm")).unwrap_or_default().trim().to_owned();
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path())
                && let Some(inode) =
                    target.to_str().and_then(|t| t.strip_prefix("socket:[")?.strip_suffix(']'))
                && let Ok(inode) = inode.parse()
            {
                map.entry(inode).or_insert_with(|| (comm.clone(), pid));
            }
        }
    }
    map
}

/// Sockets grouped into services, sorted by protocol and port.
pub fn services(sockets: &[Socket], names: &Names, ruleset: &Ruleset) -> Vec<Service> {
    let owners = owners();
    type Group<'a> = ((String, u16, Option<(String, u32)>), Vec<&'a Socket>);
    let mut groups: BTreeMap<_, Vec<&Socket>> = BTreeMap::new();
    for s in sockets {
        let owner = owners.get(&s.inode).cloned();
        groups.entry((s.proto.clone(), s.port, owner)).or_default().push(s);
    }
    groups
        .into_iter()
        .map(|((proto, port, process), socks): Group| {
            let local_only = socks.iter().all(|s| s.addr.is_loopback());
            let takes_v4 = socks.iter().any(|s| !s.addr.is_loopback() && (s.addr.is_ipv4() || s.dual));
            let takes_v6 = socks.iter().any(|s| !s.addr.is_loopback() && s.addr.is_ipv6());
            let mut addrs: Vec<IpAddr> = socks.iter().map(|s| s.addr).collect();
            addrs.sort();
            addrs.dedup();
            Service {
                name: names.service(port, &proto),
                v4: takes_v4.then(|| reach(ruleset, names, &proto, port, false)),
                v6: takes_v6.then(|| reach(ruleset, names, &proto, port, true)),
                proto,
                port,
                process,
                addrs,
                local_only,
            }
        })
        .collect()
}

// --- the walk --------------------------------------------------------------

/// A new connection from elsewhere to this machine.
#[derive(Debug, Clone, Copy)]
struct Packet<'a> {
    proto: &'a str,
    port: u16,
    v6: bool,
    /// A known source address, which decides source conditions outright.
    src: Option<IpAddr>,
}

enum Matched {
    No,
    Yes,
    /// Only for some sources, described.
    From(String),
    Unsure,
}

fn port_in(ports: &[String], port: u16, ctx: &Ctx) -> Option<bool> {
    let mut found = false;
    for p in ports {
        if let Some(name) = p.strip_prefix('@') {
            let set = ctx.ruleset.set(ctx.family, ctx.table, name)?;
            found |= port_in(&set.elements, port, ctx)?;
        } else if let Some((a, b)) = p.split_once('-') {
            let (a, b) = (a.parse::<u16>().ok()?, b.parse::<u16>().ok()?);
            found |= (a..=b).contains(&port);
        } else {
            found |= p.parse::<u16>().ok()? == port;
        }
    }
    Some(found)
}

fn proto_matches(protos: &[String], proto: &str) -> bool {
    protos.iter().any(|p| p == proto || (proto == "tcp" && p == "6") || (proto == "udp" && p == "17"))
}

fn matches(a: &Analysis, packet: Packet, ctx: &Ctx) -> Matched {
    let mut sources = Vec::new();
    let mut unsure = false;
    for cond in &a.conds {
        let ok = match cond {
            Cond::State { states, negated } => states.iter().any(|s| s == "new") != *negated,
            Cond::Iface { names, negated, incoming: true } => {
                if names.iter().all(|n| n == "lo") {
                    // Traffic from elsewhere never arrives on loopback.
                    *negated
                } else {
                    let not = if *negated { "not " } else { "" };
                    sources.push(format!("{not}arriving on {}", names.join(" or ")));
                    true
                }
            }
            Cond::Iface { incoming: false, .. } => false,
            Cond::Proto { protos, negated } => proto_matches(protos, packet.proto) != *negated,
            Cond::Family { family, negated } => {
                (family == if packet.v6 { "ipv6" } else { "ipv4" }) != *negated
            }
            Cond::PktType { types, negated } => types.iter().any(|t| t == "host") != *negated,
            Cond::Port { proto, dir: Dir::Dst, ports, negated } => {
                if proto != packet.proto && proto != "th" {
                    false
                } else {
                    match port_in(ports, packet.port, ctx) {
                        Some(found) => found != *negated,
                        None => {
                            unsure = true;
                            true
                        }
                    }
                }
            }
            // The other end picks its own source port.
            Cond::Port { proto, dir: Dir::Src, .. } => {
                unsure = true;
                proto == packet.proto || proto == "th"
            }
            Cond::Addr { family, dir, values, negated } => {
                if (family == "ip6") != packet.v6 {
                    false
                } else if *dir == Dir::Dst {
                    // Usually this machine's own address; can't be sure.
                    unsure = true;
                    true
                } else if let Some(src) = packet.src {
                    match addr_in(values, src, ctx) {
                        Some(found) => found != *negated,
                        None => {
                            unsure = true;
                            true
                        }
                    }
                } else {
                    let names: Vec<String> = values.iter().map(|v| ctx_value(ctx, v)).collect();
                    sources.push(if *negated {
                        format!("anywhere except {}", names.join(", "))
                    } else {
                        names.join(", ")
                    });
                    true
                }
            }
            Cond::TcpFlags { text } => packet.proto == "tcp" && text.contains("syn"),
            Cond::Other { .. } => {
                unsure = true;
                true
            }
        };
        if !ok {
            return Matched::No;
        }
    }
    if unsure {
        Matched::Unsure
    } else if sources.is_empty() {
        Matched::Yes
    } else {
        Matched::From(sources.join(", "))
    }
}

/// Whether `src` is one of `values` (addresses, ranges, sets); None if a
/// value cannot be read.
fn addr_in(values: &[String], src: IpAddr, ctx: &Ctx) -> Option<bool> {
    let host = Cidr::parse(&src.to_string())?;
    let mut found = false;
    for v in values {
        if let Some(name) = v.strip_prefix('@') {
            let set = ctx.ruleset.set(ctx.family, ctx.table, name)?;
            found |= addr_in(&set.elements, src, ctx)?;
        } else if let Some((a, b)) = v.split_once('-') {
            let (a, b): (IpAddr, IpAddr) = (a.parse().ok()?, b.parse().ok()?);
            found |= a <= src && src <= b;
        } else {
            found |= Cidr::parse(v)?.contains(&host);
        }
    }
    Some(found)
}

fn ctx_value(ctx: &Ctx, value: &str) -> String {
    match value.strip_prefix('@') {
        Some(name) => format!("set {name}"),
        None => ctx.names.address(value),
    }
}

enum End {
    Accept(String),
    Drop(String),
    /// Ran off the end of a regular chain, or returned.
    Back,
}

struct Walk {
    /// Sources an accept rule let in, with that rule's sentence.
    allowed: Vec<(String, String)>,
    unsure: bool,
}

const MAX_DEPTH: usize = 16;

fn walk(chain: &Chain, ruleset: &Ruleset, names: &Names, packet: Packet, w: &mut Walk, depth: usize) -> End {
    let ctx = Ctx { names, ruleset, family: &chain.family, table: &chain.table };
    if depth > MAX_DEPTH {
        w.unsure = true;
        return End::Back;
    }
    for rule in &chain.rules {
        let a = analyse(rule);
        let words = || sentence(&a, &ctx);
        match matches(&a, packet, &ctx) {
            Matched::No => continue,
            Matched::Unsure => {
                // Assume it doesn't match, and say the answer is uncertain - unless
                // it would only ever have narrowed things down.
                if a.verdict != Verdict::None {
                    w.unsure = true;
                }
                continue;
            }
            Matched::From(source) => {
                if a.verdict == Verdict::Accept {
                    w.allowed.push((source, words()));
                } else if matches!(a.verdict, Verdict::Jump(_) | Verdict::Goto(_)) {
                    w.unsure = true;
                }
                continue;
            }
            Matched::Yes => {}
        }
        match &a.verdict {
            Verdict::Accept => return End::Accept(words()),
            Verdict::Drop | Verdict::Reject => return End::Drop(words()),
            Verdict::Return => return End::Back,
            Verdict::Jump(target) | Verdict::Goto(target) => {
                let Some(next) = ruleset.chain(&chain.family, &chain.table, target) else {
                    w.unsure = true;
                    continue;
                };
                match walk(next, ruleset, names, packet, w, depth + 1) {
                    End::Back if matches!(a.verdict, Verdict::Jump(_)) => continue,
                    End::Back => return End::Back,
                    end => return end,
                }
            }
            Verdict::Queue | Verdict::Nat(_) => {
                w.unsure = true;
                return End::Back;
            }
            Verdict::Continue | Verdict::None => continue,
        }
    }
    End::Back
}

/// Whether a new connection to `proto`/`port` gets in, and from where.
pub fn reach(ruleset: &Ruleset, names: &Names, proto: &str, port: u16, v6: bool) -> Reach {
    walk_all(ruleset, names, Packet { proto, port, v6, src: None })
}

/// Whether a new connection from `src` to `proto`/`port` gets in. Only an
/// interface condition can leave it open ("From"), and that counts as in.
pub fn admits(ruleset: &Ruleset, names: &Names, proto: &str, port: u16, src: IpAddr) -> Reach {
    let src = match src {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(src),
        v4 => v4,
    };
    walk_all(ruleset, names, Packet { proto, port, v6: src.is_ipv6(), src: Some(src) })
}

fn walk_all(ruleset: &Ruleset, names: &Names, packet: Packet) -> Reach {
    let v6 = packet.v6;
    let family_ok = |c: &&Chain| match c.family.as_str() {
        "inet" => true,
        "ip" => !v6,
        "ip6" => v6,
        _ => false,
    };
    let chains: Vec<&Chain> = ruleset.hooked("input").into_iter().filter(family_ok).collect();
    if chains.is_empty() {
        return Reach {
            answer: Answer::Anywhere,
            because: "no input chain: nothing is filtered".into(),
            unsure: false,
        };
    }
    // Every input chain must accept for the packet to get in.
    let mut result = Reach { answer: Answer::Anywhere, because: String::new(), unsure: false };
    for chain in chains {
        let mut w = Walk { allowed: Vec::new(), unsure: false };
        let base = chain.base.as_ref().expect("hooked chains are base chains");
        let end = match walk(chain, ruleset, names, packet, &mut w, 0) {
            End::Back if base.policy == "drop" => End::Drop(format!("{} blocks by default", chain.path())),
            End::Back => End::Accept(format!("{} allows by default", chain.path())),
            end => end,
        };
        result.unsure |= w.unsure;
        let (answer, because) = match end {
            End::Accept(why) => (Answer::Anywhere, why),
            End::Drop(why) if w.allowed.is_empty() => (Answer::Nobody, why),
            End::Drop(_) => {
                let because = w.allowed.iter().map(|(_, why)| why.clone()).collect::<Vec<_>>().join("; ");
                (Answer::From(w.allowed.into_iter().map(|(source, _)| source).collect()), because)
            }
            End::Back => unreachable!(),
        };
        match (&result.answer, answer) {
            (_, Answer::Nobody) => return Reach { answer: Answer::Nobody, because, unsure: result.unsure },
            (Answer::Anywhere, answer) => {
                result.answer = answer;
                result.because = because;
            }
            // Two chains each allowing some sources: keep the first, mark it.
            (Answer::From(_), Answer::From(_)) => result.unsure = true,
            (Answer::From(_), Answer::Anywhere) | (Answer::Nobody, _) => {}
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::tests::{archydots, rich};

    const TCP: &str =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4113 1 0
   1: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5120 1 0
   2: 250AA8C0:0016 6E0AA8C0:C350 01 00000000:00000000 00:00000000 00000000     0        0 7000 1 0
";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4115 1 0
   1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5121 1 0
";

    #[test]
    fn proc_net() {
        let v4 = parse_proc(TCP, "tcp", false, true);
        assert_eq!(v4.len(), 2, "the established connection is not a listener");
        assert_eq!(v4[0].addr, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(v4[0].port, 22);
        assert_eq!(v4[1].addr, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(v4[1].port, 631);
        let v6 = parse_proc(TCP6, "tcp", true, true);
        assert!(v6[0].dual && v6[0].addr.is_unspecified());
        assert_eq!(v6[1].addr, "::1".parse::<IpAddr>().unwrap());
        assert!(!v6[1].dual);
    }

    #[test]
    fn ssh_on_archydots() {
        let names = Names::with("ssh 22/tcp\n", &[("192.168.10.0/24", "home LAN")], &[]);
        let r = archydots();
        let v4 = reach(&r, &names, "tcp", 22, false);
        assert_eq!(v4.answer, Answer::From(vec!["192.168.10.0/24 (home LAN)".into()]));
        assert!(!v4.unsure);
        assert_eq!(v4.because, "Allow SSH (tcp 22) from 192.168.10.0/24 (home LAN)");
        let v6 = reach(&r, &names, "tcp", 22, true);
        assert_eq!(v6.answer, Answer::Nobody);
        assert_eq!(v6.because, "Refuse packets sent to this machine, at most 5/second");
        assert_eq!(
            reach(&r, &names, "udp", 546, true).answer,
            Answer::From(vec!["fe80::/10 (link-local)".into()])
        );
        assert_eq!(reach(&r, &names, "tcp", 8080, false).answer, Answer::Nobody);
    }

    #[test]
    fn rich_rules() {
        let names = Names::with("", &[], &[]);
        let r = rich();
        // Allowed only from a set, then refused by the SYN rule.
        assert_eq!(reach(&r, &names, "tcp", 443, false).answer, Answer::From(vec!["set allowed".into()]));
        // The jump to wg depends on the interface: a source, not a verdict.
        let wg = reach(&r, &names, "tcp", 22, false);
        assert_eq!(wg.answer, Answer::Anywhere, "{wg:?}");
        assert!(wg.unsure, "a jump that depends on the interface leaves doubt");
        assert_eq!(reach(&r, &names, "udp", 53, false).answer, Answer::Nobody);
        // ip6 saddr != fe80::/10 means nothing to IPv4: the policy accepts.
        assert_eq!(reach(&r, &names, "udp", 5353, false).answer, Answer::Anywhere);
        assert_eq!(
            reach(&r, &names, "udp", 5353, true).answer,
            Answer::Anywhere,
            "accepted from everywhere but link-local, and the policy accepts the rest"
        );
    }

    #[test]
    fn one_source() {
        let names = Names::with("", &[], &[]);
        let r = archydots();
        let from = |a: &str| admits(&r, &names, "tcp", 22, a.parse().unwrap()).answer;
        assert_eq!(from("192.168.10.20"), Answer::Anywhere);
        assert_eq!(from("::ffff:192.168.10.20"), Answer::Anywhere, "an IPv4 client on a dual-stack socket");
        assert_eq!(from("192.168.40.5"), Answer::Nobody);
        assert_eq!(from("fe80::1"), Answer::Nobody);
        let rich = rich();
        let rich_from = |a: &str| admits(&rich, &names, "tcp", 443, a.parse().unwrap()).answer;
        assert_eq!(rich_from("10.1.2.3"), Answer::Anywhere, "in set allowed");
        assert_eq!(rich_from("192.168.1.1"), Answer::Nobody);
    }

    #[test]
    fn no_firewall() {
        let r = Ruleset::default();
        let reach = reach(&r, &Names::default(), "tcp", 22, false);
        assert_eq!(reach.answer, Answer::Anywhere);
    }
}
