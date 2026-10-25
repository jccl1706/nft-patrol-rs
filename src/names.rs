// SPDX-License-Identifier: GPL-3.0-or-later
//! Names for numbers: services for ports, networks for addresses.
//!
//! Ports come from /etc/services, with the common ones spelled the way
//! people say them (SSH, DNS, mDNS). An address range is named, in order:
//! by the configuration's `[networks]`, as the network an interface is on
//! right now ("the network on wlan0"), or as a well-known range (private,
//! link-local, loopback, Tailscale).

use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Default)]
pub struct Names {
    /// (port, "tcp"/"udp") -> service name
    services: HashMap<(u16, String), String>,
    /// Named in the configuration.
    networks: Vec<(Cidr, String)>,
    /// What each interface is connected to now: (its network, interface).
    local: Vec<(Cidr, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub len: u8,
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

impl Cidr {
    pub fn parse(text: &str) -> Option<Cidr> {
        let (addr, len) = match text.split_once('/') {
            Some((a, l)) => (a.parse::<IpAddr>().ok()?, l.parse().ok()?),
            None => {
                let addr: IpAddr = text.parse().ok()?;
                (addr, if addr.is_ipv4() { 32 } else { 128 })
            }
        };
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (len <= max).then(|| Cidr { addr, len }.network())
    }

    fn bits(addr: IpAddr) -> (u128, u8) {
        match addr {
            IpAddr::V4(a) => (u32::from(a) as u128, 32),
            IpAddr::V6(a) => (u128::from(a), 128),
        }
    }

    fn mask(&self) -> u128 {
        let (_, width) = Cidr::bits(self.addr);
        if self.len == 0 { 0 } else { (!0u128 << (width - self.len)) & (!0u128 >> (128 - width)) }
    }

    /// The same range with the host bits cleared.
    pub fn network(self) -> Cidr {
        let (bits, _) = Cidr::bits(self.addr);
        let net = bits & self.mask();
        let addr = match self.addr {
            IpAddr::V4(_) => IpAddr::V4((net as u32).into()),
            IpAddr::V6(_) => IpAddr::V6(net.into()),
        };
        Cidr { addr, len: self.len }
    }

    /// Whether `other` lies entirely inside this range.
    pub fn contains(&self, other: &Cidr) -> bool {
        self.addr.is_ipv4() == other.addr.is_ipv4()
            && other.len >= self.len
            && Cidr::bits(other.addr).0 & self.mask() == Cidr::bits(self.addr).0 & self.mask()
    }
}

/// Well-known ranges, most specific first.
const KNOWN: [(&str, &str); 9] = [
    ("127.0.0.0/8", "loopback"),
    ("::1/128", "loopback"),
    ("169.254.0.0/16", "link-local"),
    ("fe80::/10", "link-local"),
    ("100.64.0.0/10", "Tailscale / carrier-grade NAT"),
    ("10.0.0.0/8", "private network"),
    ("172.16.0.0/12", "private network"),
    ("192.168.0.0/16", "private network"),
    ("fc00::/7", "private network"),
];

/// How a service is usually written, where it differs from /etc/services.
fn pretty(service: &str) -> String {
    match service {
        "domain" => "DNS".into(),
        "mdns" => "mDNS".into(),
        "bootps" => "DHCP server".into(),
        "bootpc" => "DHCP client".into(),
        "dhcpv6-client" => "DHCPv6 client".into(),
        "dhcpv6-server" => "DHCPv6 server".into(),
        "llmnr" => "LLMNR".into(),
        "microsoft-ds" => "SMB".into(),
        "netbios-ns" | "netbios-dgm" | "netbios-ssn" => "NetBIOS".into(),
        "http-alt" | "webcache" => "HTTP-alt".into(),
        "ipp" => "IPP printing".into(),
        "ms-wbt-server" => "RDP".into(),
        "kdeconnect" => "KDE Connect".into(),
        "wireguard" => "WireGuard".into(),
        s if s.len() <= 5 && s.chars().all(|c| c.is_ascii_lowercase()) => s.to_uppercase(),
        s => s.to_owned(),
    }
}

impl Names {
    pub fn load(networks: &[(String, String)]) -> Names {
        let mut names = Names {
            services: std::fs::read_to_string("/etc/services")
                .map(|t| parse_services(&t))
                .unwrap_or_default(),
            ..Names::default()
        };
        names.networks = networks.iter().filter_map(|(n, c)| Some((Cidr::parse(c)?, n.clone()))).collect();
        names.local = local_networks();
        names
    }

    /// For tests: no files, no interfaces.
    #[cfg(test)]
    pub fn with(services: &str, networks: &[(&str, &str)], local: &[(&str, &str)]) -> Names {
        let pairs = |list: &[(&str, &str)]| {
            list.iter().filter_map(|(c, n)| Some((Cidr::parse(c)?, n.to_string()))).collect()
        };
        Names { services: parse_services(services), networks: pairs(networks), local: pairs(local) }
    }

    /// `SSH`, `DNS`; None for an unknown port.
    pub fn service(&self, port: u16, proto: &str) -> Option<String> {
        let proto = if proto == "tcp" || proto == "udp" { proto } else { "tcp" };
        self.services.get(&(port, proto.to_owned())).map(|s| pretty(s))
    }

    /// The networks a rule can be limited to, for the form: the named ones,
    /// then those the interfaces are on now. (label, range)
    pub fn choices(&self) -> Vec<(String, String)> {
        let mut list: Vec<(String, String)> =
            self.networks.iter().map(|(c, n)| (format!("{n} ({c})"), c.to_string())).collect();
        for (cidr, iface) in &self.local {
            let range = cidr.network().to_string();
            if !list.iter().any(|(_, r)| *r == range) {
                list.push((format!("the network on {iface} ({range})"), range));
            }
        }
        list
    }

    /// What an address or range is, or None if nothing is known about it.
    pub fn network(&self, text: &str) -> Option<String> {
        let cidr = Cidr::parse(text)?;
        if let Some((_, name)) = self.networks.iter().find(|(c, _)| *c == cidr) {
            return Some(name.clone());
        }
        if let Some((_, iface)) = self.local.iter().find(|(c, _)| *c == cidr) {
            return Some(format!("the network on {iface}"));
        }
        if let Some((_, name)) = self.networks.iter().find(|(c, _)| c.contains(&cidr)) {
            return Some(format!("part of {name}"));
        }
        if let Some((_, iface)) = self.local.iter().find(|(c, _)| c.contains(&cidr)) {
            return Some(format!("part of the network on {iface}"));
        }
        KNOWN.iter().find_map(|(range, name)| {
            let range = Cidr::parse(range)?;
            if range == cidr {
                Some(name.to_string())
            } else if range.contains(&cidr) {
                Some(format!("in a {name}"))
            } else {
                None
            }
        })
    }

    /// An address with its name: `192.168.10.0/24 (the network on wlan0)`.
    pub fn address(&self, text: &str) -> String {
        match self.network(text) {
            Some(name) => format!("{text} ({name})"),
            None => text.to_owned(),
        }
    }
}

fn parse_services(text: &str) -> HashMap<(u16, String), String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default();
        let mut words = line.split_whitespace();
        let (Some(name), Some(port)) = (words.next(), words.next()) else { continue };
        let Some((port, proto)) = port.split_once('/') else { continue };
        let Ok(port) = port.parse() else { continue };
        // The first name listed for a port is the usual one.
        map.entry((port, proto.to_owned())).or_insert_with(|| name.to_owned());
    }
    map
}

/// Each interface's networks, from `ip -j address`; empty if ip is missing.
fn local_networks() -> Vec<(Cidr, String)> {
    let Ok(output) = std::process::Command::new("ip").args(["-j", "address"]).output() else {
        return Vec::new();
    };
    let Ok(links) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else { return Vec::new() };
    let mut networks = Vec::new();
    for link in links.as_array().into_iter().flatten() {
        let iface = link["ifname"].as_str().unwrap_or_default();
        if iface == "lo" {
            continue;
        }
        for info in link["addr_info"].as_array().into_iter().flatten() {
            let (Some(local), Some(len)) = (info["local"].as_str(), info["prefixlen"].as_u64()) else {
                continue;
            };
            if let Some(cidr) = Cidr::parse(&format!("{local}/{len}"))
                && !cidr.addr.is_loopback()
                && !(cidr.addr.is_ipv6() && Cidr::parse("fe80::/10").unwrap().contains(&cidr))
            {
                networks.push((cidr, iface.to_owned()));
            }
        }
    }
    networks
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICES: &str = "ssh 22/tcp\nssh 22/udp\ndomain 53/tcp\ndomain 53/udp\nmdns 5353/udp # Multicast DNS\nhttps 443/tcp\nsunrpc 111/tcp portmapper\n";

    #[test]
    fn cidrs() {
        let lan = Cidr::parse("192.168.10.0/24").unwrap();
        assert!(lan.contains(&Cidr::parse("192.168.10.7").unwrap()));
        assert!(!lan.contains(&Cidr::parse("192.168.11.7").unwrap()));
        assert!(!lan.contains(&Cidr::parse("fe80::1").unwrap()));
        assert_eq!(Cidr::parse("192.168.10.37/24").unwrap(), lan);
        assert!(Cidr::parse("fe80::/10").unwrap().contains(&Cidr::parse("fe80::1:2/64").unwrap()));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(&lan));
        assert_eq!(Cidr::parse("10.0.0.0/33"), None);
    }

    #[test]
    fn services() {
        let n = Names::with(SERVICES, &[], &[]);
        assert_eq!(n.service(22, "tcp").as_deref(), Some("SSH"));
        assert_eq!(n.service(53, "udp").as_deref(), Some("DNS"));
        assert_eq!(n.service(5353, "udp").as_deref(), Some("mDNS"));
        assert_eq!(n.service(111, "tcp").as_deref(), Some("sunrpc"));
        assert_eq!(n.service(9999, "tcp"), None);
    }

    #[test]
    fn networks() {
        let n = Names::with("", &[("192.168.10.0/24", "home LAN")], &[("192.168.40.10/24", "wlan0")]);
        assert_eq!(n.address("192.168.10.0/24"), "192.168.10.0/24 (home LAN)");
        assert_eq!(n.network("192.168.10.5").as_deref(), Some("part of home LAN"));
        assert_eq!(n.network("192.168.40.0/24").as_deref(), Some("the network on wlan0"));
        assert_eq!(n.network("192.168.99.0/24").as_deref(), Some("in a private network"));
        assert_eq!(n.network("fe80::/10").as_deref(), Some("link-local"));
        assert_eq!(n.network("8.8.8.8"), None);
        assert_eq!(n.network("@allowed"), None);
        let choices: Vec<String> = n.choices().into_iter().map(|(_, r)| r).collect();
        assert_eq!(choices, ["192.168.10.0/24", "192.168.40.0/24"]);
    }
}
