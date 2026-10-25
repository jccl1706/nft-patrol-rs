// SPDX-License-Identifier: GPL-3.0-or-later
//! Logged packets, from the kernel's messages in the journal.
//!
//! A rule with `log` makes the kernel write one line per packet:
//!
//! ```text
//! nft-patrol drop: IN=wlan0 OUT= MAC=... SRC=192.168.10.20 DST=192.168.10.37 ... PROTO=TCP SPT=50112 DPT=8080 ...
//! ```
//!
//! Only those lines are read (`journalctl -k`, which needs the wheel or
//! systemd-journal group, or root). Nothing is logged until a rule asks
//! for it, so with no log rule the list stays empty and says why.

use std::process::Command;

use chrono::{DateTime, Local, TimeZone};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub time: DateTime<Local>,
    /// The rule's log prefix, trimmed.
    pub prefix: String,
    pub iface: String,
    pub src: String,
    pub dst: String,
    pub proto: String,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    pub message: String,
}

/// The fields of one kernel log line; None if it is not a packet log.
pub fn parse_line(message: &str, time: DateTime<Local>) -> Option<Packet> {
    let start = message.find("IN=")?;
    let field = |name: &str| {
        message[start..]
            .split_whitespace()
            .find_map(|w| w.strip_prefix(name)?.strip_prefix('='))
            .unwrap_or_default()
            .to_owned()
    };
    let src = field("SRC");
    if src.is_empty() {
        return None;
    }
    Some(Packet {
        time,
        prefix: message[..start].trim().trim_end_matches(':').trim().to_owned(),
        iface: field("IN"),
        src,
        dst: field("DST"),
        proto: field("PROTO"),
        sport: field("SPT").parse().ok(),
        dport: field("DPT").parse().ok(),
        message: message.to_owned(),
    })
}

/// The newest logged packets, newest first, at most `limit`.
pub fn recent(limit: usize) -> Result<Vec<Packet>, String> {
    let output = Command::new("journalctl")
        .args(["-k", "-o", "json", "--no-pager", "-r", "-n", &limit.to_string(), "-g", "IN=.* SRC="])
        .output()
        .map_err(|e| format!("journalctl: {e}"))?;
    // journalctl exits 1 when the grep finds nothing.
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() && stdout.trim().is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if stderr.is_empty() || stderr.contains("No entries") {
            return Ok(Vec::new());
        }
        if stderr.contains("not seeing messages") || stderr.contains("ermission") {
            return Err("the kernel log needs root, or the wheel or systemd-journal group".into());
        }
        return Err(format!("journalctl: {stderr}"));
    }
    let mut packets = Vec::new();
    for line in stdout.lines() {
        let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        let Some(message) = entry["MESSAGE"].as_str() else { continue };
        let micros: i64 = entry["__REALTIME_TIMESTAMP"].as_str().and_then(|t| t.parse().ok()).unwrap_or(0);
        let Some(time) = Local.timestamp_micros(micros).single() else { continue };
        if let Some(p) = parse_line(message, time) {
            packets.push(p);
        }
    }
    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_logged_packet() {
        let t = Local.timestamp_opt(1_800_000_000, 0).unwrap();
        let line = "nft-patrol drop: IN=wlan0 OUT= MAC=aa:bb SRC=192.168.10.20 DST=192.168.10.37 LEN=60 \
                    TOS=0x00 PREC=0x00 TTL=64 ID=1 DF PROTO=TCP SPT=50112 DPT=8080 WINDOW=64240 RES=0x00 SYN URGP=0";
        let p = parse_line(line, t).unwrap();
        assert_eq!(p.prefix, "nft-patrol drop");
        assert_eq!((p.iface.as_str(), p.src.as_str(), p.proto.as_str()), ("wlan0", "192.168.10.20", "TCP"));
        assert_eq!((p.sport, p.dport), (Some(50112), Some(8080)));
        let icmp = parse_line("IN=eth0 OUT= SRC=fe80::1 DST=ff02::1 PROTO=ICMPv6 TYPE=134", t).unwrap();
        assert_eq!((icmp.prefix.as_str(), icmp.dport), ("", None));
        assert!(parse_line("usb 3-1: new device", t).is_none());
    }
}
