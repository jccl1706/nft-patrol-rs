// SPDX-License-Identifier: GPL-3.0-or-later
//! Applying a change so that a mistake undoes itself.
//!
//! 1. The rewritten table is checked by `nft -c`, then loaded with the rest
//!    of the live ruleset into a private network namespace, and exposure is
//!    worked out there: the review shows which ports open or close, and
//!    whether a machine connected over SSH right now could log in again.
//! 2. Before applying, the table as it is goes to /run/nft-patrol/revert.nft
//!    and a systemd timer is started to load it back in 30 seconds. The timer
//!    belongs to systemd, not to this process: if the change cuts the SSH
//!    session the dashboard runs in, or the dashboard dies, it still fires.
//! 3. The change is applied: one nft transaction.
//! 4. Keeping it stops the timer and writes /etc/nftables.conf (the old one
//!    kept as /etc/nftables.conf.nft-patrol.bak). Not keeping it, or not
//!    answering, loads the old table back.

use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use crate::edit::{Change, rewrite};
use crate::error::Result;
use crate::exposure::{self, Answer, Reach};
use crate::names::Names;
use crate::ruleset::{self, ChainKey, Ruleset};
use crate::source::SAVED;
use crate::{App, bail, err};

pub const RUN_DIR: &str = "/run/nft-patrol";
const REVERT: &str = "/run/nft-patrol/revert.nft";
/// Which table is waiting: "family name".
const PENDING: &str = "/run/nft-patrol/pending";
const UNIT: &str = "nft-patrol-revert";
pub const BACKUP: &str = "/etc/nftables.conf.nft-patrol.bak";
/// How long a change has to be kept before it undoes itself.
pub const GRACE: Duration = Duration::from_secs(30);

fn run(program: &str, args: &[&str], stdin: Option<&str>) -> Result<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| err!("{program}: {e}"))?;
    if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
        pipe.write_all(text.as_bytes()).map_err(|e| err!("{program}: {e}"))?;
    }
    let out = child.wait_with_output().map_err(|e| err!("{program}: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("{}", stderr.trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn nft(args: &[&str], stdin: Option<&str>) -> Result<String> {
    run("nft", args, stdin).map_err(|e| err!("nft: {e}"))
}

/// One table, without counters, as nft would load it.
fn table_text(key: &ChainKey) -> Result<String> {
    nft(&["-s", "list", "table", &key.family, &key.table], None)
}

/// What a change would do, worked out before anything is touched.
pub struct Plan {
    pub change: Change,
    pub script: String,
    pub revert: String,
    /// The rule's line, before and after: "- ..." and "+ ...".
    pub diff: Vec<String>,
    /// Ports whose reach changes: "tcp 22 IPv4: only home LAN → anyone".
    pub exposure: Vec<String>,
    /// Serious: a machine connected over SSH now could not log in again.
    pub warnings: Vec<String>,
    /// The preview could not be worked out (and why).
    pub unpredicted: Option<String>,
}

/// SSH clients connected right now: (their address, our port).
fn ssh_clients() -> Vec<(IpAddr, u16)> {
    let mut clients = Vec::new();
    for (file, v6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        let Ok(text) = std::fs::read_to_string(file) else { continue };
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            // 01: established
            if f.len() < 4 || f[3] != "01" {
                continue;
            }
            let local_port = f[1].rsplit(':').next().and_then(|p| u16::from_str_radix(p, 16).ok());
            if local_port != Some(22) {
                continue;
            }
            let remote = f[2].rsplit_once(':').map(|(a, _)| a);
            if let Some(addr) = remote.and_then(|a| exposure::hex_addr(a, v6)) {
                let addr = match addr {
                    IpAddr::V6(a) => a.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(addr),
                    a => a,
                };
                if !addr.is_loopback() && !clients.iter().any(|(c, _)| *c == addr) {
                    clients.push((addr, 22));
                }
            }
        }
    }
    clients
}

/// The live ruleset with the change made, in a private namespace.
fn predict(script: &str) -> Result<Ruleset> {
    let full = nft(&["-s", "list", "ruleset"], None)?;
    let dir = std::env::temp_dir().join(format!("nft-patrol-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| err!("{}: {e}", dir.display()))?;
    let (a, b) = (dir.join("live.nft"), dir.join("change.nft"));
    let written = std::fs::write(&a, &full).and_then(|()| std::fs::write(&b, script));
    let result = written.map_err(|e| err!("{e}")).and_then(|()| {
        let sep = "--nft-patrol--";
        let out = run(
            "unshare",
            &[
                "--user",
                "--map-root-user",
                "--net",
                "sh",
                "-c",
                &format!("nft -f \"$1\" && nft -f \"$2\" && nft -j list ruleset && echo {sep} && nft -a list ruleset"),
                "sh",
                &a.to_string_lossy(),
                &b.to_string_lossy(),
            ],
            None,
        )?;
        let (json, text) = out.split_once(&format!("{sep}\n")).ok_or_else(|| err!("the preview was cut short"))?;
        ruleset::parse(json, text)
    });
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn reach_words(r: &Reach) -> String {
    match &r.answer {
        Answer::Anywhere => "anyone".into(),
        Answer::Nobody => "nobody".into(),
        Answer::From(s) => format!("only {}", s.join(", ")),
    }
}

/// The ports whose reach the change moves.
fn exposure_changes(before: &Ruleset, after: &Ruleset, names: &Names) -> Vec<String> {
    let sockets = exposure::sockets();
    let old = exposure::services(&sockets, names, before);
    let new = exposure::services(&sockets, names, after);
    let mut changes = Vec::new();
    for (o, n) in old.iter().zip(&new) {
        for (family, a, b) in [("IPv4", &o.v4, &n.v4), ("IPv6", &o.v6, &n.v6)] {
            if let (Some(a), Some(b)) = (a, b)
                && a.answer != b.answer
            {
                let name = o.name.as_ref().map(|n| format!(" ({n})")).unwrap_or_default();
                changes.push(format!(
                    "{} {}{name} over {family}: {} → {}",
                    o.proto,
                    o.port,
                    reach_words(a),
                    reach_words(b)
                ));
            }
        }
    }
    changes
}

/// A rule's line without its counter's numbers, which are not part of it.
fn without_counts(line: &str) -> String {
    let words: Vec<&str> = line.split(' ').collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < words.len() {
        out.push(words[i]);
        if words[i] == "counter" && words.get(i + 1) == Some(&"packets") && words.get(i + 3) == Some(&"bytes")
        {
            i += 5;
        } else {
            i += 1;
        }
    }
    out.join(" ")
}

/// Check a change and work out what it would do. Nothing is changed.
pub fn prepare(app: &App, live: &Ruleset, change: Change) -> Result<Plan> {
    let listing = nft(&["-s", "-a", "list", "table", &change.chain.family, &change.chain.table], None)?;
    let script = rewrite(&listing, &change)?;
    nft(&["-c", "-f", "-"], Some(&script)).map_err(|e| err!("nft refused the change: {e}"))?;
    let revert = format!(
        "destroy table {} {}\n{}",
        change.chain.family,
        change.chain.table,
        table_text(&change.chain)?
    );

    let chain = live.chain(&change.chain.family, &change.chain.table, &change.chain.chain);
    let line = |handle: u64| {
        let text = chain
            .and_then(|c| c.rules.iter().find(|r| r.handle == handle))
            .and_then(|r| r.text.clone())
            .unwrap_or_default();
        without_counts(&text)
    };
    let diff = match &change.op {
        crate::edit::Op::Insert { rule, .. } => vec![format!("+ {rule}")],
        crate::edit::Op::Replace { handle, rule } => {
            vec![format!("- {}", line(*handle)), format!("+ {rule}")]
        }
        crate::edit::Op::Delete { handle } => vec![format!("- {}", line(*handle))],
    };

    let mut plan =
        Plan { change, script, revert, diff, exposure: Vec::new(), warnings: Vec::new(), unpredicted: None };
    match predict(&plan.script) {
        Ok(after) => {
            plan.exposure = exposure_changes(live, &after, &app.names);
            for (client, port) in ssh_clients() {
                let was = exposure::admits(live, &app.names, "tcp", port, client).answer != Answer::Nobody;
                let will = exposure::admits(&after, &app.names, "tcp", port, client).answer != Answer::Nobody;
                if was && !will {
                    plan.warnings.push(format!(
                        "{client} is connected over SSH now and could not connect again: the open session \
                         stays up, the next login from there is refused. Without y it undoes itself in {} s.",
                        GRACE.as_secs()
                    ));
                }
            }
        }
        Err(e) => plan.unpredicted = Some(e.0),
    }
    Ok(plan)
}

/// A change applied and not yet kept.
#[derive(Debug, Clone)]
pub struct Pending {
    pub table: ChainKey,
    pub title: String,
    pub deadline: Instant,
    /// The table right after the change, to tell whether it is still in.
    applied: String,
}

/// systemctl, quietly: anything it printed would land in the middle of
/// the dashboard and scroll it.
fn systemctl(args: &[&str]) -> bool {
    Command::new("systemctl")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn timer_active() -> bool {
    systemctl(&["is-active", "--quiet", &format!("{UNIT}.timer")])
}

fn stop_timer() {
    let (timer, service) = (format!("{UNIT}.timer"), format!("{UNIT}.service"));
    systemctl(&["stop", &timer, &service]);
    systemctl(&["reset-failed", &timer, &service]);
}

fn write_private(path: &str, text: &str) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(RUN_DIR)
        .map_err(|e| err!("{RUN_DIR}: {e}"))?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| err!("{path}: {e}"))?;
    f.write_all(text.as_bytes()).map_err(|e| err!("{path}: {e}"))
}

/// Apply the change, with the undo already armed.
pub fn apply(plan: &Plan) -> Result<Pending> {
    if timer_active() {
        bail!("another change is still waiting to be kept or undone");
    }
    write_private(REVERT, &plan.revert)?;
    write_private(PENDING, &format!("{} {}\n", plan.change.chain.family, plan.change.chain.table))?;
    run(
        "systemd-run",
        &[
            "--quiet",
            &format!("--unit={UNIT}"),
            &format!("--on-active={}", GRACE.as_secs()),
            "--timer-property=AccuracySec=100ms",
            "--description=nft-patrol: undo a firewall change nobody kept",
            "/usr/bin/nft",
            "-f",
            REVERT,
        ],
        None,
    )
    .map_err(|e| err!("could not arm the undo timer, so nothing was changed: {e}"))?;
    if let Err(e) = nft(&["-f", "-"], Some(&plan.script)) {
        stop_timer();
        bail!("the change failed and nothing was changed: {e}");
    }
    Ok(Pending {
        table: plan.change.chain.clone(),
        title: plan.change.title.clone(),
        deadline: Instant::now() + GRACE,
        applied: table_text(&plan.change.chain)?,
    })
}

/// A change left waiting by an earlier run that ended before it was kept.
pub fn recover() -> Option<Pending> {
    if !timer_active() {
        return None;
    }
    let text = std::fs::read_to_string(PENDING).ok()?;
    let mut words = text.split_whitespace();
    let table = ChainKey { family: words.next()?.into(), table: words.next()?.into(), chain: String::new() };
    let started = std::fs::metadata(REVERT).and_then(|m| m.modified()).ok()?;
    let age = SystemTime::now().duration_since(started).unwrap_or_default();
    Some(Pending {
        applied: table_text(&table).ok()?,
        table,
        title: "a change from an earlier run".into(),
        deadline: Instant::now() + GRACE.saturating_sub(age),
    })
}

/// Whether the undo has already happened by itself.
pub fn expired() -> bool {
    !timer_active()
}

/// Keep the change: stop the undo, then save the ruleset to disk.
pub fn keep(pending: &Pending) -> Result<String> {
    stop_timer();
    if table_text(&pending.table).ok().as_deref() != Some(&pending.applied) {
        bail!("too late: the change was already undone");
    }
    let _ = std::fs::remove_file(PENDING);
    save(&pending.table)
}

/// Undo now rather than waiting.
pub fn undo() -> Result<()> {
    stop_timer();
    let _ = std::fs::remove_file(PENDING);
    nft(&["-f", REVERT], None).map(|_| ())
}

/// Write /etc/nftables.conf: the tables it had, plus the one just changed,
/// each as it is now. Docker's and the like stay out, as they were.
fn save(changed: &ChainKey) -> Result<String> {
    let mut tables: Vec<(String, String)> = Vec::new();
    if Path::new(SAVED).is_file() {
        match crate::source::Source::File(SAVED.into()).load() {
            Ok(r) => tables.extend(r.tables.iter().map(|t| (t.family.clone(), t.name.clone()))),
            Err(e) => bail!("kept, but not saved: {SAVED} does not load ({e})"),
        }
    }
    if !tables.iter().any(|(f, n)| *f == changed.family && *n == changed.table) {
        tables.push((changed.family.clone(), changed.table.clone()));
    }
    let mut text = format!(
        "#!/usr/bin/nft -f\n# Written by nft-patrol on {}: the live ruleset, table by table.\n\
         # The previous version is {BACKUP}.\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M")
    );
    for (family, name) in &tables {
        let key = ChainKey { family: family.clone(), table: name.clone(), chain: String::new() };
        match table_text(&key) {
            Ok(listing) => text.push_str(&format!("\ndestroy table {family} {name}\n{listing}")),
            // A table in the old file that is no longer loaded stays gone.
            Err(_) => continue,
        }
    }
    let tmp = format!("{SAVED}.nft-patrol.new");
    std::fs::write(&tmp, &text).map_err(|e| err!("kept, but not saved: {tmp}: {e}"))?;
    if let Err(e) = nft(&["-c", "-f", &tmp], None) {
        let _ = std::fs::remove_file(&tmp);
        bail!("kept, but not saved: the file would not load ({e})");
    }
    if Path::new(SAVED).is_file() {
        std::fs::copy(SAVED, BACKUP).map_err(|e| err!("kept, but not saved: {BACKUP}: {e}"))?;
    }
    std::fs::rename(&tmp, SAVED).map_err(|e| err!("kept, but not saved: {SAVED}: {e}"))?;
    Ok(format!("kept and saved to {SAVED} (the old one is {BACKUP})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_left_out() {
        assert_eq!(
            without_counts("tcp dport 8080 counter packets 12 bytes 640 accept comment \"web\""),
            "tcp dport 8080 counter accept comment \"web\""
        );
        assert_eq!(without_counts("counter packets 0 bytes 0"), "counter");
        assert_eq!(without_counts("ip saddr 10.0.0.1 accept"), "ip saddr 10.0.0.1 accept");
    }
}
