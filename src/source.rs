// SPDX-License-Identifier: GPL-3.0-or-later
//! Where the ruleset comes from: the kernel, or a file.
//!
//! The kernel's ruleset is what is actually enforced, with live hit
//! counts, and reading it needs root. A file - /etc/nftables.conf when not
//! root - is loaded into a private, empty network namespace that only this
//! process can see (`unshare --user --net`, no root needed) and listed back
//! from there: nft does the parsing, so a file looks exactly as it would
//! once loaded, and nothing touches the real firewall.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::Result;
use crate::ruleset::{self, Ruleset};
use crate::{bail, err};

pub const SAVED: &str = "/etc/nftables.conf";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Live,
    File(PathBuf),
}

impl Source {
    /// The kernel's ruleset as root, otherwise the saved one.
    pub fn pick(file: Option<PathBuf>) -> Source {
        match file {
            Some(path) => Source::File(path),
            None if crate::is_root() => Source::Live,
            None => Source::File(PathBuf::from(SAVED)),
        }
    }

    pub fn is_live(&self) -> bool {
        *self == Source::Live
    }

    pub fn describe(&self) -> String {
        match self {
            Source::Live => "live".into(),
            Source::File(path) => path.display().to_string(),
        }
    }

    pub fn load(&self) -> Result<Ruleset> {
        match self {
            Source::Live => {
                let json = nft(&["-j", "list", "ruleset"])?;
                let text = nft(&["-a", "list", "ruleset"])?;
                ruleset::parse(&json, &text)
            }
            Source::File(path) => load_file(path),
        }
    }
}

fn nft(args: &[&str]) -> Result<String> {
    let output = Command::new("nft").args(args).output().map_err(|e| err!("nft: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("Operation not permitted") {
            bail!("reading the live ruleset needs root: run it with sudo");
        }
        bail!("nft {}: {}", args.join(" "), stderr.trim());
    }
    String::from_utf8(output.stdout).map_err(|_| err!("nft printed something that is not UTF-8"))
}

/// What separates the JSON from the text listing in one namespace's output.
const SEPARATOR: &str = "\n--nft-patrol--\n";

fn load_file(path: &Path) -> Result<Ruleset> {
    if !path.is_file() {
        bail!("{}: no such file", path.display());
    }
    // One namespace for both listings, so their handles agree.
    let script = format!(
        "nft -f \"$1\" && nft -j list ruleset && printf '{}' && nft -a list ruleset",
        SEPARATOR.replace('\n', "\\n")
    );
    let output = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "sh", "-c", &script, "sh"])
        .arg(path)
        .output()
        .map_err(|e| err!("unshare: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("unshare failed") || stderr.contains("Operation not permitted") {
            bail!(
                "{}: cannot open a private network namespace to load it in ({})",
                path.display(),
                stderr.trim()
            );
        }
        // nft's own message says which line is wrong.
        bail!("{} does not load:\n{}", path.display(), stderr.trim_end());
    }
    let (json, text) = stdout.split_once(SEPARATOR).ok_or_else(|| err!("nft's output was cut short"))?;
    ruleset::parse(json, text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Needs unprivileged user namespaces, which Arch has; skipped elsewhere.
    #[test]
    fn loads_a_file_privately() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/rich.nft");
        match load_file(&path) {
            Ok(r) => assert_eq!(r.rule_count(), 8),
            Err(e) if e.0.contains("namespace") || e.0.contains("unshare") => {
                eprintln!("skipped: {e}")
            }
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn a_broken_file_says_where() {
        let dir = std::env::temp_dir().join(format!("nft-patrol-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("broken.nft");
        std::fs::write(&path, "table inet x { chain y { tcp dport accept } }\n").unwrap();
        let result = load_file(&path);
        std::fs::remove_dir_all(&dir).unwrap();
        match result {
            Err(e) if e.0.contains("namespace") => eprintln!("skipped: {e}"),
            Err(e) => assert!(e.0.contains("does not load") && e.0.contains("Error"), "{e}"),
            Ok(_) => panic!("loaded a broken file"),
        }
    }
}
