// SPDX-License-Identifier: GPL-3.0-or-later
//! /etc/nft-patrol/config.toml - optional; everything has a default.
//!
//! ```toml
//! color = "auto"            # auto, always, never
//!
//! [networks]                # names for address ranges, shown next to them
//! "home LAN" = "192.168.10.0/24"
//! ```

use std::path::Path;

use serde::Deserialize;

use crate::err;
use crate::error::Result;
use crate::names::Cidr;

pub const PATH: &str = "/etc/nft-patrol/config.toml";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ColorChoice {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub color: ColorChoice,
    /// name -> range, in the order written.
    #[serde(default)]
    pub networks: toml::Table,
}

impl Config {
    pub fn networks(&self) -> Vec<(String, String)> {
        self.networks.iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned()))).collect()
    }
}

/// The configuration at `path`, or the default one when `path` is the
/// default location and nothing is there.
pub fn load(path: Option<&Path>) -> Result<Config> {
    let (path, explicit) = match path {
        Some(p) => (p, true),
        None => (Path::new(PATH), false),
    };
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !explicit => return Ok(Config::default()),
        Err(e) => return Err(err!("{}: {e}", path.display())),
    };
    let config: Config = toml::from_str(&text).map_err(|e| err!("{}: {e}", path.display()))?;
    for (name, value) in &config.networks {
        match value.as_str() {
            Some(range) if Cidr::parse(range).is_some() => {}
            _ => {
                return Err(err!(
                    "{}: network \"{name}\" is not an address range like 192.168.1.0/24",
                    path.display()
                ));
            }
        }
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses() {
        let c: Config = toml::from_str(
            "color = \"never\"\n[networks]\n\"home LAN\" = \"192.168.10.0/24\"\nvpn = \"100.64.0.0/10\"\n",
        )
        .unwrap();
        assert_eq!(c.color, ColorChoice::Never);
        assert_eq!(
            c.networks(),
            [("home LAN".into(), "192.168.10.0/24".into()), ("vpn".into(), "100.64.0.0/10".into())]
        );
        assert!(toml::from_str::<Config>("colour = \"never\"").is_err());
    }
}
