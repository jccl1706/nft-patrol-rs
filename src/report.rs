// SPDX-License-Identifier: GPL-3.0-or-later
//! Everything the dashboard and `status` show, gathered in one go.

use chrono::{DateTime, Local};
use serde_json::{Value, json};

use crate::App;
use crate::blocked::{self, Packet};
use crate::error::Result;
use crate::exposure::{self, Answer, Reach, Service};
use crate::ruleset::Ruleset;

/// How many logged packets are read.
pub const BLOCKED: usize = 500;

pub struct Report {
    pub ruleset: Ruleset,
    pub services: Vec<Service>,
    pub blocked: std::result::Result<Vec<Packet>, String>,
    pub loaded: DateTime<Local>,
}

impl Report {
    pub fn load(app: &App, with_blocked: bool) -> Result<Report> {
        let ruleset = app.source.load()?;
        let services = exposure::services(&exposure::sockets(), &app.names, &ruleset);
        let blocked = if with_blocked { blocked::recent(BLOCKED) } else { Ok(Vec::new()) };
        Ok(Report { ruleset, services, blocked, loaded: Local::now() })
    }

    /// Services open to anyone, and to some networks only.
    pub fn counts(&self) -> (usize, usize) {
        let open = || self.services.iter().filter(|s| !s.local_only);
        let any = |s: &&Service, f: fn(&Answer) -> bool| {
            [&s.v4, &s.v6].iter().any(|r| r.as_ref().is_some_and(|r| f(&r.answer)))
        };
        let anyone = open().filter(|s| any(s, |a| *a == Answer::Anywhere)).count();
        let some = open()
            .filter(|s| !any(s, |a| *a == Answer::Anywhere) && any(s, |a| matches!(a, Answer::From(_))))
            .count();
        (anyone, some)
    }

    /// `status --json`: stable keys, for widgets.
    pub fn json(&self) -> Value {
        let reach = |r: &Option<Reach>| match r {
            None => Value::Null,
            Some(r) => json!({
                "answer": match &r.answer {
                    Answer::Anywhere => "anyone",
                    Answer::From(_) => "some",
                    Answer::Nobody => "nobody",
                },
                "from": match &r.answer { Answer::From(s) => json!(s), _ => json!([]) },
                "because": r.because,
                "unsure": r.unsure,
            }),
        };
        let input = self.ruleset.hooked("input");
        let policy = input.first().and_then(|c| c.base.as_ref()).map(|b| b.policy.clone());
        let (anyone, some) = self.counts();
        json!({
            "version": 1,
            "updated": self.loaded.to_rfc3339_opts(chrono::SecondsFormat::Secs, false),
            "firewall": !input.is_empty(),
            "input_policy": policy,
            "tables": self.ruleset.tables.len(),
            "rules": self.ruleset.rule_count(),
            "logging": self.ruleset.logs(),
            "open_to_anyone": anyone,
            "open_to_some": some,
            "services": self.services.iter().filter(|s| !s.local_only).map(|s| json!({
                "proto": s.proto,
                "port": s.port,
                "name": s.name,
                "program": s.process.as_ref().map(|p| &p.0),
                "ipv4": reach(&s.v4),
                "ipv6": reach(&s.v6),
            })).collect::<Vec<_>>(),
            "logged": match &self.blocked {
                Ok(p) => json!(p.len()),
                Err(_) => Value::Null,
            },
            "last_logged": self.blocked.as_ref().ok().and_then(|p| p.first())
                .map(|p| p.time.to_rfc3339_opts(chrono::SecondsFormat::Secs, false)),
        })
    }
}
