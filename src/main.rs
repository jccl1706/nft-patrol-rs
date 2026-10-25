// SPDX-License-Identifier: GPL-3.0-or-later
//! nft-patrol: an nftables firewall dashboard for Arch Linux.

mod apply;
mod blocked;
mod config;
mod edit;
mod error;
mod exposure;
mod names;
mod report;
mod ruleset;
mod source;
mod table;
mod tui;
mod words;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::config::{ColorChoice, Config};
use crate::error::Result;
use crate::exposure::{Answer, Reach};
use crate::names::Names;
use crate::report::Report;
use crate::source::Source;
use crate::table::{Style, display_width, pad, printable};
use crate::words::{Ctx, analyse, policy_words, sentence};

#[derive(Parser)]
#[command(
    name = "nft-patrol",
    version,
    about = "nftables firewall dashboard: rules in plain words, exposed ports, blocked traffic.",
    after_help = "With no command, the dashboard opens. As root it shows the live ruleset with hit counts;\n\
                  otherwise /etc/nftables.conf, loaded privately (nothing is changed)."
)]
struct Cli {
    /// Show this nftables file instead of the live ruleset
    #[arg(short, long, global = true, value_name = "PATH")]
    file: Option<PathBuf>,
    /// Configuration file [default: /etc/nft-patrol/config.toml]
    #[arg(short, long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Override the configuration's color
    #[arg(long, global = true, value_enum)]
    color: Option<ColorChoice>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// The dashboard (the default)
    Tui,
    /// Every chain and rule, in plain words
    List {
        /// Each rule's nft line as well
        #[arg(short, long)]
        verbose: bool,
    },
    /// A summary: is the firewall on, what is exposed
    Status {
        /// As JSON, for scripts and desktop widgets
        #[arg(long)]
        json: bool,
    },
    /// The ports this machine listens on, and who the firewall lets reach them
    Exposure,
    /// Recently logged packets, from the kernel log
    Blocked {
        /// How many, newest first
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,
    },
}

pub struct App {
    pub config: Config,
    pub names: Names,
    pub source: Source,
    pub color: ColorChoice,
}

impl App {
    pub fn ctx<'a>(&'a self, ruleset: &'a ruleset::Ruleset, family: &'a str, table: &'a str) -> Ctx<'a> {
        Ctx { names: &self.names, ruleset, family, table }
    }
}

pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("nft-patrol: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<u8> {
    let config = config::load(cli.config.as_deref())?;
    let color = cli.color.unwrap_or(config.color);
    let names = Names::load(&config.networks());
    let app = App { config, names, source: Source::pick(cli.file), color };
    let style = Style::for_stdout(color);
    match cli.command.unwrap_or(Command::Tui) {
        Command::Tui => tui::run(&app),
        Command::List { verbose } => {
            note_source(&app);
            list(&app, &app.source.load()?, verbose, style);
            Ok(0)
        }
        Command::Status { json } => {
            let report = Report::load(&app, true)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report.json()).unwrap_or_default());
            } else {
                note_source(&app);
                status(&report, style);
            }
            Ok(0)
        }
        Command::Exposure => {
            note_source(&app);
            let report = Report::load(&app, false)?;
            exposure_table(&report, style);
            Ok(0)
        }
        Command::Blocked { lines } => blocked_list(&app, lines, style),
    }
}

/// Say on stderr when what is shown is not the live ruleset.
fn note_source(app: &App) {
    if let Source::File(path) = &app.source {
        eprintln!(
            "nft-patrol: showing {} as written - run with sudo for the live ruleset and its hit counts",
            path.display()
        );
    }
}

fn verdict_badge(label: &str, style: Style) -> String {
    let text = pad(label, 6, false);
    match label {
        "ALLOW" => style.green(&text),
        "BLOCK" | "REFUSE" => style.red(&text),
        "" => text,
        _ => style.blue(&text),
    }
}

fn list(app: &App, ruleset: &ruleset::Ruleset, verbose: bool, style: Style) {
    let mut first = true;
    for chain in ruleset.chains() {
        if !first {
            println!();
        }
        first = false;
        let ctx = app.ctx(ruleset, &chain.family, &chain.table);
        let mut head = style.bold(&printable(&chain.path()));
        if let Some(base) = &chain.base {
            head.push_str(&style.dim(&format!(
                "   {} hook {} · priority {} · policy {}",
                base.kind, base.hook, base.priority, base.policy
            )));
            println!("{head}");
            println!("  {}", style.dim(&policy_words(&base.hook, &base.policy)));
        } else {
            println!("{head}{}", style.dim("   regular chain: runs when a rule jumps here"));
        }
        if chain.rules.is_empty() {
            println!("  {}", style.dim("(no rules)"));
        }
        for (n, rule) in chain.rules.iter().enumerate() {
            let a = analyse(rule);
            let mut line = format!(
                "  {:>2}  {}  {}",
                n + 1,
                verdict_badge(a.verdict.label(), style),
                printable(&sentence(&a, &ctx))
            );
            if let Some((packets, _)) = rule.counter().filter(|_| app.source.is_live()) {
                line.push_str(&style.dim(&format!("   {packets} hits")));
            }
            println!("{line}");
            if let Some(comment) = &rule.comment {
                println!("{}  {}", " ".repeat(10), style.dim(&format!("“{}”", printable(comment))));
            }
            if verbose && let Some(text) = &rule.text {
                println!("{}  {}", " ".repeat(10), style.dim(&printable(text)));
            }
        }
    }
    if first {
        println!("{}", style.yellow("The ruleset is empty: no firewall, everything is allowed."));
    }
}

pub fn reach_text(reach: Option<&Reach>, local_only: bool) -> String {
    if local_only {
        return "this machine only".into();
    }
    match reach {
        None => "—".into(),
        Some(r) => r.short(),
    }
}

fn reach_style(reach: Option<&Reach>, local_only: bool, style: Style, text: &str) -> String {
    match reach.map(|r| &r.answer) {
        _ if local_only => style.dim(text),
        None => style.dim(text),
        Some(Answer::Anywhere) => style.yellow(text),
        Some(Answer::From(_)) => style.blue(text),
        Some(Answer::Nobody) => style.green(text),
    }
}

fn exposure_table(report: &Report, style: Style) {
    let rows: Vec<[String; 5]> = report
        .services
        .iter()
        .map(|s| {
            [
                format!("{} {}", s.proto, s.port),
                s.name.clone().unwrap_or_default(),
                s.process.as_ref().map(|(n, pid)| format!("{n} ({pid})")).unwrap_or_else(|| "?".into()),
                reach_text(s.v4.as_ref(), s.local_only),
                reach_text(s.v6.as_ref(), s.local_only),
            ]
        })
        .collect();
    let headers = ["PORT", "SERVICE", "PROGRAM", "IPv4 FROM", "IPv6 FROM"];
    let widths: Vec<usize> = (0..5)
        .map(|i| rows.iter().map(|r| display_width(&r[i])).chain([headers[i].len()]).max().unwrap_or(0))
        .collect();
    let header: Vec<String> = headers.iter().zip(&widths).map(|(h, w)| pad(h, *w, false)).collect();
    println!("{}", style.bold(&header.join("  ")));
    for (row, s) in rows.iter().zip(&report.services) {
        let mut cells: Vec<String> =
            row.iter().zip(&widths).map(|(c, w)| pad(&printable(c), *w, false)).collect();
        cells[3] = reach_style(s.v4.as_ref(), s.local_only, style, &cells[3]);
        cells[4] = reach_style(s.v6.as_ref(), s.local_only, style, &cells[4]);
        println!("{}", cells.join("  ").trim_end());
    }
    if report.services.is_empty() {
        println!("{}", style.dim("Nothing is listening."));
    } else if report.services.iter().any(|s| s.process.is_none()) && !is_root() {
        println!("{}", style.dim("(? - another user's program: run with sudo to see it)"));
    }
}

fn status(report: &Report, style: Style) {
    let r = &report.ruleset;
    match r.hooked("input").first().and_then(|c| c.base.as_ref()) {
        None => println!("{}  no input chain: nothing coming in is filtered", style.red("firewall off")),
        Some(base) => {
            let on =
                if base.policy == "drop" { style.green("firewall on") } else { style.yellow("firewall on") };
            println!("{on}  {}", policy_words("input", &base.policy));
        }
    }
    println!(
        "{}",
        style.dim(&format!(
            "{} table{}, {} chains, {} rules · nftables {}",
            r.tables.len(),
            if r.tables.len() == 1 { "" } else { "s" },
            r.chains().count(),
            r.rule_count(),
            r.version
        ))
    );
    let open: Vec<_> = report.services.iter().filter(|s| !s.local_only).collect();
    let (anyone, some) = report.counts();
    println!();
    println!(
        "{} listening to the network · {} open to anyone · {} to some networks only",
        open.len(),
        if anyone > 0 { style.yellow(&anyone.to_string()) } else { anyone.to_string() },
        some
    );
    for s in open {
        let label = format!("{} {}", s.proto, s.port);
        let name = s.name.clone().unwrap_or_default();
        println!(
            "  {}  {}  IPv4: {}  ·  IPv6: {}",
            pad(&label, 9, false),
            pad(&printable(&name), 14, false),
            reach_text(s.v4.as_ref(), false),
            reach_text(s.v6.as_ref(), false)
        );
    }
    println!();
    match &report.blocked {
        _ if !r.logs() => println!("{}", style.dim("No rule logs, so blocked packets are not recorded.")),
        Ok(p) if p.is_empty() => println!("No logged packets."),
        Ok(p) => println!("{} logged packets, the last {}", p.len(), p[0].time.format("%b %d %H:%M")),
        Err(e) => println!("{}", style.dim(&format!("Logged packets: {e}"))),
    }
}

fn blocked_list(app: &App, lines: usize, style: Style) -> Result<u8> {
    let packets = blocked::recent(lines).map_err(error::Error)?;
    if packets.is_empty() {
        let logs = app.source.load().map(|r| r.logs()).unwrap_or(true);
        println!(
            "{}",
            if logs {
                "No logged packets in the kernel log."
            } else {
                "No logged packets: no rule logs (add `log` to a rule to record what it blocks)."
            }
        );
        return Ok(0);
    }
    for p in &packets {
        let port = p.dport.map(|d| format!(" {d}")).unwrap_or_default();
        let to = format!("{}{}", p.proto.to_lowercase(), port);
        let prefix = if p.prefix.is_empty() {
            String::new()
        } else {
            format!("  {}", style.dim(&printable(&p.prefix)))
        };
        println!(
            "{}  {}  {}  {}{}",
            style.dim(&p.time.format("%b %d %H:%M:%S").to_string()),
            pad(&printable(&p.src), 39, false),
            pad(&printable(&to), 10, false),
            printable(&p.iface),
            prefix
        );
    }
    Ok(0)
}
