// SPDX-License-Identifier: GPL-3.0-or-later
//! Drawing the dashboard:
//!
//! ```text
//! ╭─ nft-patrol ─────────────────────── Rules  Exposure  Blocked ─╮
//! │ firewall on  block incoming traffic unless …    8 rules · live │
//! ╰──────────────────────────────────────────────────────────────╯
//! ╭ Rules ─────────────────────────────╮╭ Rule 6 ─────────────────╮
//! │▾ inet filter input   policy drop   ││ pills, the sentence,     │
//! │▌  ALLOW  Allow SSH (tcp 22) from … ││ conditions, nft, hits    │
//! ╰────────────────────────────────────╯╰─────────────────────────╯
//!  keys that apply right now - or the search box, or a message
//! ```
//!
//! The detail panel sits beside the list on wide terminals and under it on
//! narrow ones. Every row and tab drawn is recorded in `screen.hits`.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::symbols::border;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Padding, Paragraph};

use super::form::{Field, Form};
use super::screen::{Hit, Overlay, Row, Screen, Tab, Tone, chain_words, exposure_rank};
use super::theme::{self, Look};
use crate::exposure::{Answer, Reach, Service};
use crate::table::{display_width, pad, printable, truncate, wrap_text};
use crate::words::Verdict;

/// Below this width the detail panel goes under the list.
const SIDE_BY_SIDE: u16 = 100;
/// The verdict badge's width, padding included.
const BADGE: usize = 8;

const ASCII_BORDER: border::Set = border::Set {
    top_left: "+",
    top_right: "+",
    bottom_left: "+",
    bottom_right: "+",
    vertical_left: "|",
    vertical_right: "|",
    horizontal_top: "-",
    horizontal_bottom: "-",
};

impl Look {
    fn tone(&self, tone: Tone) -> Style {
        match tone {
            Tone::Dim => self.muted(),
            Tone::Accent => self.fg(self.palette.blue),
            Tone::Heading => self.bold(self.palette.fg),
            Tone::Error => self.bold(self.palette.red),
            Tone::Ok => self.fg(self.palette.green),
        }
    }

    fn block(&self, title: Line<'static>, focused: bool) -> Block<'static> {
        let block = Block::bordered().border_style(self.border(focused)).title(title);
        if self.unicode { block.border_type(BorderType::Rounded) } else { block.border_set(ASCII_BORDER) }
    }

    fn keyname(&self, key: &str) -> String {
        if self.unicode {
            return key.to_owned();
        }
        key.replace("↑↓", "up/dn").replace("←→", "lt/rt").replace('⏎', "enter")
    }

    fn verdict_color(&self, verdict: &Verdict) -> Color {
        let p = self.palette;
        match verdict {
            Verdict::Accept => p.green,
            Verdict::Drop => p.red,
            Verdict::Reject => p.orange,
            Verdict::Jump(_) | Verdict::Goto(_) | Verdict::Return | Verdict::Continue => p.blue,
            Verdict::Nat(_) => p.purple,
            Verdict::Queue => p.cyan,
            Verdict::None => p.muted,
        }
    }

    fn badge(&self, label: &str, color: Color) -> Span<'static> {
        if label.is_empty() {
            return Span::styled(pad(&format!(" {}", self.icons.dot), BADGE, false), self.muted());
        }
        let text = format!(" {label} ");
        let text =
            if self.color { pad(&text, BADGE, false) } else { pad(&format!("[{label}]"), BADGE, false) };
        Span::styled(text, self.pill(color))
    }

    fn answer_color(&self, answer: &Answer) -> Color {
        match answer {
            Answer::Anywhere => self.palette.yellow,
            Answer::From(_) => self.palette.blue,
            Answer::Nobody => self.palette.green,
        }
    }
}

/// Draw the screen; returns how many rows the list shows (PgUp/PgDn).
pub fn draw(frame: &mut Frame, screen: &mut Screen, look: Look) -> usize {
    screen.hits.clear();
    let [main, footer] = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(frame.area());
    let [header, body] = Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).areas(main);
    draw_header(frame, header, screen, look);
    let (list, detail) = if body.width >= SIDE_BY_SIDE {
        let side = (body.width * 2 / 5).clamp(40, 64);
        let [list, detail] = Layout::horizontal([Constraint::Min(1), Constraint::Length(side)]).areas(body);
        (list, detail)
    } else {
        let [list, detail] = Layout::vertical([Constraint::Min(4), Constraint::Length(12)]).areas(body);
        (list, detail)
    };
    let height = match screen.tab {
        Tab::Rules => draw_rules(frame, list, screen, look),
        Tab::Exposure => draw_exposure(frame, list, screen, look),
        Tab::Blocked => draw_blocked(frame, list, screen, look),
    };
    let lines = match screen.tab {
        Tab::Rules => rule_detail(screen, look, detail.width.saturating_sub(2) as usize),
        Tab::Exposure => service_detail(screen, look, detail.width.saturating_sub(2) as usize),
        Tab::Blocked => packet_detail(screen, look, detail.width.saturating_sub(2) as usize),
    };
    let (title, body_lines) = lines;
    let block = look.block(Line::styled(format!(" {title} "), look.bold(look.palette.fg)), false);
    let inner = block.inner(detail);
    frame.render_widget(block, detail);
    frame.render_widget(Paragraph::new(body_lines), inner);
    if screen.help {
        draw_help(frame, main, look);
    }
    match &mut screen.overlay {
        Some(Overlay::Form(form)) => {
            let form = (**form).clone();
            draw_form(frame, main, screen, &form, look);
        }
        Some(Overlay::Review { title, lines, scroll }) => {
            draw_review(frame, main, title, lines, scroll, look);
        }
        None => {}
    }
    draw_footer(frame, footer, screen, look);
    height
}

fn draw_header(frame: &mut Frame, area: Rect, screen: &mut Screen, look: Look) {
    let p = look.palette;
    let title = Line::from(vec![
        Span::styled(format!(" {} ", look.icons.logo), look.bold(p.blue)),
        Span::styled("nft-patrol ", look.bold(p.fg)),
    ]);
    let block = look.block(title, false);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    // The tabs, on the top border at the right.
    let counts = [
        screen.rows.iter().filter(|r| matches!(r, Row::Rule(..))).count(),
        screen.exposure_rows.len(),
        screen.blocked_rows.len(),
    ];
    let labels: Vec<String> = Tab::ALL
        .iter()
        .zip(counts)
        .map(|(tab, n)| {
            let icon = match tab {
                Tab::Rules => look.icons.rules,
                Tab::Exposure => look.icons.exposure,
                Tab::Blocked => look.icons.blocked,
            };
            let icon = if icon.is_empty() { String::new() } else { format!("{icon} ") };
            format!(" {icon}{} {n} ", tab.name())
        })
        .collect();
    let total: u16 = labels.iter().map(|l| display_width(l) as u16 + 1).sum();
    if total + 18 < area.width {
        let mut x = area.right() - 1 - total;
        for (tab, label) in Tab::ALL.iter().zip(&labels) {
            let width = display_width(label) as u16;
            let style = if *tab == screen.tab { look.pill(p.blue) } else { look.muted() };
            let cell = Rect { x, y: area.y, width, height: 1 };
            frame.render_widget(Paragraph::new(Span::styled(label.clone(), style)), cell);
            screen.hits.push((cell, Hit::Tab(*tab)));
            x += width + 1;
        }
    }

    let mut left = vec![Span::raw(" ")];
    match screen.input_policy.as_deref() {
        None => {
            left.push(Span::styled(format!(" {} no firewall ", look.icons.warn), look.pill(p.red)));
            left.push(Span::styled("  nothing coming in is filtered", look.text()));
        }
        Some(policy) => {
            let color = if policy == "drop" { p.green } else { p.yellow };
            left.push(Span::styled(format!(" {} firewall on ", look.icons.ok), look.pill(color)));
            left.push(Span::styled(
                format!("  {}", crate::words::policy_words("input", policy)),
                look.text(),
            ));
        }
    }
    let mut right = Vec::new();
    let anyone = screen.open_to_anyone;
    right.push(Span::styled(
        format!("{anyone} open to anyone"),
        if anyone > 0 { look.bold(p.yellow) } else { look.muted() },
    ));
    right.push(Span::styled(format!(" {} ", look.icons.dot), look.muted()));
    right.push(Span::styled(format!("{} to some networks", screen.open_to_some), look.fg(p.subtle)));
    right.push(Span::raw("  "));
    if screen.live {
        right.push(Span::styled(" live ", look.pill(p.green)));
    } else {
        right.push(Span::styled(format!(" {} ", printable(&screen.source)), look.pill(p.yellow)));
    }
    right.push(Span::raw(" "));
    let width = inner.width as usize;
    let used = |spans: &[Span]| spans.iter().map(|s| display_width(&s.content)).sum::<usize>();
    // Narrow: the policy sentence goes first; the badge says enough.
    if used(&left) + used(&right) >= width {
        left.truncate(2);
    }
    let used: usize = used(&left) + used(&right);
    let mut spans = left;
    if used < width {
        spans.push(Span::raw(" ".repeat(width - used)));
        spans.extend(right);
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), inner);
}

fn list_block(screen: &Screen, look: Look, title: &str, shown: usize) -> Block<'static> {
    let p = look.palette;
    let mut spans = vec![Span::styled(format!(" {title} "), look.bold(p.fg))];
    if !screen.query.is_empty() {
        spans.push(Span::styled(
            format!("{} {} {} ", look.icons.dot, look.icons.search, printable(&screen.query)),
            look.fg(p.yellow),
        ));
        spans.push(Span::styled(format!("{shown} "), look.muted()));
    }
    look.block(Line::from(spans), true)
}

fn empty(frame: &mut Frame, area: Rect, look: Look, lines: Vec<(Tone, String)>) {
    let mut out = vec![Line::raw("")];
    out.extend(lines.into_iter().map(|(tone, text)| Line::styled(format!("  {text}"), look.tone(tone))));
    frame.render_widget(Paragraph::new(out), area);
}

fn no_match(screen: &Screen) -> Vec<(Tone, String)> {
    vec![(Tone::Dim, format!("nothing matches \"{}\"", printable(&screen.query)))]
}

/// The selection bar, then the row.
fn row_line(mut spans: Vec<Span<'static>>, selected: bool, look: Look) -> Line<'static> {
    spans.insert(
        0,
        if selected { Span::styled(look.icons.bar, look.fg(look.palette.blue)) } else { Span::raw(" ") },
    );
    let line = Line::from(spans);
    if selected { line.style(look.selected()) } else { line }
}

fn draw_rules(frame: &mut Frame, area: Rect, screen: &mut Screen, look: Look) -> usize {
    let p = look.palette;
    let shown = screen.rows.iter().filter(|r| matches!(r, Row::Rule(..))).count();
    let block = list_block(screen, look, "Rules", shown);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let height = inner.height as usize;
    let len = screen.rows.len();
    screen.lists[0].scroll(len, height);
    if len == 0 {
        let lines = if screen.query.is_empty() {
            vec![
                (Tone::Heading, "the ruleset is empty".to_owned()),
                (Tone::Dim, "no tables, so nothing is filtered: everything is allowed".to_owned()),
            ]
        } else {
            no_match(screen)
        };
        empty(frame, inner, look, lines);
        return height;
    }
    let width = inner.width as usize;
    let hits_width = if screen.live { 7 } else { 0 };
    let list = screen.lists[0];
    let mut lines = Vec::new();
    for (n, row) in screen.rows.iter().enumerate().skip(list.offset).take(height) {
        let selected = n == list.cursor;
        let spans = match *row {
            Row::Chain(c) => {
                let chain = &screen.chains[c];
                let mut spans = vec![
                    Span::styled(format!("{} ", look.icons.open), look.fg(p.blue)),
                    Span::styled(printable(&chain.path), look.bold(p.fg)),
                ];
                let extra = match &chain.base {
                    Some(b) => {
                        format!("   {} hook {} {} policy {}", b.kind, b.hook, look.icons.dot, b.policy)
                    }
                    None => "   regular chain".to_owned(),
                };
                let room = width.saturating_sub(3 + display_width(&chain.path));
                spans.push(Span::styled(truncate(&extra, room), look.muted()));
                spans
            }
            Row::Rule(c, r) => {
                let rule = &screen.chains[c].rules[r];
                let color = look.verdict_color(&rule.verdict);
                let room = width.saturating_sub(1 + 2 + BADGE + 1 + hits_width);
                let text = truncate(&printable(&rule.sentence), room);
                let filler = room.saturating_sub(display_width(&text));
                let mut spans = vec![
                    Span::raw("  "),
                    look.badge(rule.verdict.label(), color),
                    Span::raw(" "),
                    Span::styled(text, if selected { look.bold(p.fg) } else { look.text() }),
                ];
                if hits_width > 0 {
                    spans.push(Span::raw(" ".repeat(filler)));
                    let hits = rule.counter.map(|(packets, _)| theme::count(packets)).unwrap_or_default();
                    let style =
                        if rule.counter.is_some_and(|c| c.0 > 0) { look.fg(p.cyan) } else { look.muted() };
                    spans.push(Span::styled(pad(&hits, hits_width, true), style));
                }
                spans
            }
        };
        lines.push(row_line(spans, selected, look));
        let y = inner.y + (n - list.offset) as u16;
        screen.hits.push((Rect { x: inner.x, y, width: inner.width, height: 1 }, Hit::Row(n)));
    }
    frame.render_widget(Paragraph::new(lines), inner);
    height
}

fn reach_span(reach: Option<&Reach>, look: Look) -> Span<'static> {
    match reach {
        None => Span::styled(look.icons.dash.to_owned(), look.muted()),
        Some(r) => Span::styled(printable(&r.short()), look.fg(look.answer_color(&r.answer))),
    }
}

/// The badge for a service: how exposed it is.
fn service_badge(s: &Service, look: Look) -> Span<'static> {
    let p = look.palette;
    match exposure_rank(s) {
        0 => look.badge("ANYONE", p.yellow),
        1 => look.badge("SOME", p.blue),
        2 => look.badge("NOBODY", p.green),
        _ => look.badge("LOCAL", p.muted),
    }
}

fn draw_exposure(frame: &mut Frame, area: Rect, screen: &mut Screen, look: Look) -> usize {
    let p = look.palette;
    let block = list_block(screen, look, "Listening ports", screen.exposure_rows.len());
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let height = inner.height as usize;
    let len = screen.exposure_rows.len();
    screen.lists[1].scroll(len, height);
    if len == 0 {
        let lines = if screen.query.is_empty() {
            vec![(Tone::Heading, "nothing is listening".to_owned())]
        } else {
            no_match(screen)
        };
        empty(frame, inner, look, lines);
        return height;
    }
    let rows: Vec<&Service> = screen.exposure_rows.iter().map(|&i| &screen.services[i]).collect();
    let port_w = rows.iter().map(|s| format!("{} {}", s.proto, s.port).len()).max().unwrap_or(0);
    let name_w =
        rows.iter().map(|s| display_width(s.name.as_deref().unwrap_or(""))).max().unwrap_or(0).min(16);
    let prog_w = rows
        .iter()
        .map(|s| s.process.as_ref().map(|p| display_width(&p.0)).unwrap_or(1))
        .max()
        .unwrap_or(1)
        .min(16);
    let list = screen.lists[1];
    let mut lines = Vec::new();
    let mut hits = Vec::new();
    for (n, s) in rows.iter().enumerate().skip(list.offset).take(height) {
        let selected = n == list.cursor;
        let mut spans = vec![
            Span::raw(" "),
            service_badge(s, look),
            Span::raw(" "),
            Span::styled(pad(&format!("{} {}", s.proto, s.port), port_w, false), look.bold(p.fg)),
            Span::raw("  "),
            Span::styled(
                pad(&truncate(&printable(s.name.as_deref().unwrap_or("")), name_w), name_w, false),
                look.fg(p.cyan),
            ),
            Span::raw("  "),
            Span::styled(
                pad(
                    &truncate(&printable(s.process.as_ref().map(|p| p.0.as_str()).unwrap_or("?")), prog_w),
                    prog_w,
                    false,
                ),
                look.fg(p.subtle),
            ),
            Span::raw("  "),
        ];
        if s.local_only {
            spans.push(Span::styled("this machine only", look.muted()));
        } else if s.v4.as_ref().map(|r| &r.answer) == s.v6.as_ref().map(|r| &r.answer) {
            spans.push(reach_span(s.v4.as_ref(), look));
        } else {
            spans.push(Span::styled("v4 ", look.muted()));
            spans.push(reach_span(s.v4.as_ref(), look));
            spans.push(Span::styled(format!(" {} v6 ", look.icons.dot), look.muted()));
            spans.push(reach_span(s.v6.as_ref(), look));
        }
        lines.push(row_line(spans, selected, look));
        let y = inner.y + (n - list.offset) as u16;
        hits.push((Rect { x: inner.x, y, width: inner.width, height: 1 }, Hit::Row(n)));
    }
    frame.render_widget(Paragraph::new(lines), inner);
    screen.hits.extend(hits);
    height
}

fn draw_blocked(frame: &mut Frame, area: Rect, screen: &mut Screen, look: Look) -> usize {
    let p = look.palette;
    let block = list_block(screen, look, "Logged packets", screen.blocked_rows.len());
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let height = inner.height as usize;
    let len = screen.blocked_rows.len();
    screen.lists[2].scroll(len, height);
    let packets = match &screen.packets {
        Err(e) => {
            empty(frame, inner, look, vec![(Tone::Error, printable(e))]);
            return height;
        }
        Ok(packets) => packets,
    };
    if len == 0 {
        let lines = if !screen.query.is_empty() {
            no_match(screen)
        } else if !screen.logs {
            vec![
                (Tone::Heading, "no rule logs, so nothing is recorded".to_owned()),
                (Tone::Dim, "L (as root) adds a rule that logs what the input chain blocks,".to_owned()),
                (Tone::Dim, "at most 10 packets a second; L again takes it out".to_owned()),
            ]
        } else {
            vec![(Tone::Heading, "nothing logged yet".to_owned())]
        };
        empty(frame, inner, look, lines);
        return height;
    }
    let list = screen.lists[2];
    let now = chrono::Local::now();
    let mut lines = Vec::new();
    let mut hits = Vec::new();
    for (n, &i) in screen.blocked_rows.iter().enumerate().skip(list.offset).take(height) {
        let pk = &packets[i];
        let selected = n == list.cursor;
        let when = if pk.time.date_naive() == now.date_naive() {
            pk.time.format("%H:%M:%S").to_string()
        } else {
            pk.time.format("%b %d %H:%M").to_string()
        };
        let port = pk.dport.map(|d| format!(" {d}")).unwrap_or_default();
        let spans = vec![
            Span::raw(" "),
            Span::styled(pad(&when, 12, false), look.fg(p.subtle)),
            Span::raw(" "),
            Span::styled(pad(&truncate(&printable(&pk.src), 30), 30, false), look.bold(p.fg)),
            Span::raw(" "),
            Span::styled(
                pad(&printable(&format!("{}{port}", pk.proto.to_lowercase())), 12, false),
                look.fg(p.cyan),
            ),
            Span::raw(" "),
            Span::styled(pad(&printable(&pk.iface), 8, false), look.fg(p.subtle)),
            Span::raw(" "),
            Span::styled(printable(&pk.prefix), look.muted()),
        ];
        lines.push(row_line(spans, selected, look));
        let y = inner.y + (n - list.offset) as u16;
        hits.push((Rect { x: inner.x, y, width: inner.width, height: 1 }, Hit::Row(n)));
    }
    frame.render_widget(Paragraph::new(lines), inner);
    screen.hits.extend(hits);
    height
}

// --- the detail panel ------------------------------------------------------

/// A labelled field, its value wrapped under itself.
fn field(lines: &mut Vec<Line<'static>>, look: Look, name: &str, value: &str, style: Style, width: usize) {
    let indent = 11;
    for (i, part) in
        wrap_text(&printable(value), width.saturating_sub(indent + 1).max(8)).into_iter().enumerate()
    {
        let label = if i == 0 { format!(" {name:<10}") } else { " ".repeat(indent) };
        lines.push(Line::from(vec![Span::styled(label, look.muted()), Span::styled(part, style)]));
    }
}

fn paragraph(lines: &mut Vec<Line<'static>>, text: &str, style: Style, width: usize) {
    for part in wrap_text(&printable(text), width.saturating_sub(2).max(8)) {
        lines.push(Line::styled(format!(" {part}"), style));
    }
}

fn rule_detail(screen: &Screen, look: Look, width: usize) -> (String, Vec<Line<'static>>) {
    let p = look.palette;
    let mut lines = Vec::new();
    match screen.current_row() {
        None => ("".into(), lines),
        Some(Row::Chain(c)) => {
            let chain = &screen.chains[c];
            let mut pills = vec![Span::raw(" ")];
            if let Some(b) = &chain.base {
                pills.push(Span::styled(format!(" {} hook ", b.hook), look.pill(p.blue)));
                pills.push(Span::raw(" "));
                let color = if b.policy == "drop" { p.red } else { p.green };
                pills.push(Span::styled(format!(" policy {} ", b.policy), look.pill(color)));
            } else {
                pills.push(Span::styled(" regular chain ", look.pill(p.purple)));
            }
            lines.push(Line::from(pills));
            lines.push(Line::raw(""));
            paragraph(&mut lines, &capitalise(&chain_words(chain)), look.bold(p.fg), width);
            lines.push(Line::raw(""));
            field(
                &mut lines,
                look,
                "table",
                &format!("{} {}", chain.key.family, chain.key.table),
                look.text(),
                width,
            );
            if let Some(b) = &chain.base {
                field(&mut lines, look, "type", &b.kind, look.text(), width);
                field(&mut lines, look, "priority", &b.priority.to_string(), look.text(), width);
            }
            let n = chain.rules.len();
            field(
                &mut lines,
                look,
                "rules",
                &format!("{n} rule{}", if n == 1 { "" } else { "s" }),
                look.text(),
                width,
            );
            if chain.base.is_some() {
                lines.push(Line::raw(""));
                paragraph(
                    &mut lines,
                    "The rules below are tried in order; the first that decides wins. What no rule decides gets the policy.",
                    look.muted(),
                    width,
                );
            }
            (chain.path.clone(), lines)
        }
        Some(Row::Rule(c, r)) => {
            let chain = &screen.chains[c];
            let rule = &chain.rules[r];
            let color = look.verdict_color(&rule.verdict);
            let mut pills = vec![Span::raw(" ")];
            if !rule.verdict.label().is_empty() {
                pills.push(Span::styled(format!(" {} ", rule.verdict.label()), look.pill(color)));
                pills.push(Span::raw(" "));
            }
            pills.push(Span::styled(format!(" {} ", printable(&chain.path)), look.pill(p.border)));
            lines.push(Line::from(pills));
            lines.push(Line::raw(""));
            paragraph(&mut lines, &rule.sentence, look.bold(p.fg), width);
            lines.push(Line::raw(""));
            if let Some(comment) = &rule.comment {
                let (open, close) = look.icons.quote;
                field(
                    &mut lines,
                    look,
                    "comment",
                    &format!("{open}{comment}{close}"),
                    look.fg(p.subtle),
                    width,
                );
            }
            if rule.conds.is_empty() {
                field(&mut lines, look, "when", "every packet that gets this far", look.text(), width);
            }
            for (i, cond) in rule.conds.iter().enumerate() {
                field(&mut lines, look, if i == 0 { "when" } else { "and" }, cond, look.text(), width);
            }
            if let Some(limit) = &rule.limit {
                let what = format!("{limit} - packets beyond the limit go on to the next rule");
                field(&mut lines, look, "limit", &what, look.text(), width);
            }
            if let Some(prefix) = &rule.log {
                let what = if prefix.is_empty() {
                    "to the kernel log".to_owned()
                } else {
                    format!("to the kernel log as \"{prefix}\"")
                };
                field(&mut lines, look, "logs", &what, look.text(), width);
            }
            let hits = match rule.counter {
                Some((packets, bytes)) if screen.live => {
                    (format!("{packets} packets {} {}", look.icons.dot, theme::size(bytes)), look.fg(p.cyan))
                }
                Some(_) => ("counted (live only: run with sudo)".to_owned(), look.muted()),
                None => ("not counted (the rule has no counter)".to_owned(), look.muted()),
            };
            field(&mut lines, look, "hits", &hits.0, hits.1, width);
            field(&mut lines, look, "handle", &rule.handle.to_string(), look.muted(), width);
            if let Some(text) = &rule.text {
                lines.push(Line::raw(""));
                lines.push(Line::styled(" nft", look.muted()));
                paragraph(&mut lines, text, look.fg(p.purple), width);
            }
            (format!("Rule {}", r + 1), lines)
        }
    }
}

fn capitalise(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn service_detail(screen: &Screen, look: Look, width: usize) -> (String, Vec<Line<'static>>) {
    let p = look.palette;
    let mut lines = Vec::new();
    let Some(s) = screen.current_service() else { return (String::new(), lines) };
    lines.push(Line::from(vec![Span::raw(" "), service_badge(s, look)]));
    lines.push(Line::raw(""));
    let what = match &s.name {
        Some(name) => format!("{name} on {} port {}", s.proto, s.port),
        None => format!("{} port {}", s.proto, s.port),
    };
    paragraph(&mut lines, &what, look.bold(p.fg), width);
    lines.push(Line::raw(""));
    let program = match &s.process {
        Some((name, pid)) => format!("{name} (PID {pid})"),
        None if screen.root => "unknown".into(),
        None => "another user's: run with sudo to see it".into(),
    };
    field(&mut lines, look, "program", &program, look.text(), width);
    let addrs: Vec<String> = s
        .addrs
        .iter()
        .map(|a| if a.is_unspecified() { format!("{a} (all)") } else { a.to_string() })
        .collect();
    field(&mut lines, look, "bound to", &addrs.join(", "), look.text(), width);
    lines.push(Line::raw(""));
    if s.local_only {
        paragraph(
            &mut lines,
            "Bound to loopback: only programs on this machine can connect, whatever the firewall says.",
            look.muted(),
            width,
        );
    }
    for (family, reach) in [("IPv4", &s.v4), ("IPv6", &s.v6)] {
        let Some(r) = reach else { continue };
        let who = match &r.answer {
            Answer::Anywhere => "anyone".to_owned(),
            Answer::Nobody => "nobody".to_owned(),
            Answer::From(sources) => format!("only {}", sources.join(", ")),
        };
        let style = look.bold(look.answer_color(&r.answer));
        field(&mut lines, look, family, &who, style, width);
        field(&mut lines, look, "because", &r.because, look.text(), width);
        if r.unsure {
            field(
                &mut lines,
                look,
                "",
                &format!(
                    "{} a rule on the way could not be fully checked - treat this as likely, not certain",
                    look.icons.warn
                ),
                look.fg(p.yellow),
                width,
            );
        }
        lines.push(Line::raw(""));
    }
    (format!("{} {}", s.proto, s.port), lines)
}

fn packet_detail(screen: &Screen, look: Look, width: usize) -> (String, Vec<Line<'static>>) {
    let p = look.palette;
    let mut lines = Vec::new();
    let Some(pk) = screen.current_packet() else {
        if !screen.logs {
            paragraph(
                &mut lines,
                "Nothing is logged until a rule asks for it: L (as root) adds one that logs what is blocked.",
                look.muted(),
                width,
            );
        }
        return ("Logging".into(), lines);
    };
    if !pk.prefix.is_empty() {
        lines.push(Line::from(vec![
            Span::raw(" "),
            Span::styled(format!(" {} ", printable(&pk.prefix)), look.pill(p.orange)),
        ]));
        lines.push(Line::raw(""));
    }
    field(&mut lines, look, "when", &pk.time.format("%Y-%m-%d %H:%M:%S").to_string(), look.text(), width);
    field(
        &mut lines,
        look,
        "from",
        &format!("{}{}", pk.src, pk.sport.map(|p| format!(" port {p}")).unwrap_or_default()),
        look.bold(p.fg),
        width,
    );
    field(
        &mut lines,
        look,
        "to",
        &format!("{}{}", pk.dst, pk.dport.map(|p| format!(" port {p}")).unwrap_or_default()),
        look.text(),
        width,
    );
    field(&mut lines, look, "protocol", &pk.proto, look.text(), width);
    field(&mut lines, look, "arrived", &format!("on {}", pk.iface), look.text(), width);
    lines.push(Line::raw(""));
    lines.push(Line::styled(" kernel log", look.muted()));
    paragraph(&mut lines, &pk.message, look.fg(p.subtle), width);
    (pk.time.format("%H:%M:%S").to_string(), lines)
}

// --- footer and help -------------------------------------------------------

fn draw_footer(frame: &mut Frame, area: Rect, screen: &Screen, look: Look) {
    let p = look.palette;
    let line = if let Some((title, deadline)) = &screen.pending
        && screen.message.is_none()
    {
        let left = deadline.saturating_duration_since(std::time::Instant::now()).as_secs();
        Line::from(vec![
            Span::styled(format!(" {} not kept yet ", look.icons.warn), look.pill(p.yellow)),
            Span::styled(format!(" {} ", printable(title)), look.bold(p.fg)),
            Span::styled("  y", look.bold(p.green)),
            Span::styled(" keep  ", look.muted()),
            Span::styled("n", look.bold(p.red)),
            Span::styled(" undo now   ", look.muted()),
            Span::styled(format!("undoes itself in {left} s"), look.bold(p.yellow)),
        ])
    } else if screen.searching {
        Line::from(vec![
            Span::styled(format!(" {} ", look.icons.search), look.fg(p.yellow)),
            Span::styled(printable(&screen.query), look.bold(p.fg)),
            Span::styled("▏", look.fg(p.yellow)),
            Span::styled(format!("   {} keep  esc clear", look.keyname("⏎")), look.muted()),
        ])
    } else if let Some((tone, text)) = &screen.message {
        Line::styled(format!(" {}", printable(text)), look.tone(*tone))
    } else {
        let mut keys = vec![("↑↓", "move"), ("tab", "view"), ("/", "search")];
        if screen.can_edit {
            match screen.tab {
                Tab::Rules => keys.extend([("a", "add"), ("e", "edit"), ("d", "delete"), ("L", "log")]),
                Tab::Exposure | Tab::Blocked => keys.push(("a", "allow")),
            }
        }
        keys.extend([("?", "help"), ("q", "quit")]);
        let mut spans = vec![Span::raw(" ")];
        for (key, what) in keys {
            spans.push(Span::styled(look.keyname(key), look.bold(p.blue)));
            spans.push(Span::styled(format!(" {what}   "), look.muted()));
        }
        Line::from(spans)
    };
    frame.render_widget(Paragraph::new(line), area);
}

const HELP: &[(&str, &str)] = &[
    ("↑↓ j k", "move"),
    ("PgUp PgDn", "a page"),
    ("Home End g G", "first, last"),
    ("tab ←→ 1 2 3", "Rules, Exposure, Blocked"),
    ("/", "search all three: words, ports, addresses"),
    ("esc", "clear the search"),
    ("r", "reload now"),
    ("q", "quit"),
    ("", ""),
    ("a", "add a rule: above the one picked, or before the chain's catch-alls"),
    ("e  d", "edit, delete the rule picked"),
    ("a", "on Exposure or Blocked: allow that port, or that sender"),
    ("L", "log blocked packets (again: stop), for the Blocked tab"),
    ("y  n", "keep, undo an applied change - it undoes itself in 30 s"),
];

fn draw_help(frame: &mut Frame, area: Rect, look: Look) {
    let p = look.palette;
    let mut lines: Vec<Line> = HELP
        .iter()
        .map(|(k, what)| {
            Line::from(vec![
                Span::styled(pad(&look.keyname(k), 16, false), look.bold(p.blue)),
                Span::styled(*what, look.text()),
            ])
        })
        .collect();
    lines.push(Line::raw(""));
    for text in [
        "Rules shows each chain and its rules in plain words; the panel has the rule in nft's own syntax.",
        "Exposure puts every listening port to the input chains as a new connection from elsewhere.",
        "Blocked reads the kernel log for packets that a rule with log recorded.",
        "Live counts and the ruleset reload every 2 seconds as root; a file reloads when it changes.",
    ] {
        for part in wrap_text(text, 64) {
            lines.push(Line::styled(part, look.muted()));
        }
    }
    let width = area.width.saturating_sub(4).min(72);
    let height = area.height.saturating_sub(2).min(lines.len() as u16 + 4);
    let popup =
        Rect { x: area.x + (area.width - width) / 2, y: area.y + (area.height - height) / 2, width, height };
    frame.render_widget(Clear, popup);
    let block = look.block(Line::styled(" Keys ", look.bold(p.fg)), true).padding(Padding::new(2, 2, 1, 1));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    frame.render_widget(Paragraph::new(lines), inner);
}

/// A centred box `width` wide, as tall as needed up to the area.
fn popup(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width.saturating_sub(2));
    let height = height.min(area.height.saturating_sub(2));
    Rect { x: area.x + (area.width - width) / 2, y: area.y + (area.height - height) / 2, width, height }
}

fn draw_form(frame: &mut Frame, area: Rect, screen: &Screen, form: &Form, look: Look) {
    let p = look.palette;
    let rect = popup(area, 84, 22);
    frame.render_widget(Clear, rect);
    let block = look
        .block(Line::styled(format!(" {} ", printable(&form.title)), look.bold(p.fg)), true)
        .padding(Padding::new(2, 2, 1, 0));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let width = inner.width as usize;
    let mut lines = Vec::new();
    for (i, field) in Field::ALL.iter().enumerate() {
        let current = i == form.field;
        let (value, choice) = form.value(*field);
        let mut spans = vec![
            if current { Span::styled(look.icons.bar, look.fg(p.blue)) } else { Span::raw(" ") },
            Span::styled(
                format!(" {:<10}", field.label()),
                if current { look.bold(p.fg) } else { look.muted() },
            ),
        ];
        if choice {
            let (l, r) = if look.unicode { ("‹ ", " ›") } else { ("< ", " >") };
            spans.push(Span::styled(l, look.fg(if current { p.blue } else { p.border })));
            spans.push(Span::styled(truncate(&printable(&value), width.saturating_sub(18)), look.bold(p.fg)));
            spans.push(Span::styled(r, look.fg(if current { p.blue } else { p.border })));
        } else {
            let hint = match field {
                Field::Ports if value.is_empty() => "every port - or 22, or 80, 443, or 8000-8100",
                Field::From if value.is_empty() => "an address, or a range like 192.168.1.0/24",
                Field::Comment if value.is_empty() => "optional: what it is for",
                _ => "",
            };
            spans.push(Span::styled(printable(&value), look.text()));
            if current {
                spans.push(Span::styled("▏", look.fg(p.yellow)));
            }
            if !hint.is_empty() {
                spans.push(Span::styled(hint, look.muted()));
            }
        }
        let line = Line::from(spans);
        lines.push(if current { line.style(look.selected()) } else { line });
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(format!("  goes {}", printable(&form.place)), look.muted()));
    lines.push(Line::raw(""));
    match screen.form_sentence(form) {
        Ok(words) => {
            let color = match form.spec.action {
                crate::edit::Action::Allow => p.green,
                crate::edit::Action::Block => p.red,
                crate::edit::Action::Refuse => p.orange,
            };
            for part in wrap_text(&printable(&words), width.saturating_sub(2)) {
                lines.push(Line::styled(format!("  {part}"), look.bold(color)));
            }
            if let Ok(rule) = form.spec.to_nft() {
                for part in wrap_text(&printable(&rule), width.saturating_sub(2)) {
                    lines.push(Line::styled(format!("  {part}"), look.fg(p.purple)));
                }
            }
        }
        Err(why) => {
            for part in wrap_text(&printable(&why), width.saturating_sub(2)) {
                lines.push(Line::styled(format!("  {part}"), look.muted()));
            }
        }
    }
    if let Some(error) = &form.error {
        lines.push(Line::raw(""));
        for part in wrap_text(&printable(error), width.saturating_sub(2)) {
            lines.push(Line::styled(format!("  {part}"), look.bold(p.red)));
        }
    }
    let keys = [("←→", "choose"), ("tab ↑↓", "field"), ("⏎", "review"), ("esc", "cancel")];
    let mut spans = vec![Span::raw("  ")];
    for (key, what) in keys {
        spans.push(Span::styled(look.keyname(key), look.bold(p.blue)));
        spans.push(Span::styled(format!(" {what}   "), look.muted()));
    }
    let [body, foot] = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).areas(inner);
    frame.render_widget(Paragraph::new(lines), body);
    frame.render_widget(Paragraph::new(vec![Line::raw(""), Line::from(spans)]), foot);
}

fn draw_review(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    lines: &[(Tone, String)],
    scroll: &mut usize,
    look: Look,
) {
    let p = look.palette;
    let rect = popup(area, 92, 24);
    frame.render_widget(Clear, rect);
    let block = look
        .block(Line::styled(format!(" {} ", truncate(&printable(title), 80)), look.bold(p.fg)), true)
        .padding(Padding::new(2, 2, 1, 1));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let width = inner.width as usize;
    let mut out = Vec::new();
    for (tone, text) in lines {
        if text.is_empty() {
            out.push(Line::raw(""));
            continue;
        }
        let style = match tone {
            Tone::Ok => look.bold(p.green),
            Tone::Error => look.bold(p.red),
            other => look.tone(*other),
        };
        for part in wrap_text(&printable(text), width.max(8)) {
            out.push(Line::styled(part, style));
        }
    }
    let shown = inner.height as usize;
    *scroll = (*scroll).min(out.len().saturating_sub(shown));
    let visible: Vec<Line> = out.into_iter().skip(*scroll).take(shown).collect();
    frame.render_widget(Paragraph::new(visible), inner);
}
