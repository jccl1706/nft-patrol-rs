// SPDX-License-Identifier: GPL-3.0-or-later
//! What the dashboard shows and where the cursor is - no drawing here.
//!
//! Three tabs over one report: Rules (each chain, then its rules in plain
//! words), Exposure (listening ports and who can reach them) and Blocked
//! (logged packets). The search box filters all three at once.

use std::time::Instant;

use ratatui::layout::Rect;

use super::form::{Form, Outcome};
use super::fuzzy;
use crate::App;
use crate::blocked::Packet;
use crate::edit::{self, Change, Op, Proto, Spec};
use crate::exposure::{Answer, Service};
use crate::names::Names;
use crate::report::Report;
use crate::ruleset::{Base, ChainKey, Ruleset};
use crate::words::{Ctx, Verdict, analyse, cond_text, policy_words, sentence};

#[derive(Debug, Clone)]
pub struct RuleView {
    pub verdict: Verdict,
    pub sentence: String,
    pub conds: Vec<String>,
    pub text: Option<String>,
    pub comment: Option<String>,
    pub counter: Option<(u64, u64)>,
    pub limit: Option<String>,
    pub log: Option<String>,
    pub handle: u64,
    /// The rule as the form has it; None when it does more than the form can say.
    pub spec: Option<Spec>,
    /// What the search box matches against.
    pub fields: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ChainView {
    pub key: ChainKey,
    pub path: String,
    pub base: Option<Base>,
    pub rules: Vec<RuleView>,
    /// Where a new rule goes when no rule is picked (see edit::default_position).
    pub default_before: Option<u64>,
    /// The rule `L` added, when it is there.
    pub log_handle: Option<u64>,
}

pub fn build(app: &App, ruleset: &Ruleset) -> Vec<ChainView> {
    ruleset
        .chains()
        .map(|chain| {
            let ctx = app.ctx(ruleset, &chain.family, &chain.table);
            let rules = chain
                .rules
                .iter()
                .map(|rule| {
                    let a = analyse(rule);
                    let sentence = sentence(&a, &ctx);
                    let conds: Vec<String> = a.conds.iter().map(|c| cond_text(c, &ctx)).collect();
                    let mut fields = vec![sentence.clone(), a.verdict.label().to_owned()];
                    fields.extend(rule.comment.clone());
                    fields.extend(rule.text.clone());
                    fields.extend(conds.iter().cloned());
                    RuleView {
                        verdict: a.verdict.clone(),
                        sentence,
                        conds,
                        text: rule.text.clone(),
                        comment: rule.comment.clone(),
                        counter: rule.counter(),
                        limit: a.limit.clone(),
                        log: a.log.clone(),
                        handle: rule.handle,
                        spec: Spec::from_rule(&a, rule.comment.as_deref()),
                        fields: fields.into_iter().map(|f| f.to_lowercase()).collect(),
                    }
                })
                .collect();
            ChainView {
                key: chain.key(),
                path: chain.path(),
                base: chain.base.clone(),
                rules,
                default_before: edit::default_position(chain),
                log_handle: edit::log_rule(chain),
            }
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Rules,
    Exposure,
    Blocked,
}

impl Tab {
    pub const ALL: [Tab; 3] = [Tab::Rules, Tab::Exposure, Tab::Blocked];

    pub fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }

    pub fn name(self) -> &'static str {
        match self {
            Tab::Rules => "Rules",
            Tab::Exposure => "Exposure",
            Tab::Blocked => "Blocked",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Row {
    Chain(usize),
    Rule(usize, usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hit {
    Tab(Tab),
    Row(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Dim,
    Accent,
    Heading,
    Error,
    Ok,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Left,
    Right,
    PageUp,
    PageDown,
    Home,
    End,
    Tab,
    BackTab,
    Enter,
    Esc,
    Backspace,
    Char(char),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    None,
    Quit,
    Reload,
    /// Check a change and show what it would do.
    Prepare(Change),
    /// Apply the change under review.
    Apply,
    /// Drop the change under review.
    Cancel,
    /// Keep the applied change.
    Keep,
    /// Undo the applied change now.
    Undo,
}

/// What covers the dashboard.
#[derive(Debug, Clone)]
pub enum Overlay {
    Form(Box<Form>),
    /// What a change would do, before it is applied.
    Review {
        title: String,
        lines: Vec<(Tone, String)>,
        scroll: usize,
    },
}

#[derive(Debug, Clone, Copy, Default)]
pub struct List {
    pub cursor: usize,
    pub offset: usize,
}

impl List {
    /// Keep the cursor inside `len` rows and on screen in `height`.
    pub fn scroll(&mut self, len: usize, height: usize) {
        self.cursor = self.cursor.min(len.saturating_sub(1));
        let height = height.max(1);
        if self.cursor < self.offset {
            self.offset = self.cursor;
        } else if self.cursor >= self.offset + height {
            self.offset = self.cursor + 1 - height;
        }
        self.offset = self.offset.min(len.saturating_sub(height));
    }

    fn step(&mut self, delta: isize, len: usize) {
        if len == 0 {
            return;
        }
        self.cursor = (self.cursor as isize + delta).clamp(0, len as isize - 1) as usize;
    }
}

/// How exposed a service is, worst first: anyone, some networks, nobody,
/// this machine only.
pub fn exposure_rank(s: &Service) -> u8 {
    if s.local_only {
        return 3;
    }
    let answers: Vec<&Answer> = [&s.v4, &s.v6].into_iter().flatten().map(|r| &r.answer).collect();
    if answers.iter().any(|a| **a == Answer::Anywhere) {
        0
    } else if answers.iter().any(|a| matches!(a, Answer::From(_))) {
        1
    } else {
        2
    }
}

pub struct Screen {
    pub chains: Vec<ChainView>,
    pub services: Vec<Service>,
    pub packets: Result<Vec<Packet>, String>,
    pub logs: bool,
    /// The input chain's policy; None when nothing filters input.
    pub input_policy: Option<String>,
    pub version: String,
    pub open_to_anyone: usize,
    pub open_to_some: usize,
    pub live: bool,
    pub source: String,
    pub root: bool,

    pub tab: Tab,
    pub lists: [List; 3],
    pub rows: Vec<Row>,
    pub exposure_rows: Vec<usize>,
    pub blocked_rows: Vec<usize>,
    pub query: String,
    pub searching: bool,
    pub help: bool,
    pub message: Option<(Tone, String)>,
    pub hits: Vec<(Rect, Hit)>,

    /// Root and the live ruleset: the rules can be changed.
    pub can_edit: bool,
    pub overlay: Option<Overlay>,
    /// The form a review came from, to go back to.
    form: Option<Form>,
    /// An applied change waiting to be kept: what it was, and when it undoes itself.
    pub pending: Option<(String, Instant)>,
    names: Names,
    ruleset: Ruleset,
}

impl Screen {
    pub fn new(app: &App, report: Report) -> Screen {
        let mut screen = Screen {
            chains: Vec::new(),
            services: Vec::new(),
            packets: Ok(Vec::new()),
            logs: false,
            input_policy: None,
            version: String::new(),
            open_to_anyone: 0,
            open_to_some: 0,
            live: app.source.is_live(),
            source: app.source.describe(),
            root: crate::is_root(),
            tab: Tab::Rules,
            lists: [List::default(); 3],
            rows: Vec::new(),
            exposure_rows: Vec::new(),
            blocked_rows: Vec::new(),
            query: String::new(),
            searching: false,
            help: false,
            message: None,
            hits: Vec::new(),
            can_edit: app.source.is_live() && crate::is_root(),
            overlay: None,
            form: None,
            pending: None,
            names: app.names.clone(),
            ruleset: Ruleset::default(),
        };
        screen.set_report(app, report);
        screen
    }

    /// Show a new report, keeping the cursor on the same chain, rule, port.
    pub fn set_report(&mut self, app: &App, report: Report) {
        let rule_at = self.current_rule_id();
        let service_at = self.current_service().map(|s| (s.proto.clone(), s.port));
        let (anyone, some) = report.counts();
        self.open_to_anyone = anyone;
        self.open_to_some = some;
        self.chains = build(app, &report.ruleset);
        self.logs = report.ruleset.logs();
        self.version = report.ruleset.version.clone();
        self.input_policy =
            report.ruleset.hooked("input").first().and_then(|c| c.base.as_ref()).map(|b| b.policy.clone());
        let mut services = report.services;
        services.sort_by_key(|s| (exposure_rank(s), s.proto.clone(), s.port));
        self.services = services;
        self.packets = report.blocked;
        self.ruleset = report.ruleset;
        self.refilter();
        if let Some((key, handle)) = rule_at
            && let Some(n) = self.rows.iter().position(|row| match *row {
                Row::Chain(c) => handle.is_none() && self.chains[c].key == key,
                Row::Rule(c, r) => {
                    self.chains[c].key == key && Some(self.chains[c].rules[r].handle) == handle
                }
            })
        {
            self.lists[0].cursor = n;
        }
        if let Some((proto, port)) = service_at
            && let Some(n) = self.exposure_rows.iter().position(|&i| {
                let s = &self.services[i];
                s.proto == proto && s.port == port
            })
        {
            self.lists[1].cursor = n;
        }
    }

    fn current_rule_id(&self) -> Option<(ChainKey, Option<u64>)> {
        match self.rows.get(self.lists[0].cursor)? {
            Row::Chain(c) => Some((self.chains[*c].key.clone(), None)),
            Row::Rule(c, r) => Some((self.chains[*c].key.clone(), Some(self.chains[*c].rules[*r].handle))),
        }
    }

    /// Apply the search box to every tab.
    pub fn refilter(&mut self) {
        let query = self.query.trim().to_lowercase();
        self.rows.clear();
        for (c, chain) in self.chains.iter().enumerate() {
            let chain_matches = query.is_empty() || fuzzy::matches(&query, &[chain.path.to_lowercase()]);
            let rules: Vec<usize> = (0..chain.rules.len())
                .filter(|&r| chain_matches || fuzzy::matches(&query, &chain.rules[r].fields))
                .collect();
            if chain_matches || !rules.is_empty() {
                self.rows.push(Row::Chain(c));
                self.rows.extend(rules.into_iter().map(|r| Row::Rule(c, r)));
            }
        }
        self.exposure_rows = (0..self.services.len())
            .filter(|&i| query.is_empty() || fuzzy::matches(&query, &service_fields(&self.services[i])))
            .collect();
        self.blocked_rows = match &self.packets {
            Ok(packets) => (0..packets.len())
                .filter(|&i| query.is_empty() || fuzzy::matches(&query, &packet_fields(&packets[i])))
                .collect(),
            Err(_) => Vec::new(),
        };
        for (list, len) in
            self.lists.iter_mut().zip([self.rows.len(), self.exposure_rows.len(), self.blocked_rows.len()])
        {
            list.cursor = list.cursor.min(len.saturating_sub(1));
        }
    }

    pub fn len(&self, tab: Tab) -> usize {
        match tab {
            Tab::Rules => self.rows.len(),
            Tab::Exposure => self.exposure_rows.len(),
            Tab::Blocked => self.blocked_rows.len(),
        }
    }

    pub fn list(&mut self) -> &mut List {
        &mut self.lists[self.tab.index()]
    }

    pub fn current_row(&self) -> Option<Row> {
        self.rows.get(self.lists[0].cursor).copied()
    }

    pub fn current_service(&self) -> Option<&Service> {
        self.exposure_rows.get(self.lists[1].cursor).map(|&i| &self.services[i])
    }

    pub fn current_packet(&self) -> Option<&Packet> {
        let i = *self.blocked_rows.get(self.lists[2].cursor)?;
        self.packets.as_ref().ok()?.get(i)
    }

    fn switch(&mut self, delta: isize) {
        let n = Tab::ALL.len() as isize;
        self.tab = Tab::ALL[((self.tab.index() as isize + delta).rem_euclid(n)) as usize];
    }

    fn movement(&mut self, key: Key, page: usize) -> bool {
        let len = self.len(self.tab);
        let page = page.max(1) as isize;
        let list = self.list();
        match key {
            Key::Up | Key::Char('k') => list.step(-1, len),
            Key::Down | Key::Char('j') => list.step(1, len),
            Key::PageUp => list.step(-page, len),
            Key::PageDown => list.step(page, len),
            Key::Home | Key::Char('g') => list.cursor = 0,
            Key::End | Key::Char('G') => list.cursor = len.saturating_sub(1),
            _ => return false,
        }
        true
    }

    pub fn key(&mut self, key: Key, page: usize) -> Action {
        self.message = None;
        match &mut self.overlay {
            Some(Overlay::Form(form)) => {
                return match form.key(key) {
                    Outcome::Stay => Action::None,
                    Outcome::Cancel => {
                        self.overlay = None;
                        Action::None
                    }
                    Outcome::Submit(change) => {
                        self.form = Some((**form).clone());
                        self.overlay = None;
                        Action::Prepare(change)
                    }
                };
            }
            Some(Overlay::Review { scroll, .. }) => {
                match key {
                    Key::Enter | Key::Char('y') => return Action::Apply,
                    Key::Esc | Key::Char('n') | Key::Char('q') => {
                        // Back to the form it came from, to fix it.
                        self.overlay = self.form.take().map(|f| Overlay::Form(Box::new(f)));
                        return Action::Cancel;
                    }
                    Key::Up | Key::Char('k') => *scroll = scroll.saturating_sub(1),
                    Key::Down | Key::Char('j') => *scroll += 1,
                    _ => {}
                }
                return Action::None;
            }
            None => {}
        }
        if self.pending.is_some() && !self.searching && !self.help {
            match key {
                Key::Char('y') => return Action::Keep,
                Key::Char('n') => return Action::Undo,
                _ => {}
            }
        }
        if self.help {
            self.help = false;
            return if key == Key::Char('q') { Action::Quit } else { Action::None };
        }
        if self.searching {
            match key {
                Key::Char(c) => {
                    self.query.push(c);
                    self.refilter();
                }
                Key::Backspace => {
                    if self.query.pop().is_none() {
                        self.searching = false;
                    }
                    self.refilter();
                }
                Key::Enter => self.searching = false,
                Key::Esc => {
                    self.searching = false;
                    self.query.clear();
                    self.refilter();
                }
                Key::Tab => self.switch(1),
                Key::BackTab => self.switch(-1),
                other => {
                    self.movement(other, page);
                }
            }
            return Action::None;
        }
        if self.movement(key, page) {
            return Action::None;
        }
        if let Key::Char(c @ ('a' | 'e' | 'd' | 'L')) = key {
            return self.edit_key(c);
        }
        match key {
            Key::Char('q') => return Action::Quit,
            Key::Char('r') => return Action::Reload,
            Key::Char('/') => self.searching = true,
            Key::Char('?') => self.help = true,
            Key::Tab | Key::Right | Key::Char('l') => self.switch(1),
            Key::BackTab | Key::Left | Key::Char('h') => self.switch(-1),
            Key::Char(c @ '1'..='3') => self.tab = Tab::ALL[c as usize - '1' as usize],
            Key::Esc if !self.query.is_empty() => {
                self.query.clear();
                self.refilter();
            }
            _ => {}
        }
        Action::None
    }

    /// Show what a prepared change would do.
    pub fn show_review(&mut self, title: String, lines: Vec<(Tone, String)>) {
        self.overlay = Some(Overlay::Review { title, lines, scroll: 0 });
    }

    /// A change that failed its check: back to the form it came from.
    pub fn back_to_form(&mut self) {
        if let Some(form) = self.form.take() {
            self.overlay = Some(Overlay::Form(Box::new(form)));
        }
    }

    /// The review is done with: applied, or failed to apply.
    pub fn close_review(&mut self) {
        self.overlay = None;
        self.form = None;
    }

    /// The form's rule in words, or why it is not a rule yet.
    pub fn form_sentence(&self, form: &Form) -> Result<String, String> {
        let ctx = Ctx {
            names: &self.names,
            ruleset: &self.ruleset,
            family: &form.chain.family,
            table: &form.chain.table,
        };
        match form.spec.analysis() {
            Some(a) => Ok(sentence(&a, &ctx)),
            None => Err(form.spec.to_nft().err().map(|e| e.0).unwrap_or_default()),
        }
    }

    fn open_form(&mut self, mut form: Form, before: Option<u64>, replace: Option<u64>) {
        let chain = self.chains.iter().find(|c| c.key == form.chain);
        let number = |h: u64| chain.and_then(|c| c.rules.iter().position(|r| r.handle == h)).map(|i| i + 1);
        form.place = match (replace, before) {
            (Some(h), _) => format!("in place of rule {}", number(h).unwrap_or(0)),
            (None, Some(h)) => format!("above rule {} of {}", number(h).unwrap_or(0), form.chain.chain),
            (None, None) => format!("at the end of {}", form.chain.chain),
        };
        form.before = before;
        form.replace = replace;
        self.overlay = Some(Overlay::Form(Box::new(form)));
    }

    /// The chain new rules from Exposure and Blocked go to: the first
    /// filter chain on the input hook.
    fn input_chain(&self) -> Option<&ChainView> {
        let mut inputs: Vec<&ChainView> = self
            .chains
            .iter()
            .filter(|c| c.base.as_ref().is_some_and(|b| b.hook == "input" && b.kind == "filter"))
            .collect();
        inputs.sort_by_key(|c| c.base.as_ref().map(|b| b.priority));
        inputs.into_iter().next()
    }

    fn edit_key(&mut self, c: char) -> Action {
        let say = |screen: &mut Screen, text: &str| {
            screen.message = Some((Tone::Error, text.to_owned()));
            Action::None
        };
        if !self.can_edit {
            return say(self, "changing rules needs the live ruleset: run nft-patrol with sudo");
        }
        if self.pending.is_some() {
            return say(self, "keep (y) or undo (n) the last change first");
        }
        let networks = self.names.choices();
        match (c, self.tab) {
            ('L', _) => {
                let Some(chain) = self.input_chain() else {
                    return say(self, "there is no input chain to log in");
                };
                let op = match chain.log_handle {
                    Some(handle) => Op::Delete { handle },
                    None => Op::Insert { before: chain.default_before, rule: edit::log_rule_text() },
                };
                let title = if chain.log_handle.is_some() {
                    "Stop logging blocked packets".to_owned()
                } else {
                    "Log blocked packets (at most 10 a second)".to_owned()
                };
                Action::Prepare(Change { chain: chain.key.clone(), op, title })
            }
            ('a', Tab::Rules) => {
                let (chain, before) = match self.current_row() {
                    Some(Row::Rule(c, r)) => (&self.chains[c], Some(self.chains[c].rules[r].handle)),
                    Some(Row::Chain(c)) => (&self.chains[c], self.chains[c].default_before),
                    None => return say(self, "there is no chain to add a rule to"),
                };
                let form = Form::new(
                    format!("Add a rule to {}", chain.path),
                    chain.key.clone(),
                    Spec::default(),
                    networks,
                );
                self.open_form(form, before, None);
                Action::None
            }
            ('a', Tab::Exposure) => {
                let Some(s) = self.current_service() else { return Action::None };
                let spec = Spec {
                    proto: if s.proto == "udp" { Proto::Udp } else { Proto::Tcp },
                    ports: s.port.to_string(),
                    ..Spec::default()
                };
                let title = format!("Allow {} {}", s.proto, s.port);
                let Some(chain) = self.input_chain() else { return say(self, "there is no input chain") };
                let (key, before) = (chain.key.clone(), chain.default_before);
                self.open_form(Form::new(title, key, spec, networks), before, None);
                Action::None
            }
            ('a', Tab::Blocked) => {
                let Some(p) = self.current_packet() else { return Action::None };
                let proto = match p.proto.to_lowercase().as_str() {
                    "tcp" => Proto::Tcp,
                    "udp" => Proto::Udp,
                    _ => Proto::Any,
                };
                let spec = Spec {
                    proto,
                    ports: if proto == Proto::Any {
                        String::new()
                    } else {
                        p.dport.map(|d| d.to_string()).unwrap_or_default()
                    },
                    from: p.src.clone(),
                    ..Spec::default()
                };
                let title = format!("Allow what {} was blocked from", p.src);
                let Some(chain) = self.input_chain() else { return say(self, "there is no input chain") };
                let (key, before) = (chain.key.clone(), chain.default_before);
                self.open_form(Form::new(title, key, spec, networks), before, None);
                Action::None
            }
            ('e', Tab::Rules) => {
                let Some(Row::Rule(c, r)) = self.current_row() else {
                    return say(self, "pick a rule to change");
                };
                let (chain, rule) = (&self.chains[c], &self.chains[c].rules[r]);
                let Some(spec) = rule.spec.clone() else {
                    return say(
                        self,
                        "this rule does more than the form can say: change it in the nftables file",
                    );
                };
                let form = Form::new(format!("Change rule {}", r + 1), chain.key.clone(), spec, networks);
                let handle = rule.handle;
                self.open_form(form, None, Some(handle));
                Action::None
            }
            ('d', Tab::Rules) => {
                let Some(Row::Rule(c, r)) = self.current_row() else {
                    return say(self, "pick a rule to delete");
                };
                let (chain, rule) = (&self.chains[c], &self.chains[c].rules[r]);
                Action::Prepare(Change {
                    chain: chain.key.clone(),
                    op: Op::Delete { handle: rule.handle },
                    title: format!("Delete rule {}: {}", r + 1, rule.sentence),
                })
            }
            _ => Action::None,
        }
    }

    pub fn click(&mut self, x: u16, y: u16) -> Action {
        self.message = None;
        if self.help {
            self.help = false;
            return Action::None;
        }
        let hit =
            self.hits.iter().find(|(r, _)| r.contains(ratatui::layout::Position { x, y })).map(|(_, h)| *h);
        match hit {
            Some(Hit::Tab(tab)) => self.tab = tab,
            Some(Hit::Row(n)) => self.list().cursor = n,
            None => {}
        }
        Action::None
    }

    pub fn wheel(&mut self, down: bool) -> Action {
        let len = self.len(self.tab);
        self.list().step(if down { 3 } else { -3 }, len);
        Action::None
    }
}

pub fn service_fields(s: &Service) -> Vec<String> {
    let mut f = vec![format!("{} {}", s.proto, s.port), s.port.to_string()];
    f.extend(s.name.clone());
    f.extend(s.process.as_ref().map(|p| p.0.clone()));
    f.extend([&s.v4, &s.v6].into_iter().flatten().map(|r| r.short()));
    f.into_iter().map(|x| x.to_lowercase()).collect()
}

pub fn packet_fields(p: &Packet) -> Vec<String> {
    let mut f = vec![p.src.clone(), p.dst.clone(), p.proto.clone(), p.iface.clone(), p.prefix.clone()];
    f.extend(p.dport.map(|d| d.to_string()));
    f.push(p.time.format("%Y-%m-%d %H:%M").to_string());
    f.into_iter().map(|x| x.to_lowercase()).collect()
}

/// What a chain's policy means, for the panels.
pub fn chain_words(chain: &ChainView) -> String {
    match &chain.base {
        Some(base) => policy_words(&base.hook, &base.policy),
        None => "a regular chain: rules jump here".into(),
    }
}
