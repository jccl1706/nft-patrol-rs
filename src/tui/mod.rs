// SPDX-License-Identifier: GPL-3.0-or-later
//! `nft-patrol` (or `nft-patrol tui`): the dashboard.

mod form;
mod fuzzy;
mod screen;
mod theme;
mod view;

use std::io::IsTerminal;
use std::time::{Duration, Instant, SystemTime};

use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers, MouseButton,
    MouseEventKind,
};
use ratatui::crossterm::execute;

use self::screen::{Action, Key, Screen, Tone};
use self::theme::Look;
use crate::error::Result;
use crate::report::Report;
use crate::source::Source;
use crate::{App, apply, bail, err, table};

/// How often the live ruleset, its counters and the sockets are re-read.
const LIVE: Duration = Duration::from_secs(2);
/// How often a file is checked for changes.
const WATCH: Duration = Duration::from_secs(1);
const TICK: Duration = Duration::from_millis(250);

pub fn run(app: &App) -> Result<u8> {
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        bail!("the dashboard needs a terminal (try nft-patrol list or status)");
    }
    // Anything that can fail on the way in fails here, on an ordinary screen.
    let report = Report::load(app, true)?;
    let mut screen = Screen::new(app, report);
    if !screen.live {
        screen.message = Some((
            Tone::Dim,
            "the saved rules, as written - run with sudo for the live ones and their hit counts".into(),
        ));
    }
    let look = Look::detect(table::color_enabled(app.color, true));

    // init() restores the terminal on a panic; mouse reporting is ours to
    // turn off first, or the shell is left full of escape codes.
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = execute!(std::io::stdout(), DisableMouseCapture);
        hook(info);
    }));
    let mut terminal = ratatui::init();
    let _ = execute!(std::io::stdout(), EnableMouseCapture);
    let result = event_loop(&mut terminal, app, &mut screen, look);
    let _ = execute!(std::io::stdout(), DisableMouseCapture);
    ratatui::restore();
    result
}

fn input(code: KeyCode, modifiers: KeyModifiers) -> Option<Key> {
    Some(match code {
        KeyCode::Char(_) if modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) => return None,
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::Left => Key::Left,
        KeyCode::Right => Key::Right,
        KeyCode::PageUp => Key::PageUp,
        KeyCode::PageDown => Key::PageDown,
        KeyCode::Home => Key::Home,
        KeyCode::End => Key::End,
        KeyCode::Tab => Key::Tab,
        KeyCode::BackTab => Key::BackTab,
        KeyCode::Enter => Key::Enter,
        KeyCode::Esc => Key::Esc,
        KeyCode::Backspace => Key::Backspace,
        KeyCode::Char(c) => Key::Char(c),
        _ => return None,
    })
}

fn modified(app: &App) -> Option<SystemTime> {
    match &app.source {
        Source::File(path) => std::fs::metadata(path).and_then(|m| m.modified()).ok(),
        Source::Live => None,
    }
}

/// Read everything again; a failure is shown and the old report kept.
fn reload(app: &App, screen: &mut Screen, say: bool) {
    match Report::load(app, true) {
        Ok(report) => {
            screen.set_report(app, report);
            if say {
                screen.message = Some((Tone::Ok, "reloaded".into()));
            }
        }
        Err(e) => screen.message = Some((Tone::Error, e.0)),
    }
}

/// Say what is happening and draw it, before something slow.
fn busy(terminal: &mut ratatui::DefaultTerminal, screen: &mut Screen, look: Look, text: &str) -> Result<()> {
    screen.message = Some((Tone::Accent, text.to_owned()));
    terminal
        .draw(|frame| {
            view::draw(frame, screen, look);
        })
        .map_err(|e| err!("terminal: {e}"))?;
    Ok(())
}

/// What the review shows of a prepared change.
fn review_lines(plan: &apply::Plan) -> Vec<(Tone, String)> {
    let mut lines = vec![(Tone::Heading, "The rule".to_owned())];
    for d in &plan.diff {
        lines.push((if d.starts_with('-') { Tone::Error } else { Tone::Ok }, d.clone()));
    }
    lines.push((Tone::Dim, String::new()));
    lines.push((Tone::Heading, "Who can reach this machine's ports".to_owned()));
    match &plan.unpredicted {
        Some(why) => lines.push((Tone::Dim, format!("could not be worked out beforehand: {why}"))),
        None if plan.exposure.is_empty() => lines.push((Tone::Dim, "no listening port changes".to_owned())),
        None => lines.extend(plan.exposure.iter().map(|e| (Tone::Accent, e.clone()))),
    }
    for w in &plan.warnings {
        lines.push((Tone::Dim, String::new()));
        lines.push((Tone::Error, format!("WARNING: {w}")));
    }
    lines.push((Tone::Dim, String::new()));
    lines.push((
        Tone::Dim,
        format!(
            "Enter applies it. Then y keeps it; without y it undoes itself in {} seconds. Esc goes back.",
            apply::GRACE.as_secs()
        ),
    ));
    lines
}

fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    app: &App,
    screen: &mut Screen,
    look: Look,
) -> Result<u8> {
    let io = |e: std::io::Error| err!("terminal: {e}");
    let mut checked = Instant::now();
    let mut seen = modified(app);
    // A change under review, and one applied but not yet kept.
    let mut plan: Option<apply::Plan> = None;
    let mut pending = if screen.can_edit { apply::recover() } else { None };
    let mut warned_quit = false;
    let mut redraw = false;
    loop {
        screen.pending = pending.as_ref().map(|p| (p.title.clone(), p.deadline));
        if pending.is_some() && checked.elapsed() >= Duration::from_millis(500) && apply::expired() {
            pending = None;
            screen.pending = None;
            reload(app, screen, false);
            screen.message =
                Some((Tone::Error, "not kept, so it was undone: the firewall is as it was".into()));
        }
        let every = if screen.live { LIVE } else { WATCH };
        if checked.elapsed() >= every {
            checked = Instant::now();
            if screen.live {
                reload(app, screen, false);
            } else if modified(app) != seen {
                seen = modified(app);
                reload(app, screen, false);
                if screen.message.as_ref().is_none_or(|(t, _)| *t != Tone::Error) {
                    screen.message = Some((Tone::Accent, format!("{} changed: reloaded", screen.source)));
                }
            }
        }
        if std::mem::take(&mut redraw) {
            terminal.clear().map_err(io)?;
        }
        let mut page = 1;
        terminal.draw(|frame| page = view::draw(frame, screen, look)).map_err(io)?;
        if !event::poll(TICK).map_err(io)? {
            continue;
        }
        let action = match event::read().map_err(io)? {
            Event::Key(k) if k.kind == KeyEventKind::Press => {
                // Raw mode makes Ctrl+C an ordinary key; it must still quit.
                if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
                    Action::Quit
                } else {
                    match input(k.code, k.modifiers) {
                        Some(key) => screen.key(key, page),
                        None => Action::None,
                    }
                }
            }
            Event::Mouse(m) => match m.kind {
                MouseEventKind::Down(MouseButton::Left) => screen.click(m.column, m.row),
                MouseEventKind::ScrollDown => screen.wheel(true),
                MouseEventKind::ScrollUp => screen.wheel(false),
                _ => Action::None,
            },
            _ => Action::None,
        };
        if action != Action::Quit {
            warned_quit = false;
        }
        // Whatever ran for a change, a full redraw leaves no trace of it.
        if matches!(action, Action::Prepare(_) | Action::Apply | Action::Keep | Action::Undo) {
            redraw = true;
        }
        match action {
            Action::None => {}
            Action::Quit if pending.is_some() && !warned_quit => {
                warned_quit = true;
                screen.message = Some((
                    Tone::Error,
                    "a change is waiting: y keeps it, n undoes it - q again quits and it undoes itself"
                        .into(),
                ));
            }
            Action::Quit => return Ok(0),
            Action::Reload => {
                seen = modified(app);
                reload(app, screen, true);
            }
            Action::Prepare(change) => {
                busy(terminal, screen, look, "checking the change…")?;
                let title = change.title.clone();
                match app.source.load().and_then(|live| apply::prepare(app, &live, change)) {
                    Ok(p) => {
                        screen.message = None;
                        screen.show_review(title, review_lines(&p));
                        plan = Some(p);
                    }
                    Err(e) => {
                        screen.back_to_form();
                        screen.message = Some((Tone::Error, e.0));
                    }
                }
            }
            Action::Cancel => plan = None,
            Action::Apply => {
                if let Some(p) = plan.take() {
                    busy(terminal, screen, look, "applying…")?;
                    screen.close_review();
                    match apply::apply(&p) {
                        Ok(applied) => {
                            pending = Some(applied);
                            reload(app, screen, false);
                            screen.message = None;
                        }
                        Err(e) => screen.message = Some((Tone::Error, e.0)),
                    }
                }
            }
            Action::Keep => {
                if let Some(p) = pending.take() {
                    let result = apply::keep(&p);
                    reload(app, screen, false);
                    screen.message = Some(match result {
                        Ok(text) => (Tone::Ok, text),
                        Err(e) => (Tone::Error, e.0),
                    });
                }
            }
            Action::Undo => {
                if pending.take().is_some() {
                    let result = apply::undo();
                    reload(app, screen, false);
                    screen.message = Some(match result {
                        Ok(()) => (Tone::Ok, "undone: the firewall is as it was".into()),
                        Err(e) => (Tone::Error, format!("undo failed: {}", e.0)),
                    });
                }
            }
        }
    }
}
