// SPDX-License-Identifier: GPL-3.0-or-later
//! Text for the terminal: colours, and cutting text to fit, shared by the
//! commands and the TUI.

use std::io::IsTerminal;

use unicode_width::UnicodeWidthChar;

use crate::config::ColorChoice;

pub fn color_enabled(setting: ColorChoice, is_terminal: bool) -> bool {
    match setting {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => {
            is_terminal
                && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
                && std::env::var_os("TERM").is_none_or(|v| v != "dumb")
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Style {
    pub enabled: bool,
}

impl Style {
    pub fn for_stdout(setting: ColorChoice) -> Style {
        Style { enabled: color_enabled(setting, std::io::stdout().is_terminal()) }
    }

    fn sgr(&self, code: &str, text: &str) -> String {
        if self.enabled { format!("\x1b[{code}m{text}\x1b[0m") } else { text.to_owned() }
    }

    pub fn bold(&self, text: &str) -> String {
        self.sgr("1", text)
    }
    pub fn dim(&self, text: &str) -> String {
        self.sgr("2", text)
    }
    pub fn red(&self, text: &str) -> String {
        self.sgr("1;31", text)
    }
    pub fn green(&self, text: &str) -> String {
        self.sgr("1;32", text)
    }
    pub fn yellow(&self, text: &str) -> String {
        self.sgr("1;33", text)
    }
    pub fn blue(&self, text: &str) -> String {
        self.sgr("1;34", text)
    }
}

/// Unicode format characters (Cf) that matter here: zero-width characters
/// and the bidirectional overrides that reorder what is displayed.
fn is_format(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206F}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}'
        | '\u{E0001}' | '\u{E0020}'..='\u{E007F}')
}

fn is_private_use(c: char) -> bool {
    matches!(c, '\u{E000}'..='\u{F8FF}' | '\u{F0000}'..='\u{FFFFD}' | '\u{100000}'..='\u{10FFFD}')
}

/// Text safe to print.
///
/// Comments, log prefixes, interface and set names come from whoever wrote
/// the ruleset, and from the network. A newline splits a row; an escape
/// sequence is obeyed, not shown, so a comment could clear the screen; a
/// bidi override reorders what is displayed. This is only how it is shown.
pub fn printable(text: &str) -> String {
    text.chars()
        .filter_map(|c| {
            if c.is_control() {
                Some(' ') // newline, tab, escape: keep the words apart
            } else if is_format(c) || is_private_use(c) {
                None
            } else {
                Some(c)
            }
        })
        .collect()
}

/// Terminal columns one character occupies: 0 combining, 2 wide, else 1.
pub fn char_width(c: char) -> usize {
    c.width().unwrap_or(0)
}

/// Terminal columns text occupies, which is not its length for CJK or emoji.
pub fn display_width(text: &str) -> usize {
    text.chars().map(char_width).sum()
}

/// Pad to `width` display columns.
pub fn pad(text: &str, width: usize, right: bool) -> String {
    let filler = " ".repeat(width.saturating_sub(display_width(text)));
    if right { filler + text } else { format!("{text}{filler}") }
}

/// Cut to `limit` display columns, ending with '…', without splitting a character.
pub fn truncate(text: &str, limit: usize) -> String {
    if display_width(text) <= limit {
        return text.to_owned();
    }
    let mut kept = String::new();
    let mut used = 0;
    for c in text.chars() {
        let width = char_width(c);
        if used + width + 1 > limit {
            break;
        }
        kept.push(c);
        used += width;
    }
    kept + "…"
}

/// Wrap on whitespace to `limit` display columns, breaking a long word if it must.
pub fn wrap_text(text: &str, limit: usize) -> Vec<String> {
    let limit = limit.max(1);
    let mut lines = Vec::new();
    let (mut current, mut used) = (String::new(), 0);
    for word in text.split_whitespace() {
        let mut word = word.to_owned();
        let mut width = display_width(&word);
        if !current.is_empty() && used + 1 + width > limit {
            lines.push(std::mem::take(&mut current));
            used = 0;
        }
        while width > limit {
            // A single word wider than the column: as much as fits, at least one character.
            let mut head = String::new();
            let mut head_width = 0;
            for c in word.chars() {
                if head_width + char_width(c) > limit && !head.is_empty() {
                    break;
                }
                head.push(c);
                head_width += char_width(c);
            }
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
                used = 0;
            }
            lines.push(head.clone());
            word = word[head.len()..].to_owned();
            width = display_width(&word);
        }
        if word.is_empty() {
            continue;
        }
        if current.is_empty() {
            current = word;
            used = width;
        } else {
            current.push(' ');
            current.push_str(&word);
            used += 1 + width;
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}
