// SPDX-License-Identifier: GPL-3.0-or-later
//! How the TUI looks: Adwaita dark colours, Nerd Font icons, and the small
//! formatting rules (counts, sizes) the panels share.
//!
//! Each has a fallback. Without a true-colour terminal the palette is the
//! terminal's own ANSI colours; on the Linux console or a non-UTF-8 locale
//! the icons are letters; with `--color never` nothing is coloured and the
//! selection is reverse video - nothing is told apart by colour alone.

use ratatui::style::{Color, Modifier, Style};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    pub fg: Color,
    pub muted: Color,
    pub subtle: Color,
    pub border: Color,
    pub selection: Color,
    pub blue: Color,
    pub cyan: Color,
    pub purple: Color,
    pub green: Color,
    pub yellow: Color,
    pub orange: Color,
    pub red: Color,
    /// Text on a coloured pill.
    pub on_pill: Color,
}

/// Adwaita dark, GNOME's palette - the rest of the desktop's.
pub const ADWAITA_DARK: Palette = Palette {
    fg: Color::Rgb(0xff, 0xff, 0xff),
    muted: Color::Rgb(0x77, 0x76, 0x7b),
    subtle: Color::Rgb(0xc0, 0xbf, 0xbc),
    border: Color::Rgb(0x3d, 0x3d, 0x42),
    selection: Color::Rgb(0x36, 0x36, 0x3a),
    blue: Color::Rgb(0x78, 0xae, 0xed),
    cyan: Color::Rgb(0x99, 0xc1, 0xf1),
    purple: Color::Rgb(0xdc, 0x8a, 0xdd),
    green: Color::Rgb(0x8f, 0xf0, 0xa4),
    yellow: Color::Rgb(0xf8, 0xe4, 0x5c),
    orange: Color::Rgb(0xff, 0xa3, 0x48),
    red: Color::Rgb(0xff, 0x7b, 0x63),
    on_pill: Color::Rgb(0x22, 0x22, 0x26),
};

/// The terminal's own colours, for terminals without true colour.
pub const ANSI: Palette = Palette {
    fg: Color::Reset,
    muted: Color::DarkGray,
    subtle: Color::Gray,
    border: Color::DarkGray,
    selection: Color::DarkGray,
    blue: Color::Blue,
    cyan: Color::Cyan,
    purple: Color::Magenta,
    green: Color::Green,
    yellow: Color::Yellow,
    orange: Color::LightRed,
    red: Color::Red,
    on_pill: Color::Black,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Icons {
    pub logo: &'static str,
    pub rules: &'static str,
    pub exposure: &'static str,
    pub blocked: &'static str,
    pub ok: &'static str,
    pub warn: &'static str,
    pub search: &'static str,
    pub open: &'static str,
    pub bar: &'static str,
    pub arrow: &'static str,
    pub enter: &'static str,
    pub updown: &'static str,
    pub dot: &'static str,
    pub dash: &'static str,
    pub quote: (&'static str, &'static str),
}

pub const NERD: Icons = Icons {
    logo: "\u{F0483}",     // nf-md-shield_lock
    rules: "\u{F0279}",    // nf-md-format_list_bulleted
    exposure: "\u{F0317}", // nf-md-lan
    blocked: "\u{F0159}",  // nf-md-close_circle
    ok: "\u{F05E0}",       // nf-md-check_circle
    warn: "\u{F0028}",     // nf-md-alert_circle
    search: "\u{F0349}",   // nf-md-magnify
    open: "▾",
    bar: "▌",
    arrow: "→",
    enter: "⏎",
    updown: "↑↓",
    dot: "·",
    dash: "—",
    quote: ("“", "”"),
};

/// Box-drawing and arrows still work; only the Nerd Font icons go.
pub const UNICODE: Icons =
    Icons {
        logo: "◈", rules: "≡", exposure: "◎", blocked: "✕", ok: "✓", warn: "!", search: "/", ..NERD
    };

pub const ASCII: Icons = Icons {
    logo: "#",
    rules: "",
    exposure: "",
    blocked: "",
    open: "v",
    bar: ">",
    arrow: "->",
    enter: "enter",
    updown: "up/dn",
    ok: "ok",
    dot: "-",
    dash: "-",
    quote: ("\"", "\""),
    ..UNICODE
};

#[derive(Debug, Clone, Copy)]
pub struct Look {
    pub color: bool,
    pub palette: Palette,
    pub icons: Icons,
    /// Rounded box-drawing borders; plain ASCII ones without UTF-8.
    pub unicode: bool,
}

impl Look {
    /// The look for this terminal: true colour if it says so, Nerd Font
    /// icons unless it is the Linux console, ASCII without a UTF-8 locale.
    pub fn detect(color: bool) -> Look {
        let truecolor = std::env::var("COLORTERM").is_ok_and(|v| v == "truecolor" || v == "24bit");
        let console = std::env::var("TERM").is_ok_and(|t| t == "linux");
        let unicode = locale_is_utf8();
        let icons = match (unicode, console) {
            (false, _) => ASCII,
            (true, true) => UNICODE,
            (true, false) => NERD,
        };
        Look { color, palette: if truecolor { ADWAITA_DARK } else { ANSI }, icons, unicode }
    }

    pub fn fg(&self, color: Color) -> Style {
        if self.color { Style::new().fg(color) } else { Style::new() }
    }

    pub fn text(&self) -> Style {
        self.fg(self.palette.fg)
    }

    pub fn muted(&self) -> Style {
        self.fg(self.palette.muted)
    }

    pub fn bold(&self, color: Color) -> Style {
        self.fg(color).add_modifier(Modifier::BOLD)
    }

    pub fn border(&self, focused: bool) -> Style {
        self.fg(if focused { self.palette.blue } else { self.palette.border })
    }

    /// A coloured badge: dark text on `color`, or bold brackets without colour.
    pub fn pill(&self, color: Color) -> Style {
        if self.color {
            Style::new().fg(self.palette.on_pill).bg(color).add_modifier(Modifier::BOLD)
        } else {
            Style::new().add_modifier(Modifier::BOLD)
        }
    }

    pub fn selected(&self) -> Style {
        if self.color {
            Style::new().bg(self.palette.selection)
        } else {
            Style::new().add_modifier(Modifier::REVERSED)
        }
    }
}

pub fn locale_is_utf8() -> bool {
    ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .find(|v| !v.is_empty())
        .is_some_and(|v| {
            let v = v.to_lowercase();
            v.contains("utf-8") || v.contains("utf8")
        })
}

/// A hit count in four columns or fewer: "7", "1.2k", "57k", "3.4M".
pub fn count(n: u64) -> String {
    let (value, unit) = match n {
        n if n < 1000 => return n.to_string(),
        n if n < 1_000_000 => (n as f64 / 1e3, "k"),
        n if n < 1_000_000_000 => (n as f64 / 1e6, "M"),
        n => (n as f64 / 1e9, "G"),
    };
    if value < 10.0 { format!("{value:.1}{unit}") } else { format!("{value:.0}{unit}") }
}

/// Bytes in binary units: "0 B", "512 KiB", "312.4 MiB", "1.2 GiB".
pub fn size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    let number = if unit == 0 || value >= 100.0 { format!("{value:.0}") } else { format!("{value:.1}") };
    format!("{} {}", number.strip_suffix(".0").unwrap_or(&number), UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(size(0), "0 B");
        assert_eq!(size(1023), "1023 B");
        assert_eq!(size(512 * 1024), "512 KiB");
        assert_eq!(size(1_288_490_189), "1.2 GiB");
    }

    #[test]
    fn counts() {
        assert_eq!(count(7), "7");
        assert_eq!(count(1234), "1.2k");
        assert_eq!(count(56_789), "57k");
        assert_eq!(count(3_400_000), "3.4M");
    }
}
