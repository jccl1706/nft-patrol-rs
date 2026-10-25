// SPDX-License-Identifier: GPL-3.0-or-later
//! The search box: each word of the query must be found in one of a row's
//! fields, as a substring ("192.168", "ssh") or fuzzily within a single
//! word that starts with the same letter ("rfse" in "refuse"). Looser than
//! that matches nearly anything: "ssh" is in "eStabliSHed".

/// Whether `needle`'s characters appear in `haystack` in order.
pub fn subsequence(needle: &str, haystack: &str) -> bool {
    let mut chars = haystack.chars();
    needle.chars().all(|n| chars.any(|h| h == n))
}

fn word_matches(word: &str, field: &str) -> bool {
    field.contains(word)
        || (word.len() >= 3
            && field
                .split(|c: char| !c.is_alphanumeric())
                .any(|w| w.chars().next() == word.chars().next() && subsequence(word, w)))
}

/// `query` lowercase; `fields` lowercase.
pub fn matches(query: &str, fields: &[String]) -> bool {
    query.split_whitespace().all(|word| fields.iter().any(|f| word_matches(word, f)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words() {
        let fields = vec!["allow ssh (tcp 22) from 192.168.10.0/24".to_owned(), "allow".to_owned()];
        for q in ["ssh", "192.168", "alw", "ssh 22", "tcp allow"] {
            assert!(matches(q, &fields), "{q}");
        }
        let replies = vec!["connection state is established or related".to_owned()];
        assert!(!matches("ssh", &replies));
        for q in ["udp", "ssh udp", "zz"] {
            assert!(!matches(q, &fields), "{q}");
        }
    }
}
