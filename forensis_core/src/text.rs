//! CPython string semantics shared by the engines.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use regex::Regex;

/// `str.isspace()` for one char: Unicode White_Space plus U+001C..U+001F.
pub fn is_py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `str.strip()`.
pub fn py_strip(s: &str) -> &str {
    s.trim_matches(is_py_space)
}

/// A Python `re` pattern compiled for the regex crate. `\s`/`\S` get CPython's extra U+001C..U+001F,
/// `(?i)` is added for patterns the reference compiles with `re.I`.
pub fn compile(pattern: &str, ignore_case: bool) -> PyResult<Regex> {
    // shortcut: plain token replace, so `\s` inside a character class or an escaped backslash before `s`
    // would be mistranslated (none of the reference patterns have either); the regex crate's Unicode
    // tables for \w, \b and case folding still differ from CPython's on a few code points (combining marks)
    let translated = pattern
        .replace(r"\S", r"[^\s\x1c-\x1f]")
        .replace(r"\s", r"[\s\x1c-\x1f]");
    let flags = if ignore_case { "(?i)" } else { "" };
    Regex::new(&format!("{flags}{translated}")).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpython_whitespace() {
        assert_eq!(py_strip("\u{1f} x \u{85}"), "x");
        let re = compile(r"a\sb\S", false).unwrap();
        assert!(re.is_match("a\u{1c}bX"));
        assert!(!re.is_match("a\u{1c}b\u{1f}")); // \u{1f} is space for CPython, so not \S
        assert!(!re.is_match("a b "));
    }
}
