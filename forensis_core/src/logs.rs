//! Native per-event classification for the log analyzer. `classify_events` returns, per event,
//! exactly what `forensis.analyzers.log_analyzer._classify_event` (the reference) returns.

use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyInt, PyList, PyString};

use crate::text::compile;

/// `_event_source` keys, in `or` order.
const SOURCE_KEYS: [&str; 5] = ["ip", "host", "src_ip", "source_ip", "client_ip"];
/// `_event_text` keys, in join order.
const TEXT_KEYS: [&str; 7] = [
    "message", "raw", "path", "request", "uri", "process", "user",
];
/// Events per GIL-free matching batch (bounds the texts held at once).
const BATCH: usize = 4096;

/// `str(obj)` as text. Lone surrogates become U+FFFD; the text is only matched, never returned.
fn text_of(obj: &Bound<'_, PyAny>) -> PyResult<String> {
    Ok(match obj.cast::<PyString>() {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => obj.str()?.to_string_lossy().into_owned(),
    })
}

/// `urllib.parse.unquote_plus(s)` (utf-8, errors="replace"): '+' becomes ' ', each ASCII run is
/// percent-decoded to bytes and decoded on its own, non-ASCII text is kept verbatim, as CPython does.
fn unquote_plus(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut run: Vec<u8> = Vec::new();
    let hex = |j: usize| bytes.get(j).and_then(|c| (*c as char).to_digit(16));
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b >= 0x80 {
            out.push_str(&String::from_utf8_lossy(&run));
            run.clear();
            // `i` is on a char boundary: only whole chars are consumed.
            let tail = &s[i..];
            let n = tail.chars().next().map_or(1, char::len_utf8);
            out.push_str(&tail[..n]);
            i += n;
            continue;
        }
        match (b, hex(i + 1), hex(i + 2)) {
            (b'%', Some(hi), Some(lo)) => {
                run.push((hi * 16 + lo) as u8);
                i += 3;
            }
            (b'+', _, _) => {
                run.push(b' ');
                i += 1;
            }
            _ => {
                run.push(b);
                i += 1;
            }
        }
    }
    out.push_str(&String::from_utf8_lossy(&run));
    out
}

/// `_event_text(evt)`.
fn event_text(evt: &Bound<'_, PyDict>, keys: &[Bound<'_, PyString>]) -> PyResult<String> {
    let mut parts = Vec::with_capacity(keys.len());
    for k in keys {
        if let Some(v) = evt.get_item(k)? {
            if !v.is_none() {
                parts.push(text_of(&v)?);
            }
        }
    }
    let raw = parts.join(" ").to_lowercase();
    let decoded = unquote_plus(&raw);
    Ok(if decoded == raw {
        raw
    } else {
        format!("{raw} {decoded}")
    })
}

/// `_event_source(evt)`: the first truthy key as `str()`, else "unknown".
fn event_source<'py>(
    py: Python<'py>,
    evt: &Bound<'py, PyDict>,
    keys: &[Bound<'py, PyString>],
) -> PyResult<Bound<'py, PyAny>> {
    for k in keys {
        if let Some(v) = evt.get_item(k)? {
            if v.is_truthy()? {
                return Ok(v.str()?.into_any());
            }
        }
    }
    Ok(PyString::new(py, "unknown").into_any())
}

/// `_to_int(value)`: `int(value)` or None. Only plain ints and short decimal strings are converted
/// here; everything else goes through Python's `int()`, so every conversion rule stays Python's.
fn to_int<'py>(
    py: Python<'py>,
    value: Option<Bound<'py, PyAny>>,
    int_builtin: &Bound<'py, PyAny>,
) -> PyResult<Option<Bound<'py, PyAny>>> {
    let Some(v) = value else { return Ok(None) };
    if v.is_none() {
        return Ok(None);
    }
    if v.is_exact_instance_of::<PyInt>() {
        return Ok(Some(v));
    }
    if let Ok(s) = v.cast::<PyString>() {
        let s = s.to_string_lossy();
        if s.is_empty() {
            return Ok(None);
        }
        if s.len() <= 18 && s.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(n) = s.parse::<i64>() {
                return Ok(Some(n.into_pyobject(py)?.into_any()));
            }
        }
    } else if v.eq(PyString::new(py, ""))? {
        return Ok(None);
    }
    match int_builtin.call1((v,)) {
        Ok(n) => Ok(Some(n)),
        Err(e) if e.is_instance_of::<PyTypeError>(py) || e.is_instance_of::<PyValueError>(py) => {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// `[_classify_event(evt) for evt in events]`: per event `(source, status, path, auth_failure,
/// pattern_rule_index)`. `patterns` are the PATTERN_RULES regex sources, `auth_pattern` is
/// AUTH_FAILURE_REGEX's; the regex matching runs in batches with the GIL released.
#[pyfunction]
pub fn classify_events<'py>(
    py: Python<'py>,
    events: &Bound<'py, PyList>,
    patterns: Vec<String>,
    auth_pattern: String,
) -> PyResult<Bound<'py, PyList>> {
    let rules = patterns
        .iter()
        .map(|p| compile(p, true))
        .collect::<PyResult<Vec<_>>>()?;
    let auth = compile(&auth_pattern, true)?;
    let int_builtin = py.import("builtins")?.getattr("int")?;
    let source_keys: Vec<_> = SOURCE_KEYS.iter().map(|k| PyString::new(py, k)).collect();
    let text_keys: Vec<_> = TEXT_KEYS.iter().map(|k| PyString::new(py, k)).collect();
    let status_key = PyString::new(py, "status");
    let path_key = PyString::new(py, "path");

    let out = PyList::empty(py);
    let mut metas = Vec::with_capacity(BATCH);
    let mut texts: Vec<String> = Vec::with_capacity(BATCH);
    let mut it = events.iter().peekable();
    while it.peek().is_some() {
        for item in it.by_ref().take(BATCH) {
            let evt = item.cast::<PyDict>()?;
            let src = event_source(py, evt, &source_keys)?;
            let status = to_int(py, evt.get_item(&status_key)?, &int_builtin)?;
            let path = match evt.get_item(&path_key)? {
                Some(p) if p.is_truthy()? => Some(p.str()?),
                _ => None,
            };
            metas.push((src, status, path));
            texts.push(event_text(evt, &text_keys)?);
        }
        let hits: Vec<(bool, Option<usize>)> = py.detach(|| {
            texts
                .iter()
                .map(|t| (auth.is_match(t), rules.iter().position(|r| r.is_match(t))))
                .collect()
        });
        for ((src, status, path), (auth_hit, rule_index)) in metas.drain(..).zip(hits) {
            out.append((src, status, path, auth_hit, rule_index))?;
        }
        texts.clear();
    }
    Ok(out)
}
