//! Native indicator extraction for the threat intel engine. `extract_indicators` returns, per
//! event, exactly what `forensis.analyzers.threat_intel.ThreatIntelEngine.extract_indicators`
//! (the reference) returns.

use std::collections::HashSet;

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyString};
use regex::Regex;

use crate::logs::text_of;
use crate::text::{compile, py_strip};

/// Direct keys, in reference order: `str(evt.get(k, "")).strip()` ...
const IP_KEYS: [&str; 3] = ["ip", "src_ip", "dst_ip"];
/// ... and `.strip().lower()` kept when it has a "." and no " ".
const DOMAIN_KEYS: [&str; 2] = ["host", "domain"];
/// `extract_indicators` text keys, in join order.
const TEXT_KEYS: [&str; 5] = ["message", "raw", "path", "process", "uri"];
/// `text[:500000]`.
const MAX_TEXT_CHARS: usize = 500_000;
/// Events per GIL-free matching batch (each text can be MAX_TEXT_CHARS long).
const BATCH: usize = 256;

type Direct<'py> = (&'static str, Bound<'py, PyString>);

/// `str(evt.get(key, ""))` as a Python str, so lone surrogates in the value survive.
fn str_of<'py>(
    py: Python<'py>,
    evt: &Bound<'py, PyDict>,
    key: &Bound<'py, PyString>,
) -> PyResult<Bound<'py, PyString>> {
    match evt.get_item(key)? {
        Some(v) => v.str(),
        None => Ok(PyString::new(py, "")),
    }
}

fn strip<'py>(s: &Bound<'py, PyString>) -> PyResult<Bound<'py, PyString>> {
    s.call_method0("strip")?
        .cast_into::<PyString>()
        .map_err(Into::into)
}

fn lower<'py>(s: &Bound<'py, PyString>) -> PyResult<Bound<'py, PyString>> {
    s.call_method0("lower")?
        .cast_into::<PyString>()
        .map_err(Into::into)
}

/// Dedup key of a Python str: its UTF-8, or `encode("utf-8", "surrogatepass")` when it holds a
/// lone surrogate, which no valid str encodes to, so distinct values never collide.
fn key_bytes(s: &Bound<'_, PyString>) -> PyResult<Vec<u8>> {
    if let Ok(t) = s.to_str() {
        return Ok(t.as_bytes().to_vec());
    }
    let b = s.call_method1("encode", ("utf-8", "surrogatepass"))?;
    Ok(b.cast_into::<PyBytes>()?.as_bytes().to_vec())
}

/// `_extract_from_text(" ".join(text_parts))`, in the reference's append order.
fn scan(text: &str, ip: &Regex, domain: &Regex, hashes: &[Regex]) -> Vec<(&'static str, String)> {
    let text = match text.char_indices().nth(MAX_TEXT_CHARS) {
        Some((i, _)) => &text[..i],
        None => text,
    };
    let mut out = Vec::new();
    out.extend(ip.find_iter(text).map(|m| ("ip", m.as_str().to_string())));
    let lowered = text.to_lowercase();
    out.extend(
        domain
            .find_iter(&lowered)
            .map(|m| ("domain", m.as_str().to_string())),
    );
    for h in hashes {
        out.extend(h.find_iter(text).map(|m| ("hash", m.as_str().to_string())));
    }
    out
}

/// `[engine.extract_indicators(evt) for evt in events]`: per event the deduplicated
/// `(type, value)` tuples. `ip_pattern`, `domain_pattern` (matched with `re.I` on the lowered text)
/// and `hash_patterns` (`re.I`) are the module regex sources; matching runs in batches with the GIL
/// released.
#[pyfunction]
pub fn extract_indicators<'py>(
    py: Python<'py>,
    events: &Bound<'py, PyList>,
    ip_pattern: String,
    domain_pattern: String,
    hash_patterns: Vec<String>,
) -> PyResult<Bound<'py, PyList>> {
    let ip = compile(&ip_pattern, false)?;
    let domain = compile(&domain_pattern, true)?;
    let hashes = hash_patterns
        .iter()
        .map(|p| compile(p, true))
        .collect::<PyResult<Vec<_>>>()?;
    let ip_keys: Vec<_> = IP_KEYS.iter().map(|k| PyString::new(py, k)).collect();
    let domain_keys: Vec<_> = DOMAIN_KEYS.iter().map(|k| PyString::new(py, k)).collect();
    let text_keys: Vec<_> = TEXT_KEYS.iter().map(|k| PyString::new(py, k)).collect();

    let out = PyList::empty(py);
    let mut directs: Vec<Vec<Direct<'py>>> = Vec::with_capacity(BATCH);
    let mut texts: Vec<String> = Vec::with_capacity(BATCH);
    let mut it = events.iter().peekable();
    while it.peek().is_some() {
        for item in it.by_ref().take(BATCH) {
            let evt = item.cast::<PyDict>()?;
            let mut direct = Vec::new();
            for k in &ip_keys {
                let val = strip(&str_of(py, evt, k)?)?;
                if val.len()? > 0 {
                    direct.push(("ip", val));
                }
            }
            for k in &domain_keys {
                let val = lower(&strip(&str_of(py, evt, k)?)?)?;
                let text = val.to_string_lossy();
                if !text.is_empty() && text.contains('.') && !text.contains(' ') {
                    direct.push(("domain", val));
                }
            }
            directs.push(direct);
            let mut parts = Vec::with_capacity(text_keys.len());
            for k in &text_keys {
                if let Some(v) = evt.get_item(k)? {
                    if !v.is_none() {
                        parts.push(text_of(&v)?);
                    }
                }
            }
            texts.push(parts.join(" "));
        }
        let found: Vec<Vec<(&'static str, String)>> = py.detach(|| {
            texts
                .iter()
                .map(|t| scan(t, &ip, &domain, &hashes))
                .collect()
        });
        for (direct, found) in directs.drain(..).zip(found) {
            // _normalize_indicator + the (type, value) dedup, direct values first.
            let mut seen: HashSet<(&str, Vec<u8>)> = HashSet::new();
            let row = PyList::empty(py);
            for (t, v) in direct {
                let v = lower(&strip(&v)?)?;
                if v.len()? > 0 && seen.insert((t, key_bytes(&v)?)) {
                    row.append((PyString::intern(py, t), v))?;
                }
            }
            for (t, v) in found {
                let v = py_strip(&v).to_lowercase();
                if !v.is_empty() && seen.insert((t, v.as_bytes().to_vec())) {
                    row.append((PyString::intern(py, t), PyString::new(py, &v)))?;
                }
            }
            out.append(row)?;
        }
        texts.clear();
    }
    Ok(out)
}
