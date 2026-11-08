//! Native Sigma matcher. `correlate_sigma` returns, for the compiled rules it is given, the same
//! (event_index, rule_index) pairs that `sigma_engine._CompiledRule.match` (the reference) yields.
//! Rules with regex, numeric or bracket-glob values never reach here: Python keeps those.

use std::collections::HashMap;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString};

use crate::text::py_strip;

enum Mode {
    Contains,
    Eq,
    StartsWith,
    EndsWith,
    Glob(Vec<char>),
}

/// One expected value: `str(expected).strip().lower()` plus how `_match_value` compares it.
struct Value {
    mode: Mode,
    exp: String,
}

struct Item {
    field: String,
    field_lower: String,
    values: Vec<Value>,
}

enum Cond {
    Sel(usize),
    Any(Vec<Cond>),
    All(Vec<Cond>),
    False,
}

struct Rule {
    selections: Vec<Vec<Item>>,
    cond: Cond,
}

/// One flattened field: whether the raw string was empty (Python's `or` fallback) and `strip().lower()`.
struct Field {
    raw_empty: bool,
    lowered: String,
}

type Event = HashMap<String, Field>;

/// `fnmatch.fnmatch(text, pat)` for patterns without `[`: `*` any run, `?` one char, whole string.
fn glob(text: &[char], pat: &[char]) -> bool {
    let (mut t, mut p, mut star, mut mark) = (0, 0, None, 0);
    while t < text.len() {
        if p < pat.len() && (pat[p] == '?' || pat[p] == text[t]) {
            t += 1;
            p += 1;
        } else if p < pat.len() && pat[p] == '*' {
            star = Some(p);
            mark = t;
            p += 1;
        } else if let Some(s) = star {
            p = s + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == '*' {
        p += 1;
    }
    p == pat.len()
}

fn match_value(f: &Field, v: &Value) -> bool {
    if f.lowered.is_empty() || v.exp.is_empty() {
        return false;
    }
    match &v.mode {
        Mode::Eq => f.lowered == v.exp,
        Mode::StartsWith => f.lowered.starts_with(&v.exp),
        Mode::EndsWith => f.lowered.ends_with(&v.exp),
        Mode::Contains => f.lowered.contains(&v.exp),
        Mode::Glob(pat) => glob(&f.lowered.chars().collect::<Vec<_>>(), pat),
    }
}

fn match_selection(ev: &Event, items: &[Item]) -> bool {
    for item in items {
        if item.field.is_empty() {
            return false;
        }
        let f = match ev.get(&item.field) {
            Some(f) if !f.raw_empty => f,
            _ => match ev.get(&item.field_lower) {
                Some(f) => f,
                None => return false,
            },
        };
        if !item.values.iter().any(|v| match_value(f, v)) {
            return false;
        }
    }
    true
}

fn eval(ev: &Event, rule: &Rule, cond: &Cond) -> bool {
    match cond {
        Cond::Sel(i) => match_selection(ev, &rule.selections[*i]),
        Cond::Any(nodes) => nodes.iter().any(|c| eval(ev, rule, c)),
        Cond::All(nodes) => nodes.iter().all(|c| eval(ev, rule, c)),
        Cond::False => false,
    }
}

fn parse_cond(node: &Bound<'_, PyAny>, n_selections: usize) -> PyResult<Cond> {
    let kind: String = node.get_item(0)?.extract()?;
    Ok(match kind.as_str() {
        "sel" => {
            let i: usize = node.get_item(1)?.extract()?;
            if i >= n_selections {
                return Err(PyValueError::new_err("selection index out of range"));
            }
            Cond::Sel(i)
        }
        "any" | "all" => {
            let nodes = node
                .get_item(1)?
                .try_iter()?
                .map(|n| parse_cond(&n?, n_selections))
                .collect::<PyResult<Vec<_>>>()?;
            if kind == "any" {
                Cond::Any(nodes)
            } else {
                Cond::All(nodes)
            }
        }
        "false" => Cond::False,
        other => {
            return Err(PyValueError::new_err(format!(
                "unknown condition node {other:?}"
            )))
        }
    })
}

type PyItem = (String, String, Vec<(String, String)>);

fn parse_rule(obj: &Bound<'_, PyAny>) -> PyResult<Rule> {
    let (selections, cond): (Vec<Vec<PyItem>>, Bound<'_, PyAny>) = obj.extract()?;
    let selections = selections
        .into_iter()
        .map(|items| {
            items
                .into_iter()
                .map(|(field, field_lower, values)| {
                    let values = values
                        .into_iter()
                        .map(|(mode, exp)| {
                            let mode = match mode.as_str() {
                                "contains" => Mode::Contains,
                                "eq" => Mode::Eq,
                                "startswith" => Mode::StartsWith,
                                "endswith" => Mode::EndsWith,
                                "glob" if !exp.contains('[') => Mode::Glob(exp.chars().collect()),
                                other => {
                                    return Err(PyValueError::new_err(format!(
                                        "mode {other:?} is not native"
                                    )))
                                }
                            };
                            Ok(Value { mode, exp })
                        })
                        .collect::<PyResult<Vec<_>>>()?;
                    Ok(Item {
                        field,
                        field_lower,
                        values,
                    })
                })
                .collect::<PyResult<Vec<_>>>()
        })
        .collect::<PyResult<Vec<_>>>()?;
    let cond = parse_cond(&cond, selections.len())?;
    Ok(Rule { selections, cond })
}

fn parse_event(obj: &Bound<'_, PyAny>) -> PyResult<Option<Event>> {
    if obj.is_none() {
        return Ok(None);
    }
    let dict = obj.cast::<PyDict>()?;
    let mut ev = Event::with_capacity(dict.len());
    for (k, v) in dict.iter() {
        let raw = v.cast::<PyString>()?.to_string_lossy();
        ev.insert(
            k.cast::<PyString>()?.to_string_lossy().into_owned(),
            Field {
                raw_empty: raw.is_empty(),
                lowered: py_strip(&raw).to_lowercase(),
            },
        );
    }
    Ok(Some(ev))
}

/// `events`: flattened `{str: str}` dicts (None for non-dict events), `rules`: the native form of
/// the compiled rules. Returns `(event_index, rule_index)` in event-then-rule order, at most
/// `match_limit` pairs; the matching itself runs with the GIL released.
#[pyfunction]
#[pyo3(signature = (events, rules, match_limit=None))]
pub fn correlate_sigma(
    py: Python<'_>,
    events: &Bound<'_, PyList>,
    rules: &Bound<'_, PyList>,
    match_limit: Option<usize>,
) -> PyResult<Vec<(usize, usize)>> {
    let rules = rules
        .iter()
        .map(|r| parse_rule(&r))
        .collect::<PyResult<Vec<_>>>()?;
    let events = events
        .iter()
        .map(|e| parse_event(&e))
        .collect::<PyResult<Vec<_>>>()?;
    let limit = match_limit.unwrap_or(usize::MAX);
    Ok(py.detach(|| {
        let mut out = Vec::new();
        'events: for (ei, ev) in events.iter().enumerate() {
            let Some(ev) = ev else { continue };
            for (ri, rule) in rules.iter().enumerate() {
                if eval(ev, rule, &rule.cond) {
                    out.push((ei, ri));
                    if out.len() >= limit {
                        break 'events;
                    }
                }
            }
        }
        out
    }))
}
