//! Native engines for Forensis. `analyze_pcap` returns exactly what
//! `forensis.analyzers.network_analyzer._analyze_pcap_python` (the dpkt reference) returns;
//! `classify_events` (logs.rs) mirrors `log_analyzer._classify_event` and `correlate_sigma`
//! (sigma.rs) mirrors `sigma_engine._CompiledRule.match` the same way.

mod capture;
mod logs;
mod packet;
mod sigma;
mod text;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyFloat, PyList, PyString};

use capture::{Capture, CaptureError, Detail, Ts};
use packet::{addr_str, decode, Addr};

// Detection constants: keep in sync with network_analyzer.py (the parity tests compare both).
const KNOWN_C2_PORTS: [u16; 7] = [4444, 4445, 1337, 6667, 31337, 9001, 50050];
const RISKY_ADMIN_PORTS: [u16; 8] = [22, 23, 135, 139, 445, 3389, 5985, 5986];

struct Flow {
    src: Addr,
    dst: Addr,
    sport: Option<u16>,
    dport: Option<u16>,
    proto: u8,
    first: Ts,
    last: Ts,
    packets: u64,
    bytes: u64,
    small: u64,
    syn: u64,
}

struct Scan {
    src: Addr,
    ports: HashSet<u16>,
    hosts: HashSet<Addr>,
    syn: u64,
}

#[derive(Default)]
struct Agg {
    flows: Vec<Flow>,
    scans: Vec<Scan>,
    total: i64,
    truncated: bool,
    dropped: u64,
}

/// (src, dst, sport, dport)
type Ends = (Addr, Addr, Option<u16>, Option<u16>);

/// `dict[key] = value` with an interned key, like Python's dict literals (one shared key object).
macro_rules! set {
    ($d:expr, $k:literal, $v:expr) => {
        $d.set_item(pyo3::intern!($d.py(), $k), $v)?
    };
}

/// The per-packet loop of the reference implementation; runs without the GIL.
fn aggregate(path: &Path, max_packets: i64, max_flows: i64) -> Result<Agg, CaptureError> {
    let mut cap = Capture::open(path)?;
    let mut agg = Agg::default();
    let mut index: HashMap<(Ends, u8), usize> = HashMap::new();
    let mut scan_index: HashMap<Addr, usize> = HashMap::new();
    while let Some((ts, frame)) = cap.next()? {
        if agg.total >= max_packets {
            agg.truncated = true;
            break;
        }
        agg.total += 1;
        let Some(p) = decode(frame) else { continue };
        let syn_only = p.tcp_flags.is_some_and(|f| f & 0x02 != 0 && f & 0x10 == 0);
        if syn_only {
            let i = *scan_index.entry(p.src).or_insert_with(|| {
                agg.scans.push(Scan {
                    src: p.src,
                    ports: HashSet::new(),
                    hosts: HashSet::new(),
                    syn: 0,
                });
                agg.scans.len() - 1
            });
            let s = &mut agg.scans[i];
            s.syn += 1;
            s.ports.extend(p.dport);
            s.hosts.insert(p.dst);
        }
        let key = ((p.src, p.dst, p.sport, p.dport), p.proto);
        let i = match index.get(&key) {
            Some(&i) => i,
            None => {
                if agg.flows.len() as i64 >= max_flows {
                    agg.dropped += 1;
                    continue;
                }
                agg.flows.push(Flow {
                    src: p.src,
                    dst: p.dst,
                    sport: p.sport,
                    dport: p.dport,
                    proto: p.proto,
                    first: ts,
                    last: ts,
                    packets: 0,
                    bytes: 0,
                    small: 0,
                    syn: 0,
                });
                index.insert(key, agg.flows.len() - 1);
                agg.flows.len() - 1
            }
        };
        let f = &mut agg.flows[i];
        f.packets += 1;
        f.bytes += frame.len() as u64;
        f.last = ts;
        f.small += (p.payload_len < 100) as u64;
        f.syn += syn_only as u64;
    }
    Ok(agg)
}

fn error_result<'py>(py: Python<'py>, message: String) -> PyResult<Bound<'py, PyDict>> {
    let summary = PyDict::new(py);
    set!(summary, "error", message);
    let out = PyDict::new(py);
    out.set_item("summary", summary)?;
    for k in ["events", "flows", "anomalies"] {
        out.set_item(k, PyList::empty(py))?;
    }
    Ok(out)
}

/// Same text Python would put after the prefix (`str(exc)` of what dpkt / open() raised).
fn error_text(py: Python<'_>, e: CaptureError) -> PyResult<String> {
    let text = match e.detail {
        Detail::Msg(m) => m,
        Detail::Io(err, path) => match err.raw_os_error() {
            Some(code) => {
                let full = err.to_string();
                let strerror = full
                    .strip_suffix(&format!(" (os error {code})"))
                    .unwrap_or(&full)
                    .to_string();
                let exc = match path {
                    Some(p) => PyOSError::new_err((code, strerror, p)),
                    None => PyOSError::new_err((code, strerror)),
                };
                exc.value(py).str()?.to_string()
            }
            None => err.to_string(),
        },
        Detail::Comment(data) => {
            // Re-run dpkt's decode steps so the UnicodeDecodeError text is Python's own.
            let first = PyBytes::new(py, &data)
                .call_method1("decode", ("utf-8",))
                .err();
            let err = match data.iter().position(|&x| x == 0) {
                Some(i) => PyBytes::new(py, &data[..i])
                    .call_method1("decode", ("ascii",))
                    .err(),
                None => first,
            };
            match err {
                Some(err) => err.value(py).str()?.to_string(),
                None => String::new(),
            }
        }
    };
    Ok(text)
}

/// analyze_pcap(path, max_packets, max_tracked_flows, display_tz, format_ts, is_private_ip)
///
/// `format_ts` and `is_private_ip` are the Python helpers, so timezone rendering (zoneinfo)
/// and private-range rules (ipaddress) stay identical to the reference on every Python version.
#[pyfunction]
fn analyze_pcap<'py>(
    py: Python<'py>,
    path: PathBuf,
    max_packets: Bound<'py, PyAny>,
    max_tracked_flows: Bound<'py, PyAny>,
    display_tz: Bound<'py, PyAny>,
    format_ts: Bound<'py, PyAny>,
    is_private_ip: Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyDict>> {
    let max_p = max_packets.extract::<i64>().unwrap_or(i64::MAX);
    let max_f = max_tracked_flows.extract::<i64>().unwrap_or(i64::MAX);
    let agg = match py.detach(|| aggregate(&path, max_p, max_f)) {
        Ok(agg) => agg,
        Err(e) => {
            let prefix = if e.invalid_format {
                "Invalid PCAP format: "
            } else {
                "System error during analysis: "
            };
            return error_result(py, format!("{prefix}{}", error_text(py, e)?));
        }
    };

    let decimal_1e9 = py.import("decimal")?.getattr("Decimal")?.call1(("1E9",))?;
    let ts_obj = |ts: Ts| -> PyResult<Bound<'py, PyAny>> {
        match ts {
            Ts::F(v) => Ok(PyFloat::new(py, v).into_any()),
            // dpkt: hdr.tv_sec + (hdr.tv_usec / Decimal('1E9'))
            Ts::Nano { sec, frac } => sec
                .into_pyobject(py)?
                .add(frac.into_pyobject(py)?.div(&decimal_1e9)?),
        }
    };

    let mut flows_out: Vec<Bound<'py, PyDict>> = Vec::with_capacity(agg.flows.len());
    let events = PyList::empty(py);
    let anomalies = PyList::empty(py);
    // _add_anomaly's dedup key; reason is a function of (indicator, dport) for flow anomalies.
    let mut seen: HashSet<(Ends, &str)> = HashSet::new();
    let mut severity: Vec<(&str, u64)> = Vec::new();
    let mut add = |flow: &Bound<'py, PyDict>,
                   key: Option<Ends>,
                   reason: String,
                   sev: &'static str,
                   category: &str,
                   indicator: &'static str|
     -> PyResult<()> {
        if let Some(k) = key {
            if !seen.insert((k, indicator)) {
                return Ok(());
            }
        }
        let a = PyDict::new(py);
        set!(a, "reason", reason);
        set!(a, "flow", flow);
        set!(a, "severity", PyString::intern(py, sev));
        set!(a, "category", PyString::intern(py, category));
        set!(a, "indicator", PyString::intern(py, indicator));
        anomalies.append(a)?;
        match severity.iter_mut().find(|(s, _)| *s == sev) {
            Some((_, n)) => *n += 1,
            None => severity.push((sev, 1)),
        }
        Ok(())
    };

    for f in &agg.flows {
        let (src, dst) = (
            PyString::new(py, &addr_str(&f.src)),
            PyString::new(py, &addr_str(&f.dst)),
        );
        // Like the reference, the flow and its event share value objects (and first/last when equal).
        let same_ts = !(f.first.lt(f.last) || f.last.lt(f.first));
        let first = ts_obj(f.first)?;
        let last = if same_ts {
            first.clone()
        } else {
            ts_obj(f.last)?
        };
        let duration = last.sub(&first)?;
        let packets = f.packets.into_pyobject(py)?.into_any();
        let pps = if duration.gt(0)? {
            packets.div(&duration)?
        } else {
            packets.clone()
        };
        let avg = f.bytes as f64 / f.packets.max(1) as f64;
        let (bytes, avg_obj) = (f.bytes.into_pyobject(py)?, PyFloat::new(py, avg));
        let (sport, dport) = (f.sport.into_pyobject(py)?, f.dport.into_pyobject(py)?);
        let first_seen = format_ts.call1((&first,))?;
        // _format_ts is pure, so equal timestamps reuse the string.
        let last_seen = if same_ts {
            first_seen.clone()
        } else {
            format_ts.call1((&last,))?
        };
        let proto = match f.proto {
            6 => pyo3::intern!(py, "TCP").clone(),
            17 => pyo3::intern!(py, "UDP").clone(),
            1 => pyo3::intern!(py, "ICMP").clone(),
            n => PyString::new(py, &n.to_string()),
        };

        let d = PyDict::new(py);
        set!(d, "src", &src);
        set!(d, "dst", &dst);
        set!(d, "sport", &sport);
        set!(d, "dport", &dport);
        set!(d, "proto", &proto);
        set!(d, "first_ts", &first);
        set!(d, "last_ts", &last);
        set!(d, "packets", &packets);
        set!(d, "bytes", &bytes);
        set!(d, "small_packets", f.small);
        set!(d, "syn_packets", f.syn);
        set!(d, "duration", &duration);
        set!(d, "pps", &pps);
        set!(d, "avg_payload", &avg_obj);
        set!(d, "first_seen", &first_seen);
        set!(d, "last_seen", &last_seen);

        let key = Some((f.src, f.dst, f.sport, f.dport));
        if let Some(port) = f.dport.filter(|p| KNOWN_C2_PORTS.contains(p)) {
            let reason = format!("Connection on known C2/non-standard control port {port}");
            add(
                &d,
                key,
                reason,
                "high",
                "command_and_control",
                "known_c2_port",
            )?;
        }
        if let Some(port) = f.dport.filter(|p| RISKY_ADMIN_PORTS.contains(p)) {
            if is_private_ip.call1((&src,))?.is_truthy()?
                && is_private_ip.call1((&dst,))?.is_truthy()?
            {
                let reason = format!("Internal administrative service access on port {port} (potential lateral movement)");
                add(
                    &d,
                    key,
                    reason,
                    "medium",
                    "lateral_movement",
                    "internal_admin_port",
                )?;
            }
        }
        if f.dport == Some(53) && avg > 200.0 && f.packets > 30 {
            let reason =
                "Possible DNS tunneling pattern (high payload over many DNS packets)".into();
            add(
                &d,
                key,
                reason,
                "high",
                "command_and_control",
                "dns_tunnel_pattern",
            )?;
        }
        if f.packets >= 80 && avg < 120.0 && duration.gt(30)? {
            let reason = "Possible beaconing (frequent small packets over time)".into();
            add(
                &d,
                key,
                reason,
                "medium",
                "command_and_control",
                "beaconing_pattern",
            )?;
        }
        if f.bytes > 10_000_000 && f.packets < 40 {
            let reason = "Large transfer in low packet count (possible bulk exfiltration)".into();
            add(
                &d,
                key,
                reason,
                "high",
                "exfiltration",
                "bulk_exfil_pattern",
            )?;
        }
        if pps.gt(300)? && f.packets > 200 {
            let reason = "Abnormally high packets-per-second rate".into();
            add(&d, key, reason, "medium", "impact", "packet_flood_pattern")?;
        }

        let e = PyDict::new(py);
        set!(e, "source", pyo3::intern!(py, "pcap_flow"));
        set!(e, "src_ip", &src);
        set!(e, "dst_ip", &dst);
        set!(e, "src_port", &sport);
        set!(e, "dst_port", &dport);
        set!(e, "proto", &proto);
        set!(e, "packets", &packets);
        set!(e, "bytes", &bytes);
        set!(e, "duration", &duration);
        set!(e, "avg_payload", &avg_obj);
        set!(e, "first_seen", &first_seen);
        set!(e, "last_seen", &last_seen);
        events.append(e)?;
        flows_out.push(d);
    }

    for s in &agg.scans {
        let (ports, hosts) = (s.ports.len(), s.hosts.len());
        if ports >= 30 || (hosts >= 20 && s.syn >= 40) {
            let src = addr_str(&s.src);
            let d = PyDict::new(py);
            set!(d, "src", &src);
            set!(d, "dst", format!("{hosts} hosts"));
            set!(d, "sport", "-");
            set!(d, "dport", format!("{ports} ports"));
            set!(d, "proto", "TCP");
            set!(d, "packets", s.syn);
            set!(d, "bytes", 0);
            set!(d, "duration", 0);
            set!(d, "pps", s.syn);
            set!(d, "avg_payload", 0);
            set!(d, "first_seen", "");
            set!(d, "last_seen", "");
            let reason = format!("Potential port scan / SYN scan activity from {src}");
            add(
                &d,
                None,
                reason,
                "high",
                "reconnaissance",
                "syn_scan_pattern",
            )?;
        }
    }

    let severity_counts = PyDict::new(py);
    let mut threat_score = 0;
    for (sev, n) in &severity {
        severity_counts.set_item(*sev, *n)?;
        threat_score += n * match *sev {
            "critical" => 5,
            "high" => 3,
            "medium" => 2,
            _ => 1,
        };
    }
    let mut first_seen = "".into_pyobject(py)?.into_any();
    let mut last_seen = first_seen.clone();
    if let Some(head) = agg.flows.first() {
        // Python min()/max() keep the first of equal values.
        let (mut lo, mut hi) = (head.first, head.last);
        for f in &agg.flows[1..] {
            if f.first.lt(lo) {
                lo = f.first;
            }
            if hi.lt(f.last) {
                hi = f.last;
            }
        }
        first_seen = format_ts.call1((ts_obj(lo)?,))?;
        last_seen = format_ts.call1((ts_obj(hi)?,))?;
    }

    let summary = PyDict::new(py);
    set!(summary, "total_packets", agg.total);
    set!(summary, "flow_count", agg.flows.len());
    set!(summary, "anomaly_count", anomalies.len());
    set!(summary, "malicious_pattern_hits", anomalies.len());
    set!(summary, "severity_counts", severity_counts);
    set!(summary, "threat_score", threat_score);
    set!(summary, "first_seen", first_seen);
    set!(summary, "last_seen", last_seen);
    set!(summary, "pcap_max_packets", max_packets);
    set!(summary, "packets_truncated", agg.truncated);
    set!(summary, "max_tracked_flows", max_tracked_flows);
    set!(summary, "dropped_new_flows", agg.dropped);
    set!(summary, "display_tz", display_tz);

    // sorted(..., key=bytes, reverse=True)[:200] is stable: ties keep insertion order.
    let mut order: Vec<usize> = (0..agg.flows.len()).collect();
    order.sort_by(|&a, &b| agg.flows[b].bytes.cmp(&agg.flows[a].bytes));
    let top = PyList::empty(py);
    for i in order.into_iter().take(200) {
        top.append(&flows_out[i])?;
    }

    let out = PyDict::new(py);
    out.set_item("summary", summary)?;
    out.set_item("events", events)?;
    out.set_item("flows", top)?;
    out.set_item("anomalies", anomalies)?;
    Ok(out)
}

/// Native (Rust) engines for Forensis: PCAP flows, log event classification, Sigma matching.
#[pymodule]
mod forensis_core {
    use pyo3::prelude::*;

    #[pymodule_export]
    use super::analyze_pcap;

    #[pymodule_export]
    use super::logs::classify_events;

    #[pymodule_export]
    use super::sigma::correlate_sigma;

    #[pymodule_init]
    fn init(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add("__version__", env!("CARGO_PKG_VERSION"))
    }
}
