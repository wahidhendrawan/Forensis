//! Frame decoding that mirrors what `analyze_pcap` gets from dpkt 1.9.8:
//! `dpkt.ethernet.Ethernet(buf)` -> IP / IP6 -> TCP / UDP ports, flags and payload length.
//! For other IP protocols Python uses `len(ip.data)`, which is the length of dpkt's decoded
//! object (not always the raw byte count), so `obj_len` replays those decoders' lengths.
//! Every read is bounds-checked; malformed input only ever yields "skip" or a raw length.

use crate::capture::py_slice;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Addr {
    V4([u8; 4]),
    V6([u8; 16]),
}

pub struct Pkt {
    pub src: Addr,
    pub dst: Addr,
    pub proto: u8,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    pub payload_len: usize,
    pub tcp_flags: Option<u16>,
}

/// dpkt outcome of decoding a nested protocol object.
enum Err {
    /// dpkt.UnpackError / KeyError: the parent keeps the raw bytes.
    Unpack,
    /// Any other exception: it escapes to `analyze_pcap`'s per-packet `except`, the packet is skipped.
    Fatal,
}

/// dpkt hits RecursionError (-> packet skipped) after ~300-340 nested tunnel headers depending
/// on the caller's stack depth; this cap approximates that and bounds our own recursion.
const MAX_DEPTH: u32 = 300;

fn be16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}

/// Returns None when the packet does not end up as an IP/IP6 flow in dpkt.
pub fn decode(frame: &[u8]) -> Option<Pkt> {
    let mut buf = frame;
    loop {
        if buf.len() < 14 {
            return None;
        }
        let eth_type = be16(buf, 12);
        if eth_type > 1500 {
            return ethertype(eth_type, &buf[14..]);
        }
        // Cisco ISL: dpkt strips the 26-byte tag and re-parses the inner frame.
        if buf[..5] == [1, 0, 0x0c, 0, 0] || buf[..5] == [3, 0, 0x0c, 0, 0] {
            buf = buf.get(26..)?;
            continue;
        }
        return None; // IPX, LLC/SNAP, type 0: never IP at the top level
    }
}

fn ethertype(eth_type: u16, mut buf: &[u8]) -> Option<Pkt> {
    let qinq = |t: u16| matches!(t, 0x8100 | 0x88a8 | 0x9100 | 0x9200);
    let mpls = |t: u16| t == 0x8847 || t == 0x8848;
    let mut next = eth_type;
    // Ethernet.__init__ runs _unpack_data again when the first pass left raw bytes, resuming
    // from the type it stopped on (so e.g. a third/fourth 802.1Q tag is still decoded).
    for _ in 0..2 {
        if qinq(next) {
            // up to two tags per pass, the second only if the first announces another 0x8100
            for _ in 0..2 {
                next = be16(buf.get(..4)?, 2);
                buf = &buf[4..];
                if next != 0x8100 {
                    break;
                }
            }
        } else if mpls(next) {
            for _ in 0..24 {
                let bottom = buf.get(..4)?[2] & 1;
                buf = &buf[4..];
                if bottom == 1 {
                    break;
                }
            }
            match *buf.first()? {
                0x45 => next = 0x0800,
                b if b & 0xf0 == 0x60 => next = 0x86dd,
                _ if buf.len() >= 14 => return None, // Ethernet-over-MPLS: never IP at the top
                _ => {}
            }
        }
        // dpkt: `self._next_type or self.type`
        match if next != 0 { next } else { eth_type } {
            0x0800 => return ipv4(buf),
            0x86dd => return ipv6(buf),
            t if qinq(t) || mpls(t) => continue, // no decoder (KeyError): raw bytes
            _ => return None,
        }
    }
    None
}

fn ipv4(b: &[u8]) -> Option<Pkt> {
    if b.len() < 20 {
        return None;
    }
    let hl = (b[0] & 0xf) as i64 * 4;
    if hl < 20 {
        return None;
    }
    let total = be16(b, 2) as i64;
    let payload = py_slice(b, hl, if total != 0 { total } else { b.len() as i64 });
    let fragment = be16(b, 6) & 0x1fff != 0;
    let src = Addr::V4(b[12..16].try_into().ok()?);
    let dst = Addr::V4(b[16..20].try_into().ok()?);
    transport(src, dst, b[9], payload, fragment)
}

fn ipv6(b: &[u8]) -> Option<Pkt> {
    let v6 = ip6_parse(b, 1).ok()?;
    let src = Addr::V6(b[8..24].try_into().ok()?);
    let dst = Addr::V6(b[24..40].try_into().ok()?);
    // `ip.p` is only set when the extension chain ends on a next-header value; else `ip.nxt`.
    match v6.p {
        Some(p) => transport(src, dst, p, v6.payload, v6.raw),
        None => transport(src, dst, b[6], v6.payload, true),
    }
}

/// `raw`: dpkt kept `ip.data` as bytes without trying a decoder (fragments).
fn transport(src: Addr, dst: Addr, proto: u8, data: &[u8], raw: bool) -> Option<Pkt> {
    let mut p = Pkt {
        src,
        dst,
        proto,
        sport: None,
        dport: None,
        payload_len: 0,
        tcp_flags: None,
    };
    match proto {
        6 => {
            if !raw && data.len() >= 20 && data[12] >> 4 >= 5 {
                p.sport = Some(be16(data, 0));
                p.dport = Some(be16(data, 2));
                p.payload_len = data.len().saturating_sub((data[12] >> 4) as usize * 4);
                p.tcp_flags = Some(be16(data, 12) & 0x1ff);
            }
        }
        17 => {
            if !raw && data.len() >= 8 {
                p.sport = Some(be16(data, 0));
                p.dport = Some(be16(data, 2));
                p.payload_len = data.len() - 8;
            }
        }
        _ => {
            p.payload_len = if raw {
                data.len()
            } else {
                child_len(proto, data, 1).ok()?
            };
        }
    }
    Some(p)
}

/// `len(IP._protosw[p](buf))` with the parent's `except (KeyError, UnpackError)` fallback.
fn child_len(p: u8, b: &[u8], depth: u32) -> Result<usize, ()> {
    match obj_len(p, b, depth + 1) {
        Ok(n) => Ok(n),
        Err(Err::Unpack) => Ok(b.len()),
        Err(Err::Fatal) => Err(()),
    }
}

fn need(b: &[u8], hdr: usize) -> Result<usize, Err> {
    if b.len() < hdr {
        Err(Err::Unpack)
    } else {
        Ok(b.len())
    }
}

fn fatal(_: ()) -> Err {
    Err::Fatal
}

/// dpkt object length for the classes registered in `IP._protosw`.
fn obj_len(p: u8, b: &[u8], depth: u32) -> Result<usize, Err> {
    if depth > MAX_DEPTH {
        return Err(Err::Fatal);
    }
    match p {
        0 | 4 => ip4_len(b, depth),
        1 => icmp_len(b, depth, 3),
        2 | 17 | 50 => need(b, 8), // IGMP, UDP, ESP
        6 => {
            need(b, 20)?;
            if b[12] >> 4 < 5 {
                Err(Err::Unpack)
            } else {
                Ok(b.len())
            }
        }
        41 => ip6_len(b, depth),
        47 => gre_len(b, depth),
        51 => ah_len(b, depth),
        58 => icmp_len(b, depth, 6),
        89 => need(b, 24), // OSPF
        103 => need(b, 4), // PIM
        112 => vrrp_len(b),
        118 => need(b, 35), // STP
        132 => sctp_len(b),
        _ => Err(Err::Unpack), // no decoder: KeyError
    }
}

fn ip4_len(b: &[u8], depth: u32) -> Result<usize, Err> {
    need(b, 20)?;
    let hl = (b[0] & 0xf) as usize * 4;
    if hl < 20 {
        return Err(Err::Unpack);
    }
    let opts = hl.min(b.len()) - 20;
    let total = be16(b, 2) as i64;
    let payload = py_slice(
        b,
        hl as i64,
        if total != 0 { total } else { b.len() as i64 },
    );
    let data = if be16(b, 6) & 0x1fff != 0 {
        payload.len()
    } else {
        child_len(b[9], payload, depth).map_err(fatal)?
    };
    Ok(20 + opts + data)
}

/// ICMP (v=3) / ICMPv6 (v=6): echo keeps the raw length, error types quote an IP header.
fn icmp_len(b: &[u8], depth: u32, v: u8) -> Result<usize, Err> {
    need(b, 4)?;
    let quotes = if v == 3 {
        matches!(b[0], 3 | 4 | 5 | 11)
    } else {
        matches!(b[0], 1..=4)
    };
    if !quotes || b.len() < 8 {
        return Ok(b.len());
    }
    let inner = if v == 3 {
        ip4_len(&b[8..], depth + 1)
    } else {
        ip6_len(&b[8..], depth + 1)
    };
    match inner {
        Ok(n) => Ok(8 + n),
        Err(Err::Unpack) => Ok(b.len()),
        Err(Err::Fatal) => Err(Err::Fatal),
    }
}

struct Ip6<'a> {
    /// `ip.p`; None when the extension chain ended on ESP (no next header).
    p: Option<u8>,
    payload: &'a [u8],
    /// Non-first fragment: dpkt keeps the payload as bytes.
    raw: bool,
    ext_len: usize,
}

/// `IP6.unpack`: payload length cut, extension header chain, fragment rule.
fn ip6_parse(b: &[u8], depth: u32) -> Result<Ip6<'_>, Err> {
    if depth > MAX_DEPTH {
        return Err(Err::Fatal);
    }
    need(b, 40)?;
    let plen = be16(b, 4) as usize;
    let nxt = b[6];
    let mut buf = if plen != 0 {
        &b[40..(40 + plen).min(b.len())]
    } else {
        &b[40..]
    };
    let mut next = Some(nxt);
    let mut ext_len = 0;
    let mut last_frag_off = None; // Some(None): last extension header has no frag_off
    while let Some(nh @ (0 | 43 | 44 | 50 | 51 | 60)) = next {
        let (length, obj, nn, frag) = match nh {
            0 | 60 => {
                need(buf, 2)?;
                let length = (buf[1] as usize + 1) * 8;
                let opts = &buf[2..];
                let mut i = 0;
                while i < length - 2 {
                    let t = *opts.get(i).ok_or(Err::Unpack)?;
                    i += if t == 0 {
                        1
                    } else {
                        *opts.get(i + 1).ok_or(Err::Unpack)? as usize + 2
                    };
                }
                (
                    length,
                    2 + py_slice(buf, 2, length as i64).len(),
                    Some(buf[0]),
                    None,
                )
            }
            43 => {
                need(buf, 8)?;
                let addrs = py_slice(buf, 8, 8 + (buf[1] as i64 / 2) * 16).len();
                (buf[1] as usize * 8 + 8, 8 + addrs, Some(buf[0]), None)
            }
            44 => {
                need(buf, 8)?;
                (8, 8, Some(buf[0]), Some(be16(buf, 2) >> 3))
            }
            50 => (need(buf, 8)?, buf.len(), None, None),
            _ => {
                need(buf, 12)?; // AH
                ((buf[1] as usize + 2) * 4, buf.len(), Some(buf[0]), None)
            }
        };
        ext_len += obj;
        last_frag_off = Some(frag);
        buf = &buf[length.min(buf.len())..];
        next = nn;
    }
    let mut raw = false;
    if nxt == 44 {
        // `ext.frag_off` on the *last* extension header: AttributeError unless it is a fragment header
        match last_frag_off {
            Some(Some(off)) => raw = off > 0,
            _ => return Err(Err::Fatal),
        }
    }
    Ok(Ip6 {
        p: next,
        payload: buf,
        raw,
        ext_len,
    })
}

fn ip6_len(b: &[u8], depth: u32) -> Result<usize, Err> {
    let v6 = ip6_parse(b, depth)?;
    let data = match v6.p {
        Some(p) if !v6.raw => child_len(p, v6.payload, depth).map_err(fatal)?,
        _ => v6.payload.len(),
    };
    Ok(40 + data + v6.ext_len)
}

fn gre_len(b: &[u8], depth: u32) -> Result<usize, Err> {
    need(b, 4)?;
    let flags = be16(b, 0);
    let has = |f: u16| (flags & f != 0) as usize * 4;
    let mut opt = if flags & 7 == 0 {
        has(0xc000) + has(0x2000)
    } else {
        4
    };
    opt += has(0x1000) + has(0x0080);
    let mut d = b[4..].get(opt..).ok_or(Err::Unpack)?;
    let mut sre = 0;
    if flags & 0x4000 != 0 {
        loop {
            need(d, 4)?;
            let n = 4 + py_slice(d, 4, 4 + d[3] as i64).len();
            sre += n;
            let last = d[3] == 0;
            d = &d[n..];
            if last {
                break;
            }
        }
    }
    // shortcut: only IPv4/IPv6 payloads are re-decoded; dpkt's other GRE ethertypes (PPP, TEB,
    // CDP, ...) are counted raw, which only differs for malformed inner frames.
    let data = match be16(b, 2) {
        0x0800 => child_len(4, d, depth).map_err(fatal)?,
        0x86dd => child_len(41, d, depth).map_err(fatal)?,
        _ => d.len(),
    };
    Ok(4 + opt + sre + data)
}

fn ah_len(b: &[u8], depth: u32) -> Result<usize, Err> {
    need(b, 12)?;
    let d = &b[12..];
    let auth = (4 * b[1] as usize).saturating_sub(4).min(d.len());
    Ok(12 + auth + child_len(b[0], &d[auth..], depth).map_err(fatal)?)
}

fn vrrp_len(b: &[u8]) -> Result<usize, Err> {
    need(b, 8)?;
    let count = b[3] as i64;
    let off = if count > 0 { 4 * (count - 1) } else { 0 };
    let d = &b[8..];
    Ok(8 + 4 * count as usize + py_slice(d, off + 4, d.len() as i64).len())
}

fn sctp_len(b: &[u8]) -> Result<usize, Err> {
    need(b, 12)?;
    let mut d = &b[12..];
    let mut total = 12;
    while !d.is_empty() {
        need(d, 4)?;
        let clen = be16(d, 2) as i64;
        let data = py_slice(&d[4..], 0, clen - 4).len() as i64;
        let pad = if d[0] == 0 && clen % 4 != 0 {
            py_slice(d, 4 + data, 8 + data - clen % 4).len()
        } else {
            0
        };
        let n = clen as usize + pad;
        if n == 0 {
            break;
        }
        total += n;
        d = &d[n.min(d.len())..];
    }
    Ok(total)
}

/// glibc `inet_ntop` text (what Python's socket.inet_ntop returns on Linux).
pub fn addr_str(a: &Addr) -> String {
    match a {
        Addr::V4(o) => format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3]),
        Addr::V6(o) => {
            let w: Vec<u16> = o
                .chunks(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            let (mut best, mut cur) = ((usize::MAX, 0), (usize::MAX, 0));
            for (i, &x) in w.iter().enumerate() {
                if x == 0 {
                    cur = if cur.0 == usize::MAX {
                        (i, 1)
                    } else {
                        (cur.0, cur.1 + 1)
                    };
                    if best.0 == usize::MAX || cur.1 > best.1 {
                        best = cur;
                    }
                } else {
                    cur = (usize::MAX, 0);
                }
            }
            if best.1 < 2 {
                best = (usize::MAX, 0);
            }
            let mut s = String::new();
            for i in 0..8 {
                if best.0 != usize::MAX && i >= best.0 && i < best.0 + best.1 {
                    if i == best.0 {
                        s.push(':');
                    }
                    continue;
                }
                if i != 0 {
                    s.push(':');
                }
                if i == 6 && best.0 == 0 && (best.1 == 6 || (best.1 == 5 && w[5] == 0xffff)) {
                    s += &format!("{}.{}.{}.{}", o[12], o[13], o[14], o[15]);
                    break;
                }
                s += &format!("{:x}", w[i]);
            }
            if best.0 != usize::MAX && best.0 + best.1 == 8 {
                s.push(':');
            }
            s
        }
    }
}
