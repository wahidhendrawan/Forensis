//! pcap / pcapng framing that mirrors dpkt 1.9.8's `pcap.Reader` and `pcapng.Reader`
//! byte for byte, including their quirks (Python `f.read(n)` semantics for bogus block
//! lengths, only the first IDB's timestamp options, error texts), so the
//! native engine returns the same results and errors as the dpkt reference.

use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Clone, Copy)]
pub enum Ts {
    /// Seconds as a Python float.
    F(f64),
    /// Nanosecond pcap: Python builds `sec + Decimal(frac) / Decimal('1E9')`.
    Nano { sec: u32, frac: u32 },
}

impl Ts {
    /// `<` between timestamps of one file (they always share a variant).
    pub fn lt(self, other: Ts) -> bool {
        match (self, other) {
            (Ts::F(a), Ts::F(b)) => a < b,
            (Ts::Nano { sec: s1, frac: f1 }, Ts::Nano { sec: s2, frac: f2 }) => {
                s1 as u128 * 1_000_000_000 + (f1 as u128) < s2 as u128 * 1_000_000_000 + f2 as u128
            }
            _ => false,
        }
    }
}

pub enum Detail {
    Msg(String),
    /// OSError; the path is set when it came from open() (Python includes the filename then).
    Io(io::Error, Option<String>),
    /// UnicodeDecodeError from a pcapng comment option; Python renders the exact message.
    Comment(Vec<u8>),
}

pub struct CaptureError {
    /// true -> "Invalid PCAP format: ...", false -> "System error during analysis: ..."
    pub invalid_format: bool,
    pub detail: Detail,
}

fn msg(invalid_format: bool, m: impl Into<String>) -> CaptureError {
    CaptureError {
        invalid_format,
        detail: Detail::Msg(m.into()),
    }
}

fn need(invalid_format: bool, got: usize, needed: usize) -> CaptureError {
    msg(
        invalid_format,
        format!("got {got}, {needed} needed at least"),
    )
}

/// Python slice `buf[start:end]` (start >= 0, end may be negative).
pub fn py_slice(buf: &[u8], start: i64, end: i64) -> &[u8] {
    let n = buf.len() as i64;
    let norm = |i: i64| if i < 0 { (i + n).max(0) } else { i.min(n) };
    let (s, e) = (norm(start), norm(end));
    if s >= e {
        &[]
    } else {
        &buf[s as usize..e as usize]
    }
}

fn u16_at(b: &[u8], o: usize, le: bool) -> u16 {
    let v = [b[o], b[o + 1]];
    if le {
        u16::from_le_bytes(v)
    } else {
        u16::from_be_bytes(v)
    }
}

fn u32_at(b: &[u8], o: usize, le: bool) -> u32 {
    let v = [b[o], b[o + 1], b[o + 2], b[o + 3]];
    if le {
        u32::from_le_bytes(v)
    } else {
        u32::from_be_bytes(v)
    }
}

/// Python file semantics: `read(n)` returns up to n bytes, -1 reads to EOF, below -1 raises.
struct PyFile(BufReader<File>);

impl PyFile {
    fn read(
        &mut self,
        n: i64,
        out: &mut Vec<u8>,
        invalid_format: bool,
    ) -> Result<(), CaptureError> {
        if n < -1 {
            return Err(msg(
                invalid_format,
                "read length must be non-negative or -1",
            ));
        }
        let r = if n == -1 {
            self.0.read_to_end(out)
        } else {
            (&mut self.0).take(n as u64).read_to_end(out)
        };
        r.map(|_| ()).map_err(|e| CaptureError {
            invalid_format,
            detail: Detail::Io(e, None),
        })
    }
}

enum Format {
    Pcap {
        le: bool,
        rec_len: usize,
        nano: bool,
    },
    Pcapng {
        le: bool,
        divisor: f64,
        tsoffset: i64,
    },
}

pub struct Capture {
    f: PyFile,
    fmt: Format,
    buf: Vec<u8>,
}

impl Capture {
    pub fn open(path: &Path) -> Result<Capture, CaptureError> {
        let file = File::open(path).map_err(|e| CaptureError {
            invalid_format: false,
            detail: Detail::Io(e, Some(path.to_string_lossy().into_owned())),
        })?;
        let mut f = PyFile(BufReader::with_capacity(1 << 16, file));
        let mut hdr = Vec::with_capacity(24);
        f.read(24, &mut hdr, false)?;
        // dpkt.pcap.Reader: a short header is NeedData (not ValueError), so pcapng is never tried.
        if hdr.len() < 24 {
            return Err(need(false, hdr.len(), 24));
        }
        let pcap = match u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) {
            0xa1b2c3d4 => Some((false, 16, false)),
            0xa1b23c4d => Some((false, 16, true)),
            0xa1b2cd34 => Some((false, 24, false)),
            0xd4c3b2a1 => Some((true, 16, false)),
            0x4d3cb2a1 => Some((true, 16, true)),
            0x34cdb2a1 => Some((true, 24, false)),
            _ => None,
        };
        let fmt = match pcap {
            Some((le, rec_len, nano)) => Format::Pcap { le, rec_len, nano },
            None => {
                f.0.seek(SeekFrom::Start(0)).map_err(|e| CaptureError {
                    invalid_format: false,
                    detail: Detail::Io(e, None),
                })?;
                pcapng_header(&mut f)?
            }
        };
        Ok(Capture {
            f,
            fmt,
            buf: Vec::with_capacity(1 << 16),
        })
    }

    /// Next (timestamp, frame); Ok(None) at EOF. Errors mean dpkt raised mid-iteration.
    pub fn next(&mut self) -> Result<Option<(Ts, &[u8])>, CaptureError> {
        match self.fmt {
            Format::Pcap { le, rec_len, nano } => {
                self.buf.clear();
                self.f.read(rec_len as i64, &mut self.buf, false)?;
                if self.buf.is_empty() {
                    return Ok(None);
                }
                if self.buf.len() < rec_len {
                    return Err(need(false, self.buf.len(), rec_len));
                }
                let sec = u32_at(&self.buf, 0, le);
                let frac = u32_at(&self.buf, 4, le);
                let caplen = u32_at(&self.buf, 8, le);
                self.buf.clear();
                self.f.read(caplen as i64, &mut self.buf, false)?;
                let ts = if nano {
                    Ts::Nano { sec, frac }
                } else {
                    Ts::F(sec as f64 + frac as f64 / 1e6)
                };
                Ok(Some((ts, &self.buf)))
            }
            Format::Pcapng {
                le,
                divisor,
                tsoffset,
            } => loop {
                self.buf.clear();
                self.f.read(8, &mut self.buf, false)?;
                if self.buf.len() < 8 {
                    return Ok(None);
                }
                let blk_type = u32_at(&self.buf, 0, le);
                let blk_len = u32_at(&self.buf, 4, le);
                self.f.read(blk_len as i64 - 8, &mut self.buf, false)?;
                // 6 = Enhanced Packet Block, 2 = (obsolete) Packet Block; same layout for what we read.
                if blk_type != 6 && blk_type != 2 {
                    continue;
                }
                let b = &self.buf;
                if b.len() < 32 {
                    return Err(need(false, b.len(), 32));
                }
                let caplen = u32_at(b, 20, le);
                block_options(b, 32, 28 + align32(caplen as i64), le, false)?;
                let raw = ((u32_at(b, 12, le) as u64) << 32) | u32_at(b, 16, le) as u64;
                let ts = Ts::F(tsoffset as f64 + raw as f64 / divisor);
                return Ok(Some((ts, py_slice(&self.buf, 28, 28 + caplen as i64))));
            },
        }
    }
}

fn align32(i: i64) -> i64 {
    (i + 3) / 4 * 4
}

/// `_PcapngBlock.unpack` + `_do_unpack_options`: header length check, total length check,
/// option walk (comment decoding included) and the trailing length field. Returns the options.
fn block_options(
    buf: &[u8],
    hdr_len: usize,
    opts_offset: i64,
    le: bool,
    invalid_format: bool,
) -> Result<Vec<(u16, Vec<u8>)>, CaptureError> {
    if buf.len() < hdr_len {
        return Err(need(invalid_format, buf.len(), hdr_len));
    }
    let blk_len = u32_at(buf, 4, le) as i64;
    if blk_len > buf.len() as i64 {
        return Err(msg(invalid_format, "")); // bare dpkt.NeedData
    }
    let mut opts = Vec::new();
    let mut rest = py_slice(buf, opts_offset, opts_offset + (blk_len - opts_offset - 4));
    while !rest.is_empty() {
        if rest.len() < 4 {
            return Err(need(invalid_format, rest.len(), 4));
        }
        let code = u16_at(rest, 0, le);
        let data = py_slice(rest, 4, 4 + u16_at(rest, 2, le) as i64);
        if code == 1 && comment_fails(data) {
            return Err(CaptureError {
                invalid_format,
                detail: Detail::Comment(data.to_vec()),
            });
        }
        opts.push((code, data.to_vec()));
        let used = 4 + align32(data.len() as i64) as usize;
        rest = &rest[used.min(rest.len())..];
        if code == 0 {
            break;
        }
    }
    let n = buf.len();
    if u32_at(buf, n - 4, le) as i64 != blk_len {
        return Err(msg(invalid_format, "length fields do not match"));
    }
    Ok(opts)
}

/// PcapngOption.unpack: utf-8, else (if a NUL exists) ascii up to the NUL, else raise.
fn comment_fails(data: &[u8]) -> bool {
    std::str::from_utf8(data).is_err()
        && match data.iter().position(|&b| b == 0) {
            Some(i) => !data[..i].is_ascii(),
            None => true,
        }
}

fn pcapng_header(f: &mut PyFile) -> Result<Format, CaptureError> {
    let mut buf = Vec::with_capacity(64);
    f.read(28, &mut buf, true)?;
    if buf.len() < 28 {
        return Err(msg(true, "invalid pcapng header"));
    }
    if u32_at(&buf, 0, false) != 0x0A0D0D0A {
        return Err(msg(true, "invalid pcapng header: not a SHB"));
    }
    let le = match u32_at(&buf, 8, false) {
        0x4D3C2B1A => true,
        0x1A2B3C4D => false,
        _ => return Err(msg(true, "unknown endianness")),
    };
    f.read(u32_at(&buf, 4, le) as i64 - 28, &mut buf, true)?;
    block_options(&buf, 28, 24, le, true)?;
    let (major, minor) = (u16_at(&buf, 12, le), u16_at(&buf, 14, le));
    if major != 1 {
        return Err(msg(true, format!("unknown pcapng version {major}.{minor}")));
    }
    // First Interface Description Block; other blocks before it are skipped.
    let idb_opts = loop {
        buf.clear();
        f.read(8, &mut buf, true)?;
        if buf.len() < 8 {
            return Err(msg(true, "IDB not found"));
        }
        let blk_type = u32_at(&buf, 0, le);
        f.read(u32_at(&buf, 4, le) as i64 - 8, &mut buf, true)?;
        if blk_type == 1 {
            break block_options(&buf, 20, 16, le, true)?;
        }
    };
    let (mut divisor, mut tsoffset) = (1e6_f64, 0_i64);
    for (code, data) in idb_opts {
        if code == 9 {
            let [v] = data[..] else {
                return Err(msg(true, "unpack requires a buffer of 1 bytes"));
            };
            let exp = (v & 0x7f) as i32;
            // float(10 ** exp) is correctly rounded; parsing "1eN" is too.
            divisor = if v & 0x80 != 0 {
                2f64.powi(exp)
            } else {
                format!("1e{exp}").parse().unwrap_or(f64::INFINITY)
            };
        } else if code == 14 {
            let Ok(raw) = <[u8; 8]>::try_from(&data[..]) else {
                return Err(msg(true, "unpack requires a buffer of 8 bytes"));
            };
            tsoffset = if le {
                i64::from_le_bytes(raw)
            } else {
                i64::from_be_bytes(raw)
            };
        }
    }
    Ok(Format::Pcapng {
        le,
        divisor,
        tsoffset,
    })
}
