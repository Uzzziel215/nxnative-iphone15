#!/usr/bin/env python3
# Probe of Vicarious Visions' Alchemy archives (Crash Team Racing Nitro-Fueled, 0100F9F00C696000): where the shaders shader_split.py misses live.
# The game's log names 47 shaders outside the shader map; shader_split found only 12 (main). The rest are believed to sit in the .pak archives (IGA, files .igz inside),
# whose format no reader here knows yet. This script reads no layout it is not sure of: it reports, for every file under RomFS,
#   · the IGA header words (magic 'IGA\x1a', then u32 fields) so the table layout can be read off real data,
#   · NVN control-section magic (34 12 76 98) and code-area magic (78 56 34 12 / 79 56 34 12) hits in the raw bytes,
#   · compressed streams found by brute force (zlib, raw deflate, LZMA with a 5-byte props header, zstd), and the same magic hits inside what they decode to,
#   · IGZ magic ('IGZ\x01', either byte order) hits, raw and decoded.
# Usage: alchemy_probe.py <RomFS dir> [<report.json>]   Environment PROBE_MAX_MB (default 64): bytes scanned per file for streams; PROBE_SECONDS (default 90): stream search budget per file;
#   PROBE_FILES: comma-separated substrings to limit files; PROBE_DUMP=<dir>: the first and last PROBE_DUMP_KB (default 1024) of every IGA archive go there (<name>.head / .tail), for reading the layout offline;
#   J: processes (default the CPU count)
import concurrent.futures as cf, json, lzma, os, re, struct, sys, time, zlib

CTL_MAGIC, GFX_MAGIC, CS_MAGIC = bytes.fromhex('34127698'), bytes.fromhex('78563412'), bytes.fromhex('79563412')
IGA_MAGIC = b'IGA\x1a'
IGZ_MAGICS = (b'IGZ\x01', b'\x01ZGI')
ZSTD_MAGIC = bytes.fromhex('28b52ffd')

def hits(d):
    """Magic counts in d; controls are only counted 4-aligned with a plausible length at +0x20 and code length at +0x704"""
    ctl = 0
    for m in re.finditer(re.escape(CTL_MAGIC), d):
        c = m.start()
        if c + 0x708 <= len(d):
            n, k = struct.unpack_from('<I', d, c + 0x20)[0], struct.unpack_from('<I', d, c + 0x704)[0]
            if 0x760 <= n <= 0x2000 and 0x30 <= k <= 0x400000: ctl += 1
    return {'ctl': ctl, 'gfx': d.count(GFX_MAGIC), 'cs': d.count(CS_MAGIC), 'igz': sum(d.count(m) for m in IGZ_MAGICS)}

def iga_header(d):
    """The first 0x40 bytes of an IGA archive as u32 words (layout to be confirmed on real data), plus the guesses of the published layouts (igArchiveLib): version, toc size, file count, sector size"""
    if d[:4] != IGA_MAGIC or len(d) < 0x40: return None
    w = struct.unpack_from('<16I', d, 0)
    return {'words': [f'{x:#x}' for x in w], 'version?': w[1], 'toc_size?': w[2], 'files?': w[3], 'sector?': w[4]}

def try_zlib(d, at, wbits):
    o = zlib.decompressobj(wbits)
    try: out = o.decompress(d[at:at + 0x200000], 0x400000)
    except zlib.error: return None
    return out if len(out) >= 0x100 else None

def lzma_props(b):
    """An LZMA1 props header (lc/lp/pb byte + u32 dictionary size) → filter, or None when implausible"""
    p, dic = b[0], struct.unpack_from('<I', b, 1)[0]
    if p >= 9 * 5 * 5 or dic < 0x1000 or dic > 0x4000000 or dic & (dic - 1): return None
    lc, r = p % 9, p // 9
    return {'id': lzma.FILTER_LZMA1, 'lc': lc, 'lp': r % 5, 'pb': r // 5, 'dict_size': dic}

def try_lzma(d, at):
    f = lzma_props(bytes(d[at:at + 5])) if at + 5 <= len(d) else None
    if not f: return None
    o = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[f])
    try: out = o.decompress(d[at + 5:at + 0x100000], 0x400000)
    except lzma.LZMAError: return None
    if len(out) >= 0x100 and not o.eof and len(set(out[:0x100])) > 200: return None   # garbage decoded as LZMA: no end, near-random bytes
    return out if len(out) >= 0x100 else None

def try_zstd(d, at):
    try:
        try: from compression import zstd
        except ImportError: from backports import zstd
    except ImportError: return None
    try: out = zstd.ZstdDecompressor().decompress(d[at:at + 0x2000000], 0x800000)
    except Exception: return None
    return out or None

def streams(d, limit, budget):
    """Brute-force search of compressed streams in the first limit bytes: (kind, offset, decoded length, magic hits in the decoded bytes); stops scanning
    inside a stream once one decodes, so a long stream is counted once. Raw deflate is tried only at sector-aligned (0x800) offsets: it has no header to find"""
    out, d = [], d[:limit]
    mv, cand = memoryview(d), []
    for m in re.finditer(b'\x78[\x01\x5e\x9c\xda]', d): cand.append((m.start(), 'zlib'))
    for m in re.finditer(b'[\x5d\x5e\x6c]\x00\x00[\x01-\x80]\x00', d): cand.append((m.start(), 'lzma'))
    for m in re.finditer(re.escape(ZSTD_MAGIC), d): cand.append((m.start(), 'zstd'))
    cand += [(a, 'deflate') for a in range(0, len(d), 0x800)]
    cand.sort()
    skip_to, t0 = 0, time.monotonic()
    for at, kind in cand:
        if time.monotonic() - t0 > budget: out.append({'kind': 'TIMEOUT', 'at': at, 'out': 0, 'head': '', 'ctl': 0, 'gfx': 0, 'cs': 0, 'igz': 0}); break
        if at < skip_to: continue
        dec = try_zlib(mv, at, 15) if kind == 'zlib' else try_zlib(mv, at, -15) if kind == 'deflate' else try_lzma(mv, at) if kind == 'lzma' else try_zstd(mv, at)
        if dec is None: continue
        h = hits(dec)
        out.append({'kind': kind, 'at': at, 'out': len(dec), 'head': bytes(dec[:16]).hex(), **h})
        skip_to = at + 0x10
    return out

def probe(path, limit, budget, dump, dump_kb, root=''):
    with open(path, 'rb') as f: d = f.read()
    r = {'file': path, 'size': len(d), 'head': d[:16].hex(), 'raw': hits(d)}
    h = iga_header(d)
    if h:
        r['iga'] = h
        if dump:
            n = dump_kb << 10; base = os.path.join(dump, os.path.relpath(path, root).replace(os.sep, '__'))
            with open(base + '.head', 'wb') as f: f.write(d[:n])
            with open(base + '.tail', 'wb') as f: f.write(d[-n:] if len(d) > n else b'')
    if h or path.lower().endswith(('.pak', '.igz', '.arc')):
        s = streams(d, limit, budget)
        r['streams'] = len(s)
        r['kinds'] = sorted({x['kind'] for x in s})
        r['decoded'] = {k: sum(x[k] for x in s) for k in ('ctl', 'gfx', 'cs', 'igz')}
        r['first_streams'] = s[:12]
    return r

def main():
    if len(sys.argv) < 2: sys.exit(__doc__ or 'usage: alchemy_probe.py <RomFS dir> [<report.json>]')
    root, limit = sys.argv[1], int(os.environ.get('PROBE_MAX_MB', '64')) << 20
    budget, dump, dump_kb = float(os.environ.get('PROBE_SECONDS', '90')), os.environ.get('PROBE_DUMP'), int(os.environ.get('PROBE_DUMP_KB', '1024'))
    if dump: os.makedirs(dump, exist_ok=True)
    only = [s for s in os.environ.get('PROBE_FILES', '').split(',') if s]
    paths = sorted(os.path.join(dp, fn) for dp, _, fs in os.walk(root) for fn in fs)
    paths = [p for p in paths if not only or any(s in p for s in only)]
    rep = []
    with cf.ProcessPoolExecutor(int(os.environ.get('J', '0')) or None) as ex:
        for p, r in zip(paths, ex.map(probe, paths, *zip(*[(limit, budget, dump, dump_kb, root)] * len(paths)))) if paths else ():
            rep.append(r)
            line = f"{os.path.relpath(p, root)}  {r['size']:,} B  head {r['head'][:8]}  raw ctl {r['raw']['ctl']} gfx {r['raw']['gfx']} igz {r['raw']['igz']}"
            if 'streams' in r: line += f"  | streams {r['streams']} {','.join(r['kinds'])}  decoded ctl {r['decoded']['ctl']} gfx {r['decoded']['gfx']} igz {r['decoded']['igz']}"
            if 'iga' in r: line += f"  | IGA v{r['iga']['version?']:#x} files? {r['iga']['files?']}"
            print(line, flush=True)
    tot = lambda k, f: sum(r[f][k] for r in rep if f in r)
    print(f"\nTOTAL files {len(rep)}  raw ctl {tot('ctl', 'raw')}  decoded ctl {tot('ctl', 'decoded')}  IGA archives {sum('iga' in r for r in rep)}")
    if len(sys.argv) > 2:
        with open(sys.argv[2], 'w') as f: json.dump(rep, f, indent=1)

if __name__ == '__main__': main()
