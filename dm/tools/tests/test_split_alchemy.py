"""shader_split: Vicarious Visions Alchemy archives (IGA version 0xd, Crash Team Racing Nitro-Fueled's .pak) are read member by member: stored members as they are, compressed ones
as LZMA blocks through the block table their length picks (iga_members); only shaders/ members are scanned, and each control section takes the code area right after it
(alchemy_shaders). No game files needed."""
import lzma
import os
import struct
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / 'dm/gfx/tools'))
_had = os.environ.get('DM_GAME'); os.environ['DM_GAME'] = '010029B0118E8000'   # shader_split loads a profile at import; other tests expect no default game
import shader_split as ss
if _had is None: del os.environ['DM_GAME']
else: os.environ['DM_GAME'] = _had

PROPS = bytes([93]) + struct.pack('<I', 0x8000)   # lc 3, lp 0, pb 2, as CTR's archives have


def lzma_block(raw):
    data = lzma.compress(raw, format=lzma.FORMAT_RAW, filters=[{'id': lzma.FILTER_LZMA1, 'lc': 3, 'lp': 0, 'pb': 2, 'dict_size': 0x8000}])
    return struct.pack('<I', len(data)) + PROPS + data


def archive(members, version=0xd):
    """members: [(archive path, bytes, compressed)] → an IGA file: header, hashes, member table, small and medium block tables, sector-aligned data, then the name table"""
    n, sector = len(members), 0x800
    small, med, data, table = [], [], bytearray(), []
    pos = lambda: (len(data) + sector - 1) // sector * sector
    for name, raw, comp in members:
        data += bytes(pos() - len(data)); start = len(data)
        if not comp: table.append((start, len(raw), 0xffffffff)); data += raw; continue
        sectors = (len(raw) + sector - 1) // sector
        blocks, top = (small, 0x80) if sectors <= 0x7f else (med, 0x8000)
        table.append((start, len(raw), 0x20000000 | len(blocks)))
        for k in range(0, len(raw), 0x8000):
            data += bytes(pos() - len(data)); blocks.append(top | (len(data) - start) // sector)
            data += lzma_block(raw[k:k + 0x8000])
    names = bytearray(4 * n)
    for i, (name, _, _) in enumerate(members):
        struct.pack_into('<I', names, 4 * i, len(names)); names += b'temporary/octane/data/nx/output/' + name.encode() + b'\0' + name.encode() + b'\0'
    toc = 4 * n + 16 * n + 2 * len(med) + len(small)
    base = (0x38 + toc + sector - 1) // sector * sector
    noff = (base + len(data) + sector - 1) // sector * sector
    head = struct.pack('<4s9IQII', ss.IGA, version, toc, n, sector, 0, 0, 0, len(med), len(small), noff, len(names), 1)
    body = bytes(4 * n) + b''.join(struct.pack('<4I', base + o, 0, ln, m) for o, ln, m in table) + struct.pack(f'<{len(med)}H', *med) + bytes(small)
    out = bytearray(head + body); out += bytes(base - len(out)); out += data; out += bytes(noff - len(out)); out += names
    return bytes(out)


def shader(code_len=0x100, stage_word=0x0461):
    """a vertex shader: a 0x850-byte control section (its length at +0x20, the code length at +0x704) and its code area (0x30 header + SPH)"""
    ctl = bytearray(0x850); ctl[:4] = ss.CTL_MAGIC; struct.pack_into('<I', ctl, 0x20, 0x850); struct.pack_into('<I', ctl, 0x704, code_len)
    code = bytearray(code_len); code[:4] = ss.GFX_MAGIC; struct.pack_into('<I', code, 0x30, stage_word); code[0x40:0x48] = os.urandom(8)
    return bytes(ctl), bytes(code)


class Alchemy(unittest.TestCase):
    def test_members_decode_through_both_block_tables(self):
        small, big, stored = os.urandom(0x9000), os.urandom(0x41000), b'stored member'
        d = archive([('shaders/a.igz', small, True), ('vsc/b.igz', big, True), ('ui/c.lng', stored, False)])
        self.assertEqual(ss.iga_members(d, '/x.pak'), [('shaders/a.igz', small), ('vsc/b.igz', big), ('ui/c.lng', stored)])
        self.assertEqual(ss.iga_members(d, '/x.pak', lambda nm: nm.startswith('ui/')), [('ui/c.lng', stored)])

    def test_shaders_pair_control_and_following_code(self):
        (c1, k1), (c2, k2) = shader(), shader(0x200)
        igz = b'\x01ZGI' + bytes(0x7c) + c1 + k1 + bytes(12) + c2 + k2
        d = archive([('shaders/Standard.igz', igz, True), ('vsc/menu.igz', c1 + k1, True)])
        got = ss.alchemy_shaders(d, '/archives/shaders_nx.pak')
        self.assertEqual([(st, ss.skey(c, k)) for _, st, c, k in got], [('vs', ss.skey(c1, k1)), ('vs', ss.skey(c2, k2))])
        self.assertTrue(all(w.startswith('/archives/shaders_nx.pak/shaders/Standard.igz#IGA@') for w, *_ in got))

    def test_unknown_version_is_named(self):
        with self.assertRaises(SystemExit) as e: ss.iga_members(archive([('a', b'x', False)], version=0xb), '/y.pak')
        self.assertIn('IGA version 0xb', str(e.exception.code))


if __name__ == '__main__':
    unittest.main()
