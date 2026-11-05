#!/usr/bin/env python3
"""
System-NNN engine internals: SPT scripts, init config files, text layout and
game-exe probing.

Everything here is derived from the engine's published source code
(https://github.com/tinyan/SystemNNN), mainly:

  nnnLib/execscript.cpp     - SPT loading, decryption, string tables
  nnnUtilLib/namelist.cpp   - init/*.xtx (plain) and init2/*.fxf (XOR 0xFF)
  nnnUtilLib/mymessage.cpp  - message rendering, '#' inline codes,
                              half-width -> full-width conversion
  nnnUtilLib/myfont.cpp     - codeByte (1/2), fonts, rightShift1Byte
  nnnLib/gamecallback.cpp   - which init keys the engine reads

Only the Python standard library is used.
"""

import os
import re
import struct
import unicodedata
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# =============================================================================
# SPT encryption
# =============================================================================
#
# The engine reads the file as 32-bit words and decrypts each one with
#
#     word = (word ^ key) + inc;   key += add_xor;   inc += add_inc
#
# The defaults (key=0xFFFFFFFF, add_xor=0, add_inc=0) are equivalent to
# XOR-ing every byte with 0xFF, which is what almost every shipped game uses.
# A few titles change the three constants; they can be passed through.

DEFAULT_SPT_KEY = (0xFFFFFFFF, 0, 0)


def _parse_key(key) -> Tuple[int, int, int]:
    if key is None:
        return DEFAULT_SPT_KEY
    if isinstance(key, str):
        parts = [int(p, 0) for p in key.split(',')]
        while len(parts) < 3:
            parts.append(0)
        return parts[0] & 0xFFFFFFFF, parts[1] & 0xFFFFFFFF, parts[2] & 0xFFFFFFFF
    return tuple(int(k) & 0xFFFFFFFF for k in key)  # type: ignore


def nnn_decrypt(data: bytes, key=None) -> bytes:
    xor, add_xor, add_inc = _parse_key(key)
    if (xor, add_xor, add_inc) == DEFAULT_SPT_KEY:
        return bytes(b ^ 0xFF for b in data)
    pad = (-len(data)) % 4
    words = struct.unpack('<%dI' % ((len(data) + pad) // 4), data + b'\0' * pad)
    out = []
    inc = 0
    for w in words:
        out.append(((w ^ xor) + inc) & 0xFFFFFFFF)
        xor = (xor + add_xor) & 0xFFFFFFFF
        inc = (inc + add_inc) & 0xFFFFFFFF
    return struct.pack('<%dI' % len(out), *out)[:len(data)]


def nnn_encrypt(data: bytes, key=None) -> bytes:
    xor, add_xor, add_inc = _parse_key(key)
    if (xor, add_xor, add_inc) == DEFAULT_SPT_KEY:
        return bytes(b ^ 0xFF for b in data)
    pad = (-len(data)) % 4
    words = struct.unpack('<%dI' % ((len(data) + pad) // 4), data + b'\0' * pad)
    out = []
    inc = 0
    for w in words:
        out.append(((w - inc) & 0xFFFFFFFF) ^ xor)
        xor = (xor + add_xor) & 0xFFFFFFFF
        inc = (inc + add_inc) & 0xFFFFFFFF
    return struct.pack('<%dI' % len(out), *out)[:len(data)]


def is_spt_data(data: bytes, key=None) -> bool:
    if len(data) < 0x40:
        return False
    head = nnn_decrypt(data[:0x40], key)
    return head[0x30:0x39] == b'SPTHEADER'


# =============================================================================
# SPT script
# =============================================================================
#
# Header (32-bit words, after decryption):
#   [4] message count      [5] word index of the message pointer table
#   [6] string count       [7] word index of the string pointer table
#   [12..15] "SPTHEADER0      "
# Each table entry is the word index of a NUL-terminated CP932 string.
# Bytecode refers to text only through these tables (by number), so a string
# can be moved anywhere in the file as long as its table entry is updated.
#
# Message strings look like "name\r\nbody" for dialogue and "body" for
# narration. Table 2 holds choice texts, but also file names and labels.

JP_RE = re.compile(r'[぀-ヿ㐀-鿿！-｠　-〿]')
NAME_FORBIDDEN = set('「」『』（）()。、！？!?…―─：:　 ')
QUOTE_OPENERS = ('「', '『', '（', '(', '《', '〈', '“')

# '#' starts an inline code; the code character is a single SJIS char.
# 姓 名 = player surname/given name, ［ ］ = ruby, 強 = emphasis, 終 = end,
# ０-９ = colours, シ = system replacement text, 改 花 = misc.
INLINE_CODE_CHARS = '姓名改花［］強終シ０１２３４５６７８９'
INLINE_CODE_RE = re.compile('#[' + INLINE_CODE_CHARS + ']')


@dataclass
class SPTEntry:
    id: str
    table: int
    slot: int
    word: int
    raw: bytes
    name: str = ''
    text: str = ''
    kind: str = 'message'  # message | choice
    translated: str = ''
    name_translated: str = ''


def split_name(full: str) -> Tuple[str, str]:
    """Split 'name\\r\\nbody' into (name, body). Narration returns ('', full)."""
    norm = full.replace('\r\n', '\n')
    if '\n' not in norm:
        return '', norm
    first, rest = norm.split('\n', 1)
    if (0 < len(first) <= 12 and not any(c in NAME_FORBIDDEN for c in first)
            and rest.lstrip('　 ').startswith(QUOTE_OPENERS)):
        return first, rest
    return '', norm


class SPTScript:
    """Table-based SPT reader/writer (safe for any translation length)."""

    def __init__(self, key=None):
        self.key = key
        self.data = b''
        self.words: Tuple[int, ...] = ()
        self.entries: List[SPTEntry] = []
        self.tables: List[Tuple[int, int]] = []
        self.trailing_newline: Dict[str, bool] = {}

    # ---------------------------------------------------------------- parse
    def parse(self, raw: bytes) -> bool:
        dec = nnn_decrypt(raw, self.key)
        if len(dec) < 0x40 or dec[0x30:0x39] != b'SPTHEADER':
            return False
        pad = (-len(dec)) % 4
        self.data = dec + b'\0' * pad
        self.orig_len = len(dec)
        self.words = struct.unpack('<%dI' % (len(self.data) // 4), self.data)
        w = self.words
        self.tables = [(w[4], w[5]), (w[6], w[7])]
        self.entries = []
        for t, (count, ptr) in enumerate(self.tables, start=1):
            if ptr + count > len(w):
                return False
            for i in range(count):
                word = w[ptr + i]
                off = word * 4
                if off >= len(self.data):
                    continue
                end = self.data.find(b'\0', off)
                if end < 0:
                    end = len(self.data)
                rawstr = self.data[off:end]
                text = rawstr.decode('cp932', errors='replace')
                e = SPTEntry(id=f'{"m" if t == 1 else "s"}{i}', table=t, slot=i,
                             word=word, raw=rawstr)
                if t == 1:
                    e.name, e.text = split_name(text)
                    e.kind = 'message'
                else:
                    if not JP_RE.search(text):
                        continue  # file names, labels, variables
                    e.text = text.replace('\r\n', '\n')
                    e.kind = 'choice'
                self.entries.append(e)
        return True

    @property
    def strings(self):
        return self.entries

    # ---------------------------------------------------------------- json
    def to_json(self, source_file: str = '') -> dict:
        return {
            'source_file': source_file,
            'format': 'spt-table',
            'version': 2,
            'string_count': len(self.entries),
            'strings': [
                {
                    'id': e.id,
                    'index': n,
                    'kind': e.kind,
                    'name': e.name,
                    'name_translated': e.name_translated,
                    'original': e.text,
                    'translated': e.translated,
                }
                for n, e in enumerate(self.entries)
            ],
        }

    def import_json(self, doc: dict):
        if doc.get('format') != 'spt-table':
            raise ValueError(
                'This JSON was made by an older VNTools SPT extractor whose string '
                'indices do not match the table-based parser. Re-run extract-text '
                'and carry translations over with `migrate-json`.')
        by_id = {s['id']: s for s in doc.get('strings', [])}
        for e in self.entries:
            s = by_id.get(e.id)
            if s:
                e.translated = s.get('translated', '') or ''
                e.name_translated = s.get('name_translated', '') or ''

    # ---------------------------------------------------------------- build
    def rebuild(self, encoder: 'MessageEncoder', names: Optional[Dict[str, str]] = None) -> bytes:
        names = names or {}
        buf = bytearray(self.data)
        # Slot capacity: bytes until the next string (any table) or a table start.
        starts = sorted(set(self.words[p + i] * 4 for c, p in self.tables for i in range(c)))
        barriers = sorted(starts + [p * 4 for c, p in self.tables] + [len(self.data)])

        def capacity(off: int) -> int:
            for b in barriers:
                if b > off:
                    return b - off
            return len(self.data) - off

        refs: Dict[int, int] = {}
        for c, p in self.tables:
            for i in range(c):
                refs[self.words[p + i]] = refs.get(self.words[p + i], 0) + 1

        appended = bytearray()
        base = len(self.data)
        for e in self.entries:
            if not e.translated and not (e.name and (e.name_translated or names.get(e.name))):
                continue
            body = (e.translated or e.text).rstrip('\r\n')
            orig_norm = e.text.replace('\r\n', '\n')
            body += '\n' * (len(orig_norm) - len(orig_norm.rstrip('\n')))
            if e.kind == 'message' and e.name:
                nm = e.name_translated or names.get(e.name) or e.name
                full = nm + '\r\n' + body.replace('\r\n', '\n').replace('\n', '\r\n')
            else:
                full = body.replace('\r\n', '\n').replace('\n', '\r\n')
            new = encoder.encode(full, original=e.raw.decode('cp932', 'replace'))
            off = e.word * 4
            if refs.get(e.word, 0) == 1 and len(new) + 1 <= capacity(off):
                cap = capacity(off)
                buf[off:off + cap] = new + b'\0' * (cap - len(new))
            else:
                word = (base + len(appended)) // 4
                blob = new + b'\0'
                blob += b'\0' * ((-len(blob)) % 4)
                appended += blob
                _, ptr = self.tables[e.table - 1]
                struct.pack_into('<I', buf, (ptr + e.slot) * 4, word)
        out = bytes(buf[:self.orig_len]) if not appended else bytes(buf) + bytes(appended)
        return nnn_encrypt(out, self.key)


# =============================================================================
# Message encoding / layout
# =============================================================================

# Typography the engine (CP932 / full-width cells) cannot show or would show
# badly, mapped to safe equivalents. Applied before SJIS encoding.
TYPO_MAP = {
    '‘': "'", '’': "'", '“': '"', '”': '"',
    '—': '―', '–': '-', '…': '…', ' ': ' ',
    '‒': '-', '‑': '-', '´': "'", '`': "'",
}


def strip_accents(s: str) -> str:
    return ''.join(c for c in unicodedata.normalize('NFKD', s) if not unicodedata.combining(c))


class SJISTunnel:
    """
    VNTextProxy-compatible SJIS tunneling (same algorithm as VNTextPatch).

    Characters CP932 cannot encode are mapped to SJIS lead byte + an invalid
    trail byte (0x01-0x3F, skipping \\t \\n \\r space and comma). The list of
    mapped characters is written to sjis_ext.bin as raw UTF-16LE; VNTextProxy
    (placed next to the game exe) reads it and draws the real characters.
    """

    LOW_AVOID = (0x09, 0x0A, 0x0D, 0x20, 0x2C)
    PER_HIGH = 0x40 - len(LOW_AVOID) - 1  # 0x3A
    LIMIT = 0x3B * PER_HIGH

    def __init__(self, path: Optional[str] = None):
        self.chars: List[str] = []
        self.index: Dict[str, int] = {}
        if path and os.path.exists(path):
            self.load(path)

    def load(self, path: str):
        data = open(path, 'rb').read()
        for i in range(0, len(data) - 1, 2):
            self._add(data[i:i + 2].decode('utf-16le'))

    def save(self, path: str):
        with open(path, 'wb') as f:
            f.write(''.join(self.chars).encode('utf-16le'))

    def _add(self, ch: str) -> int:
        if ch in self.index:
            return self.index[ch]
        if len(self.chars) >= self.LIMIT:
            raise ValueError('SJIS tunnel limit exceeded')
        self.index[ch] = len(self.chars)
        self.chars.append(ch)
        return self.index[ch]

    def tunnel_bytes(self, ch: str) -> bytes:
        idx = self._add(ch)
        hi_idx, lo_idx = divmod(idx, self.PER_HIGH)
        hi = 0x81 + hi_idx if hi_idx < 0x1F else 0xE0 + (hi_idx - 0x1F)
        lo = 1 + lo_idx
        for avoid in self.LOW_AVOID:
            if lo >= avoid:
                lo += 1
        return bytes([hi, lo])

    def encode_char(self, ch: str) -> bytes:
        try:
            b = ch.encode('cp932')
            if b[0] < 0xF0:
                return b
        except UnicodeEncodeError:
            pass
        if len(ch.encode('utf-16le')) != 2:
            raise ValueError(f'Cannot tunnel non-BMP character {ch!r}')
        return self.tunnel_bytes(ch)


class MessageEncoder:
    """Turn translated text into bytes the engine accepts."""

    def __init__(self, tunnel: Optional[SJISTunnel] = None, ascii_fallback: bool = True,
                 code_byte: int = 2):
        self.tunnel = tunnel
        self.ascii_fallback = ascii_fallback
        self.code_byte = code_byte
        self.warnings: List[str] = []

    def normalize(self, text: str, original: str = '') -> str:
        if self.tunnel is None:
            # Without VNTextProxy the font only has CP932 glyphs: use look-alikes.
            text = ''.join(TYPO_MAP.get(c, c) for c in text)
        # '#' is the engine's inline-code prefix. Keep codes that also appear in
        # the original line; turn any other '#' into a full-width sign.
        keep = set(INLINE_CODE_RE.findall(original))
        out = []
        i = 0
        while i < len(text):
            if text[i] == '#':
                pair = text[i:i + 2]
                if pair in keep:
                    out.append(pair)
                    i += 2
                    continue
                out.append('＃')
                i += 1
                continue
            out.append(text[i])
            i += 1
        return ''.join(out)

    def encode(self, text: str, original: str = '') -> bytes:
        text = self.normalize(text, original)
        if self.code_byte == 1:
            return self._encode_single_byte(text)
        out = bytearray()
        for ch in text:
            if self.tunnel is not None:
                out += self.tunnel.encode_char(ch)
                continue
            try:
                out += ch.encode('cp932')
            except UnicodeEncodeError:
                alt = strip_accents(ch) if self.ascii_fallback else ''
                try:
                    out += alt.encode('cp932') if alt else b'?'
                except UnicodeEncodeError:
                    out += b'?'
                self.warnings.append(f'unencodable {ch!r} replaced (use --tunnel to keep it)')
        return bytes(out)


ASCII_MAP = {
    '\u2015': '-', '\u2014': '-', '\u2026': '...', '\u3000': ' ', '\u300c': '"', '\u300d': '"',
    '\u300e': "'", '\u300f': "'", '\uff08': '(', '\uff09': ')', '\u3001': ',', '\u3002': '.',
    '\uff01': '!', '\uff1f': '?', '\uff1a': ':', '\uff5e': '~', '\u301c': '~', '\u30fb': '-',
    '\uff0d': '-', '\u2212': '-', '\uff03': '#',
}


def _single_byte_warn(self, ch):
    self.warnings.append(f'codeByte 1 output is ASCII only: {ch!r} replaced')


def _encode_single_byte(self, text: str) -> bytes:
    """codeByte=1: the engine selects an ANSI font and draws one byte per cell,
    so only ASCII is safe. Inline #codes are written as '#' + one byte."""
    out = bytearray()
    for ch in text:
        if ord(ch) < 0x80:
            out.append(ord(ch))
            continue
        alt = ASCII_MAP.get(ch)
        if alt is None:
            alt = unicodedata.normalize('NFKC', ch)
            alt = strip_accents(alt)
        if alt and all(ord(c) < 0x80 for c in alt):
            out += alt.encode('ascii')
        else:
            out += b'?'
            _single_byte_warn(self, ch)
    return bytes(out)


MessageEncoder._encode_single_byte = _encode_single_byte


def cell_width(ch: str, code_byte: int) -> int:
    """Width of one character in half-width units as the engine lays it out."""
    if code_byte == 2:
        return 2  # every character, ASCII included, gets a full-width cell
    o = ord(ch)
    if o < 0x80 or 0xFF61 <= o <= 0xFF9F:
        return 1
    return 2


def text_width(s: str, code_byte: int) -> int:
    s = INLINE_CODE_RE.sub('', s)
    return sum(cell_width(c, code_byte) for c in s)


def wrap_text(text: str, width: int, code_byte: int = 2) -> str:
    """
    Word-wrap text to `width` half-width units. The engine never wraps on its
    own: it only breaks lines at '\\n', so every break must be in the script.
    """
    if width <= 0:
        return text
    lines_out = []
    for para in text.replace('\r\n', '\n').split('\n'):
        words = para.split(' ')
        cur = ''
        for word in words:
            cand = word if not cur else cur + ' ' + word
            if text_width(cand, code_byte) <= width:
                cur = cand
                continue
            if cur:
                lines_out.append(cur)
            # Hard-split words longer than a line
            while text_width(word, code_byte) > width:
                n = 0
                acc = 0
                for ch in word:
                    w = cell_width(ch, code_byte)
                    if acc + w > width:
                        break
                    acc += w
                    n += 1
                lines_out.append(word[:n])
                word = word[n:]
            cur = word
        lines_out.append(cur)
    return '\n'.join(lines_out)


def measure_layout(entries: List[SPTEntry]) -> Tuple[int, int]:
    """(max line width in half-width units, max lines) of the original text."""
    max_w = 0
    max_lines = 0
    for e in entries:
        if e.kind != 'message':
            continue
        lines = e.text.split('\n')
        while lines and lines[-1] == '':
            lines.pop()
        max_lines = max(max_lines, len(lines))
        for ln in lines:
            max_w = max(max_w, text_width(ln, 2))
    return max_w, max_lines


def unwrap_japanese(text: str) -> str:
    """Join the original's hard line breaks for the translator (keep blank-line breaks)."""
    lines = text.replace('\r\n', '\n').split('\n')
    while lines and lines[-1] == '':
        lines.pop()
    return '\n'.join(lines)


# =============================================================================
# QA for System-NNN output
# =============================================================================

def qa_entry(original: str, translated: str, width: int, max_lines: int,
             code_byte: int = 2, tunnel: bool = False) -> List[str]:
    issues = []
    if not translated:
        return issues
    for code in set(INLINE_CODE_RE.findall(original)):
        if original.count(code) != translated.count(code):
            issues.append(f'inline code {code} count changed')
    if not tunnel:
        bad = sorted({c for c in ''.join(TYPO_MAP.get(c, c) for c in translated)
                      if not _cp932_ok(c)})
        if bad:
            issues.append('not encodable in CP932: ' + ''.join(bad))
    if JP_RE.search(re.sub('[　-〿！-｠…―]', '', translated)):
        issues.append('still contains Japanese')
    lines = translated.split('\n')
    if width:
        for ln in lines:
            if text_width(ln, code_byte) > width:
                issues.append(f'line wider than {width} units: {ln[:30]!r}')
                break
    if max_lines and len(lines) > max_lines:
        issues.append(f'{len(lines)} lines (window fits {max_lines})')
    return issues


def _cp932_ok(c: str) -> bool:
    try:
        c.encode('cp932')
        return True
    except UnicodeEncodeError:
        return False


# =============================================================================
# init/*.xtx and init2/*.fxf configuration files
# =============================================================================
#
# The engine loads init2\\<name>.fxf (bytes XOR 0xFF) when an init2 folder
# exists, otherwise init\\<name>.xtx (plain CP932). Contents are whitespace
# separated "key value" tokens. Spaces inside a value are written as '?'.

def read_config_text(path: str) -> str:
    data = open(path, 'rb').read()
    if path.lower().endswith('.fxf'):
        data = bytes(b ^ 0xFF for b in data)
    return data.decode('cp932', errors='replace')


def write_config_text(path: str, text: str):
    data = text.encode('cp932')
    if path.lower().endswith('.fxf'):
        data = bytes(b ^ 0xFF for b in data)
    with open(path, 'wb') as f:
        f.write(data)


def parse_config(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith(('//', ';', '#')):
            continue
        toks = re.split(r'[\s,]+', s)
        if len(toks) >= 2:
            result.setdefault(toks[0], toks[1])
    return result


def set_config_value(text: str, key: str, value: str) -> str:
    value = value.replace(' ', '?')
    lines = text.splitlines()
    pat = re.compile(r'^(\s*)' + re.escape(key) + r'([\s,]+)\S*(.*)$')
    for i, line in enumerate(lines):
        m = pat.match(line)
        if m:
            lines[i] = f'{m.group(1)}{key}{m.group(2)}{value}{m.group(3)}'
            return '\r\n'.join(lines) + '\r\n'
    lines.append(f'{key} {value}')
    return '\r\n'.join(lines) + '\r\n'


# Keys that matter for translation patches (file, key, what it does)
TRANSLATION_KEYS = [
    ('game', 'codeByte', '1 = single-byte text mode: ASCII drawn half-width with an ANSI font '
                         '(default 2 = every character is a full-width cell)'),
    ('game', 'rightShift1Byte', 'x offset applied to single-byte glyphs (default 2)'),
    ('game', 'defaultFont', 'font face to use; write spaces as ?  (e.g. Segoe?UI)'),
    ('game', 'gothicFontName', 'replacement for "MS Gothic"'),
    ('game', 'minchoFontName', 'replacement for "MS Mincho"'),
    ('game', 'fontWeight', '0-1000, default 700'),
    ('game', 'useDirect2D', '1 = Direct2D renderer (needed by d2d1.dll font proxies like font_prop)'),
    ('game', 'locale', 'jp / en'),
    ('printmessage', 'fontSize', 'message font size'),
    ('printmessage', 'nextX', 'horizontal advance per character cell'),
    ('printmessage', 'nextY', 'line height'),
    ('printmessage', 'space', 'gap between characters'),
    ('printmessage', 'printX', 'message x'),
    ('printmessage', 'printY', 'message y'),
    ('printmessage', 'windowMessageNumber', 'characters per window line'),
    ('printmessage', 'nameX', 'name plate x'),
    ('printmessage', 'nameLengthMax', 'max name length (cells)'),
]


def find_config(game_dir: str, name: str) -> Optional[str]:
    for sub, ext in (('init2', '.fxf'), ('init', '.xtx')):
        p = os.path.join(game_dir, sub, name + ext)
        if os.path.exists(p):
            return p
    return None


# =============================================================================
# Game exe probe
# =============================================================================

PROBE_STRINGS = [
    'codeByte', 'rightShift1Byte', 'defaultFont', 'gothicFontName', 'minchoFontName',
    'useDirect2D', 'locale', 'fontWeight', 'rubiFlag', 'windowMessageNumber',
    'SPTHEADER', 'init2', 'project.xtx', 'charaname.xtx',
]
PROBE_IMPORTS = ['d2d1.dll', 'ddraw.dll', 'd3d9.dll', 'd3d11.dll', 'dsound.dll',
                 'xaudio2', 'gdi32.dll', 'TextOutA', 'TextOutW', 'CreateFontA',
                 'CreateFontIndirectA', 'DWriteCreateFactory']


def probe_exe(path: str) -> dict:
    data = open(path, 'rb').read()
    low = data.lower()
    found = {s: (s.encode() in data) for s in PROBE_STRINGS}
    imports = {s: (s.lower().encode() in low) for s in PROBE_IMPORTS}
    rec = []
    if found['codeByte']:
        rec.append('This build reads "codeByte": set `codeByte 1` in init/game.xtx to draw '
                   'English half-width (proper Latin letters instead of full-width cells). '
                   'Insert with --code-byte 1 so wrapping uses half-width units.')
    else:
        rec.append('No "codeByte" key: this build always uses full-width cells, so Latin '
                   'letters are spaced like Japanese. Options: (a) keep full-width layout and '
                   'wrap with --code-byte 2; (b) VNTextProxy (ddraw.dll/d3d9.dll/... proxy) '
                   'with --tunnel for custom glyphs and a custom font.')
    if found['useDirect2D'] or imports['d2d1.dll']:
        rec.append('Direct2D path present: the d2d1.dll proxy "font_prop" '
                   '(github.com/louisbui63/font_prop) can proportionalize the font.')
    if imports['ddraw.dll']:
        rec.append('Imports ddraw.dll: VNTextProxy built as ddraw.dll can be dropped next to the exe.')
    if imports['d3d9.dll']:
        rec.append('Imports d3d9.dll: VNTextProxy can also be built as d3d9.dll.')
    if found['defaultFont']:
        rec.append('Supports "defaultFont" in init/game.xtx (write spaces as ?).')
    return {'strings': found, 'imports': imports, 'recommendations': rec}


# =============================================================================
# Character names (spt/charaname.xtx)
# =============================================================================

def read_charaname(path: str) -> List[str]:
    text = read_config_text(path)
    names = []
    for line in text.splitlines():
        for tok in re.split(r'[\s,]+', line.strip()):
            if tok and JP_RE.search(tok) and tok not in names:
                names.append(tok)
    return names
