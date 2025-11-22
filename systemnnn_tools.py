#!/usr/bin/env python3
"""
SystemNNN/PIL/SLASH Visual Novel Tools
Supports DDP2/DDP3 archives, HXB/SPT/NNN script files, and LLM translation

Tools for:
- Extracting DDP2/DDP3 archives
- Parsing HXB scripts and extracting translatable text (UTF-16LE)
- Parsing SPT scripts (Shift-JIS, XOR 0xFF encrypted)
- Parsing NNN dev scripts (--MESSAGEDATA/-COMMANDDATA format)
- Translating text using LLM APIs (OpenAI, Anthropic, DeepL, local)
- Reinserting translated text into scripts
- Repacking DDP archives

Based on GARbro's format specifications and reverse engineering

Tested with: Shingakkou (神学校 -Noli me tangere-), Mugen Kairou 2
"""

import struct
import os
import sys
import json
import argparse
import time
import re
from pathlib import Path
from typing import List, Dict, Tuple, Optional, BinaryIO, Any
from dataclasses import dataclass, field


# =============================================================================
# Utility Functions
# =============================================================================

def read_uint32_le(data: bytes, offset: int) -> int:
    return struct.unpack_from('<I', data, offset)[0]

def read_uint32_be(data: bytes, offset: int) -> int:
    return struct.unpack_from('>I', data, offset)[0]

def read_uint16_le(data: bytes, offset: int) -> int:
    return struct.unpack_from('<H', data, offset)[0]

def write_uint32_le(value: int) -> bytes:
    return struct.pack('<I', value)

def write_uint32_be(value: int) -> bytes:
    return struct.pack('>I', value)


# =============================================================================
# SHS Compression (LZSS variant from GARbro)
# =============================================================================

def shs_decompress(data: bytes, unpacked_size: int) -> bytes:
    """
    ShsCompression decompression from GARbro.
    Custom LZSS variant used by SystemNNN/DDSystem.
    """
    result = bytearray(unpacked_size)
    src = 0
    dst = 0

    while dst < unpacked_size and src < len(data):
        ctl = data[src]
        src += 1

        if ctl < 32:  # Literal copy
            if ctl == 0x1D:
                if src >= len(data):
                    break
                count = data[src] + 0x1E
                src += 1
            elif ctl == 0x1E:
                if src + 1 >= len(data):
                    break
                count = (data[src] << 8 | data[src+1]) + 0x11E
                src += 2
            elif ctl == 0x1F:
                if src + 3 >= len(data):
                    break
                count = (data[src] << 24 | data[src+1] << 16 | data[src+2] << 8 | data[src+3])
                src += 4
            else:
                count = ctl + 1

            count = min(count, unpacked_size - dst)
            if src + count <= len(data):
                result[dst:dst+count] = data[src:src+count]
                src += count
            else:
                break
        else:  # Back-reference
            if (ctl & 0x80) == 0:
                if (ctl & 0x60) == 0x20:
                    offset = (ctl >> 2) & 7
                    count = ctl & 3
                else:
                    if src >= len(data):
                        break
                    offset = data[src]
                    src += 1
                    if (ctl & 0x60) == 0x40:
                        count = (ctl & 0x1F) + 4
                    else:
                        offset |= (ctl & 0x1F) << 8
                        if src >= len(data):
                            break
                        ctl2 = data[src]
                        src += 1
                        if ctl2 == 0xFE:
                            if src + 1 >= len(data):
                                break
                            count = (data[src] << 8 | data[src+1]) + 0x102
                            src += 2
                        elif ctl2 == 0xFF:
                            if src + 3 >= len(data):
                                break
                            count = (data[src] << 24 | data[src+1] << 16 | data[src+2] << 8 | data[src+3])
                            src += 4
                        else:
                            count = ctl2 + 4
            else:
                if src >= len(data):
                    break
                count = (ctl >> 5) & 3
                offset = ((ctl & 0x1F) << 8) | data[src]
                src += 1

            count += 3
            offset += 1
            count = min(count, unpacked_size - dst)

            # Copy with overlap handling
            for i in range(count):
                if dst - offset + i >= 0 and dst + i < unpacked_size:
                    result[dst + i] = result[dst - offset + i]
                elif dst + i < unpacked_size:
                    result[dst + i] = 0

        dst += count

    return bytes(result[:dst])


def shs_compress(data: bytes) -> bytes:
    """
    ShsCompression compression.
    Simple implementation - may not achieve optimal compression.
    """
    result = bytearray()
    src_pos = 0

    while src_pos < len(data):
        # Find the longest match in the sliding window
        best_offset = 0
        best_length = 0

        # Search window: up to 8191 bytes back (13-bit offset)
        window_start = max(0, src_pos - 8191)

        for search_pos in range(window_start, src_pos):
            length = 0
            max_len = min(258, len(data) - src_pos)  # Max length we can encode

            while length < max_len and data[search_pos + length] == data[src_pos + length]:
                length += 1
                if search_pos + length >= src_pos:
                    break

            if length >= 3 and length > best_length:
                best_length = length
                best_offset = src_pos - search_pos

        if best_length >= 3:
            # Encode back-reference
            offset = best_offset - 1
            count = best_length - 3

            if offset < 8 and count < 4:
                # Short format: 001ooocc
                ctl = 0x20 | ((offset & 7) << 2) | (count & 3)
                result.append(ctl)
            elif offset < 256 and count < 32:
                # Medium format with 1-byte offset
                ctl = 0x40 | (count & 0x1F)
                result.append(ctl)
                result.append(offset & 0xFF)
            else:
                # Long format with 13-bit offset
                if count < 252:
                    ctl = 0x60 | ((offset >> 8) & 0x1F)
                    result.append(ctl)
                    result.append(offset & 0xFF)
                    result.append(count)
                else:
                    # Very long count
                    ctl = 0x60 | ((offset >> 8) & 0x1F)
                    result.append(ctl)
                    result.append(offset & 0xFF)
                    result.append(0xFE)
                    count_val = count - 0x102 + 4
                    result.append((count_val >> 8) & 0xFF)
                    result.append(count_val & 0xFF)

            src_pos += best_length
        else:
            # Find a run of literals
            literal_start = src_pos
            literal_end = src_pos + 1

            while literal_end < len(data):
                # Check if we should switch to back-reference
                if literal_end - literal_start >= 30:  # Don't make literals too long
                    break

                # Quick check for possible match
                found_match = False
                window_start = max(0, literal_end - 8191)
                for search_pos in range(window_start, literal_end):
                    if (literal_end + 2 < len(data) and
                        data[search_pos:search_pos+3] == data[literal_end:literal_end+3]):
                        found_match = True
                        break

                if found_match:
                    break

                literal_end += 1

            # Encode literals
            count = literal_end - literal_start
            if count <= 0x1C:
                result.append(count - 1)
            elif count <= 0x1E + 0xFF:
                result.append(0x1D)
                result.append(count - 0x1E)
            else:
                result.append(0x1E)
                count_val = count - 0x11E
                result.append((count_val >> 8) & 0xFF)
                result.append(count_val & 0xFF)

            result.extend(data[literal_start:literal_end])
            src_pos = literal_end

    return bytes(result)


# =============================================================================
# HXB Script Encryption/Decryption
# =============================================================================

def fix_hxb_signature(data: bytes) -> bytes:
    """Convert DDWuHXB signature to DDSxHXB."""
    if len(data) >= 4 and data[:4] == b'DDWu':
        data = bytearray(data)
        data[2] = 0x53  # S
        data[3] = 0x78  # x
        return bytes(data)
    return data


def unfix_hxb_signature(data: bytes) -> bytes:
    """Convert DDSxHXB signature back to DDWuHXB for repacking."""
    if len(data) >= 4 and data[:4] == b'DDSx':
        data = bytearray(data)
        data[2] = 0x57  # W
        data[3] = 0x75  # u
        return bytes(data)
    return data


def decrypt_hxb(data: bytes) -> bytes:
    """Decrypt HXB script files."""
    if len(data) < 0x14 or data[:4] != b'DDSx' or data[4:7] != b'HXB':
        return data

    length = len(data)
    key = (((length << 5) ^ 0xA5) * (length + 0x6F349)) ^ 0x34A9B129
    key = key & 0xFFFFFFFF

    key_bytes = [
        key & 0xFF,
        (key >> 8) & 0xFF,
        (key >> 16) & 0xFF,
        (key >> 24) & 0xFF
    ]

    result = bytearray(data)
    for i in range(0x10, len(result)):
        result[i] ^= key_bytes[i & 3]

    return bytes(result)


def encrypt_hxb(data: bytes) -> bytes:
    """Encrypt HXB script files (same as decrypt - XOR is symmetric)."""
    return decrypt_hxb(data)


# =============================================================================
# DDP Archive Entry
# =============================================================================

@dataclass
class DDPEntry:
    """Represents a file entry in a DDP archive."""
    name: str
    offset: int
    unpacked_size: int
    packed_size: int
    is_packed: bool = False

    @property
    def size(self) -> int:
        return self.unpacked_size


# =============================================================================
# DDP Archive Reader
# =============================================================================

class DDPArchive:
    """Reader for DDP2/DDP3 archives."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.entries: List[DDPEntry] = []
        self.version = 0
        self._data: Optional[bytes] = None

    def open(self) -> bool:
        """Open and parse the archive."""
        with open(self.filepath, 'rb') as f:
            self._data = f.read()
        return self._parse_header()

    def _parse_header(self) -> bool:
        """Parse DDP header and file entries."""
        if not self._data or len(self._data) < 16:
            return False

        signature = self._data[:4]
        if signature == b'DDP2':
            self.version = 2
        elif signature == b'DDP3':
            self.version = 3
        else:
            print(f"Unknown signature: {signature}")
            return False

        header_size = read_uint32_le(self._data, 4)
        file_count = read_uint32_le(self._data, 8)

        if self.version == 3:
            self._parse_ddp3_entries(header_size, file_count)
        else:
            self._parse_ddp2_entries(header_size, file_count)

        return True

    def _parse_ddp2_entries(self, header_size: int, file_count: int):
        """Parse DDP2 format entries."""
        pos = header_size
        for i in range(file_count):
            if pos + 16 > len(self._data):
                break

            offset = read_uint32_le(self._data, pos)
            unpacked_size = read_uint32_le(self._data, pos + 4)
            packed_size = read_uint32_le(self._data, pos + 8)

            is_packed = packed_size != 0 and packed_size != unpacked_size

            self.entries.append(DDPEntry(
                name=f'file_{i:04d}',
                offset=offset,
                unpacked_size=unpacked_size,
                packed_size=packed_size if is_packed else unpacked_size,
                is_packed=is_packed
            ))
            pos += 16

    def _parse_ddp3_entries(self, header_size: int, data_offset: int):
        """Parse DDP3 format entries with UTF-16LE names.

        Note: The value at 0x08 in DDP3 is the data offset, not file count.
        We parse entries until we reach the data offset.
        """
        # DDP3 has an index section followed by file entries
        # Index at 0x20: pairs of (text_size, cumulative_offset) - auxiliary info
        # File entries start at 0x120 and continue until data_offset

        entries_start = 0x120  # Standard start position
        pos = entries_start
        i = 0

        while pos < data_offset and pos < len(self._data):
            entry_size = self._data[pos]

            # Skip null padding
            while entry_size == 0 and pos < len(self._data) - 1:
                pos += 1
                entry_size = self._data[pos]

            if entry_size < 17 or pos + entry_size > len(self._data):
                break

            # Stop if we've reached the data section
            if pos + entry_size > data_offset:
                break

            file_offset = read_uint32_le(self._data, pos + 1)
            unpacked_size = read_uint32_le(self._data, pos + 5)
            packed_size = read_uint32_le(self._data, pos + 9)

            # Read UTF-16LE name starting at pos + 17
            name_data = self._data[pos + 17:pos + entry_size]
            try:
                null_pos = name_data.find(b'\x00\x00')
                if null_pos >= 0 and null_pos % 2 == 0:
                    name = name_data[:null_pos].decode('utf-16-le', errors='replace')
                else:
                    name = name_data.decode('utf-16-le', errors='replace').rstrip('\x00')
            except:
                name = f'file_{i:04d}'

            # Clean up name
            name = name.replace('\x00', '').strip()
            if not name:
                name = f'file_{i:04d}'

            is_packed = packed_size != 0 and packed_size != unpacked_size

            self.entries.append(DDPEntry(
                name=name,
                offset=file_offset,
                unpacked_size=unpacked_size,
                packed_size=packed_size if is_packed else unpacked_size,
                is_packed=is_packed
            ))

            pos += entry_size
            i += 1

    def extract_entry(self, entry: DDPEntry, decrypt: bool = True) -> bytes:
        """Extract and decompress a single entry."""
        if not self._data:
            raise RuntimeError("Archive not opened")

        file_data = self._data[entry.offset:entry.offset + entry.packed_size]

        # Decompress if packed
        if entry.is_packed and entry.packed_size != entry.unpacked_size:
            try:
                file_data = shs_decompress(file_data, entry.unpacked_size)
            except Exception as e:
                print(f"Warning: Decompression failed for {entry.name}: {e}")

        # Fix signature (DDWuHXB -> DDSxHXB)
        file_data = fix_hxb_signature(file_data)

        # Decrypt HXB if needed
        if decrypt and len(file_data) >= 7 and file_data[:4] == b'DDSx':
            file_data = decrypt_hxb(file_data)

        return file_data

    def extract_all(self, output_dir: str, decrypt: bool = True, progress_callback=None):
        """Extract all files to output directory."""
        os.makedirs(output_dir, exist_ok=True)

        for i, entry in enumerate(self.entries):
            try:
                file_data = self.extract_entry(entry, decrypt)

                # Determine extension
                ext = self._detect_extension(file_data)

                # Sanitize filename
                safe_name = entry.name.replace('/', '_').replace('\\', '_').replace(':', '_')
                outpath = os.path.join(output_dir, safe_name + ext)

                with open(outpath, 'wb') as out:
                    out.write(file_data)

                if progress_callback:
                    progress_callback(i + 1, len(self.entries), entry.name)

            except Exception as e:
                print(f"Error extracting {entry.name}: {e}")

    def _detect_extension(self, data: bytes) -> str:
        """Detect file extension from magic bytes."""
        if len(data) < 4:
            return ''

        magic = data[:4]
        if magic == b'DDSx':
            return '.hxb'
        elif magic == b'OggS':
            return '.ogg'
        elif magic == b'RIFF':
            return '.wav'
        elif magic == b'\x89PNG':
            return '.png'
        elif magic[:2] == b'BM':
            return '.bmp'
        return ''


# =============================================================================
# SPT Script Encryption/Decryption (Mugen Kairou 2, etc.)
# =============================================================================

def spt_decrypt(data: bytes) -> bytes:
    """Decrypt SPT script files (XOR 0xFF)."""
    return bytes(b ^ 0xFF for b in data)


def spt_encrypt(data: bytes) -> bytes:
    """Encrypt SPT script files (XOR 0xFF - same as decrypt)."""
    return spt_decrypt(data)


def is_spt_file(data: bytes) -> bool:
    """Check if data is an SPT script file."""
    if len(data) < 0x40:
        return False
    decrypted = spt_decrypt(data[0x30:0x40])
    return decrypted.startswith(b'SPTHEADER')


# =============================================================================
# SPT Script Parser
# =============================================================================

@dataclass
class SPTString:
    """Represents an extractable text string from SPT script."""
    index: int
    offset: int
    original: str
    translated: str = ""
    context: str = ""


class SPTScript:
    """
    Parser for SPT script files (Mugen Kairou 2, etc.).
    XOR 0xFF encrypted, Shift-JIS text encoding.
    """

    def __init__(self):
        self.strings: List[SPTString] = []
        self.raw_data: bytes = b''
        self.decrypted_data: bytes = b''

    def parse(self, data: bytes) -> bool:
        """Parse SPT script and extract text strings."""
        self.raw_data = data
        self.decrypted_data = spt_decrypt(data)

        # Check signature
        if len(self.decrypted_data) < 0x40:
            return False

        signature = self.decrypted_data[0x30:0x3A]
        if not signature.startswith(b'SPTHEADER'):
            print(f"Not a valid SPT file (got: {signature})")
            return False

        # Extract Shift-JIS strings
        self._extract_shiftjis_strings()
        return True

    def _extract_shiftjis_strings(self):
        """Extract Shift-JIS encoded text strings.

        SPT format has text strings that are null-terminated.
        After null byte, there's typically a 1-byte control/command code before the text.
        Pattern: 00 <control_byte> <actual_text> 00

        Control bytes can be in ranges 0x40-0x7F (ASCII) or 0xA0-0xFF (half-width katakana range).
        Real text starts with 0x81-0x9F (Shift-JIS symbols/hiragana/katakana/kanji).
        """
        data = self.decrypted_data
        i = 0x1000  # Skip header/code area
        idx = 0

        while i < len(data) - 2:
            # Look for null byte followed by text
            if data[i] == 0:
                j = i + 1

                # Skip consecutive nulls
                while j < len(data) and data[j] == 0:
                    j += 1

                if j >= len(data):
                    break

                # Skip control byte(s) until we find a valid text start
                # Valid text usually starts with:
                # - 0x8140 (full-width space)
                # - 0x8167 (")  0x8175 (「) - quotes
                # - 0x834X (katakana ク, ケ, etc. for names)
                # - 0x89XX-0x9FXX (kanji)
                # Control bytes can be ANY byte including valid Shift-JIS first bytes
                max_skip = 6
                while j < len(data) - 1 and data[j] != 0 and j - i <= max_skip:
                    b = data[j]
                    b2 = data[j + 1] if j + 1 < len(data) else 0

                    # Definitely valid text starts:
                    # Full-width space (81 40)
                    if b == 0x81 and b2 == 0x40:
                        break
                    # Opening quotes/brackets (81 67=", 81 75=「, 81 77=『)
                    if b == 0x81 and b2 in [0x67, 0x68, 0x75, 0x77]:
                        break
                    # Kanji (88-9F as first byte, almost always real text)
                    if 0x88 <= b <= 0x9F:
                        break
                    # Common katakana names (83 4X-5X range: ク, ケ, コ, etc.)
                    if b == 0x83 and 0x4E <= b2 <= 0x96:  # Common katakana
                        break
                    # Hiragana (82 9F-F1: あ-ん)
                    if b == 0x82 and 0x9F <= b2 <= 0xF1:
                        break

                    # Skip this byte pair if it's Shift-JIS (likely control)
                    if 0x81 <= b <= 0x9F or 0xE0 <= b <= 0xEF:
                        j += 2
                    else:
                        j += 1

                if j < len(data) - 1 and (0x81 <= data[j] <= 0x9F or 0xE0 <= data[j] <= 0xEF):
                    start = j
                    end = j

                    # Read continuous text
                    while end < len(data):
                        b = data[end]
                        if b == 0:
                            break
                        # Shift-JIS multi-byte (0x81-0x9F, 0xE0-0xEF are first bytes)
                        if 0x81 <= b <= 0x9F or 0xE0 <= b <= 0xEF:
                            if end + 1 < len(data):
                                end += 2
                            else:
                                break
                        # ASCII printable + newlines
                        elif 0x20 <= b <= 0x7E or b in [0x0A, 0x0D]:
                            end += 1
                        # Half-width katakana (only within text, not as control)
                        elif 0xA1 <= b <= 0xDF:
                            end += 1
                        else:
                            break

                    if end > start + 4:
                        try:
                            text = data[start:end].decode('shift-jis', errors='strict')
                            # Must contain actual Japanese text (hiragana/katakana/kanji)
                            has_japanese = any(
                                0x3040 <= ord(c) <= 0x30FF or  # Hiragana/Katakana
                                0x4E00 <= ord(c) <= 0x9FFF     # Kanji
                                for c in text
                            )
                            if len(text) >= 2 and has_japanese:
                                # Clean up: remove garbage prefix characters
                                # These are control codes that got decoded as text
                                text = self._clean_text_prefix(text)
                                if text and len(text) >= 2:
                                    self.strings.append(SPTString(
                                        index=idx,
                                        offset=start,
                                        original=text
                                    ))
                                    idx += 1
                                i = end
                                continue
                        except:
                            pass
            i += 1

    def _clean_text_prefix(self, text: str) -> str:
        """Remove garbage control code prefixes from text.

        SPT files have control bytes before text that can decode as valid
        but meaningless Shift-JIS characters. We need to find the actual
        text start.
        """
        import re

        # For dialogue lines (name + newline + bracket), find the actual name
        # Pattern: <garbage><name>\n「<dialogue>
        # Common names: 奥様, クラスメイト, "たろ", "しろ", ハナ, etc.

        # Check for dialogue pattern
        if '\n「' in text or '\n『' in text:
            # Find the bracket position
            bracket_match = re.search(r'\n[「『]', text)
            if bracket_match:
                before_bracket = text[:bracket_match.start()]
                after_bracket = text[bracket_match.start():]

                # Clean up the name part (before bracket)
                # Look for known character name patterns
                name_patterns = [
                    r'(奥様)',
                    r'(クラスメイト[ＡＢＣ]?)',
                    r'("たろ")',
                    r'("しろ")',
                    r'(奈菜香)',
                    r'(百合絵)',
                    r'(祐美子)',
                    r'(薫子)',
                    r'(ハナ)',
                    r'(グモルク)',
                    r'(女の子[ＡＢ]?)',
                    r'(通行人[ＡＢＣＤＥＦＧ]?)',
                    r'(アナウンス)',
                ]

                for pattern in name_patterns:
                    match = re.search(pattern, before_bracket)
                    if match:
                        # Return name + bracket + dialogue
                        return match.group(1) + after_bracket

                # If no known name, try to find katakana word at the end
                kata_match = re.search(r'([ァ-ヶー]+[ＡＢＣ]?)$', before_bracket)
                if kata_match:
                    name = kata_match.group(1)
                    # Fix common truncations
                    if name == 'ラスメイトＡ' or name == 'ラスメイト':
                        name = 'クラスメイトＡ'
                    return name + after_bracket

                # Try to find quoted name pattern at the end
                quote_match = re.search(r'("[\w]+")$', before_bracket)
                if quote_match:
                    return quote_match.group(1) + after_bracket

                # Try partial quote at end
                partial_quote = re.search(r'([\w]+")\s*$', before_bracket)
                if partial_quote:
                    name = '"' + partial_quote.group(1)
                    return name + after_bracket

                # If no match, try to clean leading garbage
                cleaned = self._clean_leading_garbage(before_bracket)
                return cleaned + after_bracket

        # For non-dialogue lines, just clean leading garbage
        return self._clean_leading_garbage(text)

    def _clean_leading_garbage(self, text: str) -> str:
        """Remove garbage characters from the start of text."""
        # Known garbage patterns (control codes that decode as text)
        garbage_patterns = [
            'ブャN', 'ｃN', '泣N', '轤ﾈ', '焉@', 'ﾈた', 'ｳ゛', '黶@',
            '諱', '轣', '驍', '齦', '齬', '謔', '閧', '黷',  # Common garbage kanji
            '＝@', 'た　', 'し　', 'ぁ　', 'い　', 'に　', 'か　', 'は　',  # Single kana + space
        ]
        for pattern in garbage_patterns:
            if text.startswith(pattern):
                text = text[len(pattern):]

        # Fix known truncated patterns
        if text.startswith('ラスメイトＡ'):
            text = 'ク' + text
        if text.startswith('ラスメイト\n'):
            text = 'ク' + text
        if text.startswith('たろ"'):
            text = '"' + text

        while text:
            c = text[0]
            code = ord(c)

            # Keep: full-width space, quotes, brackets, normal punctuation after text
            if c in '　 "「『（【':
                break

            # Keep: kanji
            if 0x4E00 <= code <= 0x9FFF:
                break

            # Keep: hiragana if followed by more text (part of a word)
            if 0x3041 <= code <= 0x3096:  # Hiragana
                if len(text) > 1:
                    next_c = ord(text[1])
                    # If followed by more Japanese text, keep it
                    if (0x3040 <= next_c <= 0x30FF or
                        0x4E00 <= next_c <= 0x9FFF or
                        next_c == 0x3000):  # Full-width space
                        break
                    # Single hiragana followed by space might be valid
                    if text[1] in '　 ':
                        # Check if it's common patterns like "が　" "は　" etc.
                        if c in 'がはもをにでとへや':
                            break
                # Remove isolated hiragana
                text = text[1:]
                continue

            # Keep: katakana word (2+ consecutive katakana)
            if 0x30A0 <= code <= 0x30FF:  # Katakana
                if len(text) > 1 and 0x30A0 <= ord(text[1]) <= 0x30FF:
                    break
                # Single katakana is garbage
                text = text[1:]
                continue

            # Skip: punctuation at start
            if c in '、。？！…―゛゜':
                text = text[1:]
                continue

            # Skip: small kana (usually garbage when alone)
            if c in 'ぁぃぅぇぉっゃゅょゎァィゥェォッャュョヮ':
                text = text[1:]
                continue

            # Skip: half-width katakana
            if 0xFF61 <= code <= 0xFF9F:
                text = text[1:]
                continue

            # Skip: ASCII letters alone (control codes)
            if 0x41 <= code <= 0x5A or 0x61 <= code <= 0x7A:
                if len(text) > 1 and ord(text[1]) >= 0x80:
                    # ASCII followed by Japanese = control byte
                    text = text[1:]
                    continue
                break

            # Default: keep
            break

        return text

    def export_strings(self, filepath: str):
        """Export strings to JSON for translation."""
        export_data = {
            'source_file': '',
            'format': 'spt-shiftjis',
            'string_count': len(self.strings),
            'strings': [
                {
                    'index': s.index,
                    'offset': s.offset,
                    'original': s.original,
                    'translated': s.translated,
                    'context': s.context
                }
                for s in self.strings
            ]
        }

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)

    def import_strings(self, filepath: str):
        """Import translated strings from JSON."""
        with open(filepath, 'r', encoding='utf-8') as f:
            import_data = json.load(f)

        translation_map = {
            s['index']: s.get('translated', '')
            for s in import_data.get('strings', [])
        }

        for string in self.strings:
            if string.index in translation_map:
                string.translated = translation_map[string.index]

    def rebuild(self) -> bytes:
        """Rebuild SPT file with translated strings."""
        result = bytearray(self.decrypted_data)

        # Sort strings by offset in reverse to avoid shifting issues
        sorted_strings = sorted(self.strings, key=lambda s: s.offset, reverse=True)

        for string in sorted_strings:
            if not string.translated:
                continue

            # Find original string end (null terminator)
            orig_end = string.offset
            while orig_end < len(result) and result[orig_end] != 0:
                orig_end += 1

            # Encode new string
            try:
                new_bytes = string.translated.encode('shift-jis')
            except UnicodeEncodeError:
                print(f"Warning: Could not encode string at index {string.index}")
                continue

            # Replace
            result[string.offset:orig_end] = new_bytes

        # Re-encrypt
        return spt_encrypt(bytes(result))


# =============================================================================
# HXB Text String
# =============================================================================

@dataclass
class HXBString:
    """Represents an extractable text string from HXB script."""
    index: int
    offset: int
    original: str
    translated: str = ""
    context: str = ""


# =============================================================================
# HXB Script Parser
# =============================================================================

class HXBScript:
    """
    Parser for HXB script files (DDSxHXB format).
    Text strings are stored in UTF-16LE encoding.
    """

    def __init__(self):
        self.strings: List[HXBString] = []
        self.raw_data: bytes = b''
        self.is_encrypted: bool = False

    @staticmethod
    def is_japanese_char(code: int) -> bool:
        """Check if Unicode code point is a Japanese/printable character."""
        return (0x3040 <= code <= 0x309F or   # Hiragana
                0x30A0 <= code <= 0x30FF or   # Katakana
                0x4E00 <= code <= 0x9FFF or   # CJK Ideographs
                0x3000 <= code <= 0x303F or   # CJK Punctuation
                0x0020 <= code <= 0x007E or   # ASCII printable
                0xFF01 <= code <= 0xFF5E or   # Fullwidth
                0x2000 <= code <= 0x206F or   # General punctuation
                code == 0x000A or             # Newline
                code == 0x000D)               # Carriage return

    def parse(self, data: bytes) -> bool:
        """Parse HXB script and extract text strings."""
        self.raw_data = data

        # Check signature
        if len(data) < 0x10:
            return False

        if data[:4] != b'DDSx' or data[4:7] != b'HXB':
            print("Not a valid DDSxHXB file")
            return False

        # Extract UTF-16LE strings
        self._extract_utf16le_strings()

        return True

    def _extract_utf16le_strings(self):
        """Extract UTF-16LE encoded text strings."""
        data = self.raw_data
        i = 0x10  # Skip header
        idx = 0

        while i < len(data) - 1:
            code = data[i] | (data[i+1] << 8)

            if self.is_japanese_char(code):
                start = i
                chars = []

                while i < len(data) - 1:
                    code = data[i] | (data[i+1] << 8)
                    if code == 0:  # Null terminator
                        i += 2
                        break
                    if self.is_japanese_char(code):
                        chars.append(chr(code))
                        i += 2
                    else:
                        break

                if len(chars) >= 3:  # Minimum 3 characters
                    text = ''.join(chars)
                    self.strings.append(HXBString(
                        index=idx,
                        offset=start,
                        original=text
                    ))
                    idx += 1
            else:
                i += 1

    def export_strings(self, filepath: str):
        """Export strings to JSON for translation."""
        export_data = {
            'source_file': '',
            'format': 'utf-16le',
            'string_count': len(self.strings),
            'strings': [
                {
                    'index': s.index,
                    'offset': s.offset,
                    'original': s.original,
                    'translated': s.translated,
                    'context': s.context
                }
                for s in self.strings
            ]
        }

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)

    def import_strings(self, filepath: str):
        """Import translated strings from JSON."""
        with open(filepath, 'r', encoding='utf-8') as f:
            import_data = json.load(f)

        translation_map = {
            s['index']: s.get('translated', '')
            for s in import_data.get('strings', [])
        }

        for string in self.strings:
            if string.index in translation_map:
                string.translated = translation_map[string.index]

    def rebuild(self) -> bytes:
        """Rebuild HXB file with translated strings."""
        result = bytearray(self.raw_data)

        # Sort strings by offset in reverse to avoid shifting issues
        sorted_strings = sorted(self.strings, key=lambda s: s.offset, reverse=True)

        for string in sorted_strings:
            if not string.translated:
                continue

            # Find original string length in bytes
            orig_end = string.offset
            while orig_end < len(result) - 1:
                code = result[orig_end] | (result[orig_end+1] << 8)
                if code == 0:
                    break
                orig_end += 2

            # Encode new string
            try:
                new_bytes = string.translated.encode('utf-16-le')
            except UnicodeEncodeError:
                print(f"Warning: Could not encode string at index {string.index}")
                continue

            # Replace (keeping the null terminator)
            result[string.offset:orig_end] = new_bytes

        return bytes(result)


# =============================================================================
# DDP Archive Writer
# =============================================================================

class DDPWriter:
    """Writer for DDP3 archives."""

    def __init__(self, version: int = 3):
        self.version = version
        self.entries: List[Tuple[str, bytes]] = []

    def add_file(self, name: str, data: bytes):
        """Add a file to the archive."""
        self.entries.append((name, data))

    def write(self, filepath: str, compress: bool = False):
        """Write the archive to disk."""
        with open(filepath, 'wb') as f:
            if self.version == 3:
                self._write_ddp3(f, compress)
            else:
                self._write_ddp2(f, compress)

    def _write_ddp3(self, f: BinaryIO, compress: bool):
        """Write DDP3 format archive."""
        file_count = len(self.entries)
        header_size = 0x20

        # Calculate entry section size
        entry_sizes = []
        for name, data in self.entries:
            name_bytes = name.encode('utf-16-le')
            entry_size = 1 + 4 + 4 + 4 + 4 + len(name_bytes) + 2  # +2 for null terminator
            entry_sizes.append(entry_size)

        # Index section (32 entries of 8 bytes each)
        index_size = 32 * 8
        entries_start = header_size + index_size
        entries_size = sum(entry_sizes)
        data_start = entries_start + entries_size

        # Align to 16 bytes
        data_start = (data_start + 15) & ~15

        # Process files
        processed = []
        current_offset = data_start

        for name, data in self.entries:
            # Encrypt HXB files
            if len(data) >= 4 and data[:4] == b'DDSx':
                data = encrypt_hxb(data)
                data = unfix_hxb_signature(data)

            # Optionally compress
            packed_data = data
            if compress:
                packed_data = shs_compress(data)
                if len(packed_data) >= len(data):
                    packed_data = data

            processed.append({
                'name': name,
                'data': packed_data,
                'offset': current_offset,
                'unpacked_size': len(data),
                'packed_size': len(packed_data)
            })

            current_offset += len(packed_data)

        # Write header
        f.write(b'DDP3')
        f.write(write_uint32_le(header_size))
        f.write(write_uint32_le(file_count))
        f.write(b'\x00' * (header_size - 12))

        # Write index (placeholder - simple cumulative offsets)
        cumulative = entries_start
        for i, entry_size in enumerate(entry_sizes[:32]):
            f.write(write_uint32_le(entry_size))
            f.write(write_uint32_le(cumulative))
            cumulative += entry_size

        # Pad index to 32 entries
        for i in range(len(entry_sizes), 32):
            f.write(write_uint32_le(0))
            f.write(write_uint32_le(cumulative))

        # Write file entries
        for i, pd in enumerate(processed):
            name_bytes = pd['name'].encode('utf-16-le') + b'\x00\x00'
            entry_size = 1 + 4 + 4 + 4 + 4 + len(name_bytes)

            f.write(bytes([entry_size]))
            f.write(write_uint32_le(pd['offset']))
            f.write(write_uint32_le(pd['unpacked_size']))
            f.write(write_uint32_le(pd['packed_size']))
            f.write(b'\x00\x00\x00\x00')  # Padding
            f.write(name_bytes)

        # Pad to data start
        current_pos = f.tell()
        if current_pos < data_start:
            f.write(b'\x00' * (data_start - current_pos))

        # Write file data
        for pd in processed:
            f.write(pd['data'])

    def _write_ddp2(self, f: BinaryIO, compress: bool):
        """Write DDP2 format archive."""
        file_count = len(self.entries)
        header_size = 0x20
        index_size = file_count * 16
        data_start = header_size + index_size
        data_start = (data_start + 15) & ~15

        processed = []
        current_offset = data_start

        for name, data in self.entries:
            if len(data) >= 4 and data[:4] == b'DDSx':
                data = encrypt_hxb(data)
                data = unfix_hxb_signature(data)

            packed_data = data
            if compress:
                packed_data = shs_compress(data)
                if len(packed_data) >= len(data):
                    packed_data = data

            processed.append({
                'data': packed_data,
                'offset': current_offset,
                'unpacked_size': len(data),
                'packed_size': len(packed_data)
            })

            current_offset += len(packed_data)

        # Write header
        f.write(b'DDP2')
        f.write(write_uint32_le(header_size))
        f.write(write_uint32_le(file_count))
        f.write(b'\x00' * (header_size - 12))

        # Write index
        for pd in processed:
            f.write(write_uint32_le(pd['offset']))
            f.write(write_uint32_le(pd['unpacked_size']))
            f.write(write_uint32_le(pd['packed_size']))
            f.write(b'\x00\x00\x00\x00')

        # Pad
        current_pos = f.tell()
        if current_pos < data_start:
            f.write(b'\x00' * (data_start - current_pos))

        # Write data
        for pd in processed:
            f.write(pd['data'])


# =============================================================================
# High-Level Workflow Functions
# =============================================================================

def extract_archive(archive_path: str, output_dir: str, decrypt: bool = True) -> bool:
    """Extract all files from a DDP archive."""
    print(f"Opening archive: {archive_path}")

    archive = DDPArchive(archive_path)
    if not archive.open():
        print("Failed to open archive")
        return False

    print(f"Format: DDP{archive.version}")
    print(f"Files: {len(archive.entries)}")

    def progress(current, total, name):
        if current % 100 == 0 or current == total:
            print(f"  Extracted {current}/{total}: {name}")

    archive.extract_all(output_dir, decrypt, progress)
    print(f"Done! Files extracted to: {output_dir}")
    return True


def extract_text(script_path: str, output_path: str) -> bool:
    """Extract translatable text from an HXB or SPT script (auto-detect)."""
    print(f"Parsing script: {script_path}")

    with open(script_path, 'rb') as f:
        data = f.read()

    # Auto-detect format
    if is_spt_file(data):
        print("Detected: SPT format (Shift-JIS)")
        script = SPTScript()
    elif len(data) >= 7 and (data[:4] == b'DDSx' or data[:4] == b'DDWu'):
        print("Detected: HXB format (UTF-16LE)")
        if data[:4] == b'DDWu':
            data = fix_hxb_signature(data)
            data = decrypt_hxb(data)
        script = HXBScript()
    else:
        print("Unknown script format")
        return False

    if not script.parse(data):
        print("Failed to parse script")
        return False

    print(f"Found {len(script.strings)} text strings")
    script.export_strings(output_path)
    print(f"Exported to: {output_path}")
    return True


def extract_all_text(input_dir: str, output_dir: str) -> bool:
    """Extract text from all HXB and SPT scripts in a directory."""
    os.makedirs(output_dir, exist_ok=True)

    # Find both HXB and SPT files
    hxb_files = list(Path(input_dir).glob('*.hxb'))
    spt_files = list(Path(input_dir).glob('*.spt'))
    all_files = hxb_files + spt_files

    print(f"Found {len(hxb_files)} HXB and {len(spt_files)} SPT script files")

    total_strings = 0
    for script_path in all_files:
        json_path = Path(output_dir) / (script_path.stem + '.json')

        with open(script_path, 'rb') as f:
            data = f.read()

        # Auto-detect format
        if is_spt_file(data):
            script = SPTScript()
        else:
            if data[:4] == b'DDWu':
                data = fix_hxb_signature(data)
                data = decrypt_hxb(data)
            script = HXBScript()

        if script.parse(data):
            script.export_strings(str(json_path))
            total_strings += len(script.strings)
            print(f"  {script_path.name}: {len(script.strings)} strings")

    print(f"\nTotal: {total_strings} strings extracted")
    return True


def insert_text(script_path: str, translation_path: str, output_path: str) -> bool:
    """Insert translated text back into an HXB or SPT script (auto-detect)."""
    print(f"Loading script: {script_path}")

    with open(script_path, 'rb') as f:
        data = f.read()

    # Auto-detect format
    if is_spt_file(data):
        print("Detected: SPT format")
        script = SPTScript()
    elif len(data) >= 7 and (data[:4] == b'DDSx' or data[:4] == b'DDWu'):
        print("Detected: HXB format")
        if data[:4] == b'DDWu':
            data = fix_hxb_signature(data)
            data = decrypt_hxb(data)
        script = HXBScript()
    else:
        print("Unknown script format")
        return False

    if not script.parse(data):
        print("Failed to parse script")
        return False

    print(f"Importing translations from: {translation_path}")
    script.import_strings(translation_path)

    # Count translated strings
    translated_count = sum(1 for s in script.strings if s.translated)
    print(f"Applying {translated_count} translations...")

    new_data = script.rebuild()

    with open(output_path, 'wb') as f:
        f.write(new_data)

    print(f"Wrote patched script to: {output_path}")
    return True


def repack_archive(input_dir: str, output_path: str, version: int = 3, compress: bool = False) -> bool:
    """Repack files into a DDP archive."""
    print(f"Repacking directory: {input_dir}")

    writer = DDPWriter(version)

    files = sorted(Path(input_dir).iterdir())
    files = [f for f in files if f.is_file() and not f.name.endswith('.json')]

    print(f"Found {len(files)} files")

    for filepath in files:
        with open(filepath, 'rb') as f:
            data = f.read()
        writer.add_file(filepath.stem, data)

    writer.write(output_path, compress)
    print(f"Wrote archive to: {output_path}")
    return True


# =============================================================================
# NNN Dev Script Parser (VNTranslationTools compatible)
# =============================================================================

@dataclass
class NNNString:
    """Represents an extractable text string from NNN dev script."""
    index: int
    offset: int
    original: str
    translated: str = ""
    context: str = ""
    message_type: str = "message"  # "message" or "command"


class NNNScript:
    """
    Parser for NNN dev script files.
    Uses --MESSAGEDATA and -COMMANDDATA headers.
    Text is Shift-JIS encoded.
    """

    MESSAGEDATA_HEADER = b'--MESSAGEDATA  \x00'
    COMMANDDATA_HEADER = b'-COMMANDDATA   \x00'

    def __init__(self):
        self.strings: List[NNNString] = []
        self.raw_data: bytes = b''

    def parse(self, data: bytes) -> bool:
        """Parse NNN dev script and extract text strings."""
        self.raw_data = data
        idx = 0

        # Find MESSAGEDATA sections
        pos = 0
        while True:
            msg_pos = data.find(self.MESSAGEDATA_HEADER, pos)
            if msg_pos == -1:
                break

            # Read message data structure
            # At offset +0x50: buffer offset, +0x3C: length
            if msg_pos + 0x60 < len(data):
                try:
                    buffer_offset = read_uint32_le(data, msg_pos + 0x50)
                    text_length = read_uint32_le(data, msg_pos + 0x3C)

                    if buffer_offset > 0 and text_length > 0 and buffer_offset + text_length <= len(data):
                        text_data = data[buffer_offset:buffer_offset + text_length]
                        # Remove null terminator
                        text_data = text_data.rstrip(b'\x00')

                        try:
                            text = text_data.decode('shift-jis', errors='replace')
                            if text and len(text) >= 2:
                                self.strings.append(NNNString(
                                    index=idx,
                                    offset=buffer_offset,
                                    original=text,
                                    message_type="message"
                                ))
                                idx += 1
                        except:
                            pass
                except:
                    pass

            pos = msg_pos + len(self.MESSAGEDATA_HEADER)

        # Find COMMANDDATA sections (for choices, etc.)
        pos = 0
        while True:
            cmd_pos = data.find(self.COMMANDDATA_HEADER, pos)
            if cmd_pos == -1:
                break

            # Check for "Case" type commands at +0x60, length at +0x24
            if cmd_pos + 0x70 < len(data):
                try:
                    text_offset = cmd_pos + 0x60
                    text_length = read_uint32_le(data, cmd_pos + 0x24)

                    if text_length > 0 and text_offset + text_length <= len(data):
                        text_data = data[text_offset:text_offset + text_length]
                        text_data = text_data.rstrip(b'\x00')

                        try:
                            text = text_data.decode('shift-jis', errors='replace')
                            if text and len(text) >= 2:
                                self.strings.append(NNNString(
                                    index=idx,
                                    offset=text_offset,
                                    original=text,
                                    message_type="command"
                                ))
                                idx += 1
                        except:
                            pass
                except:
                    pass

            pos = cmd_pos + len(self.COMMANDDATA_HEADER)

        return len(self.strings) > 0

    def export_strings(self, filepath: str, format: str = "vntools"):
        """Export strings to JSON for translation.

        Args:
            filepath: Output file path
            format: "vntools" (default) or "vnt" (VNTranslationTools compatible)
        """
        if format == "vnt":
            # VNTranslationTools format: [{"name": "...", "message": "..."}]
            export_data = []
            for s in self.strings:
                # Try to split name and message if there's a newline
                if '\n' in s.original:
                    parts = s.original.split('\n', 1)
                    export_data.append({
                        "name": parts[0].strip(),
                        "message": parts[1].strip() if len(parts) > 1 else ""
                    })
                else:
                    export_data.append({"message": s.original})
        else:
            # VNTools format
            export_data = {
                'source_file': '',
                'format': 'nnn-shiftjis',
                'string_count': len(self.strings),
                'strings': [
                    {
                        'index': s.index,
                        'offset': s.offset,
                        'original': s.original,
                        'translated': s.translated,
                        'context': s.context,
                        'type': s.message_type
                    }
                    for s in self.strings
                ]
            }

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)

    def import_strings(self, filepath: str):
        """Import translated strings from JSON."""
        with open(filepath, 'r', encoding='utf-8') as f:
            import_data = json.load(f)

        # Handle both VNTools and VNT formats
        if isinstance(import_data, list):
            # VNT format
            for i, item in enumerate(import_data):
                if i < len(self.strings):
                    translated = item.get('translated', item.get('message', ''))
                    if translated:
                        self.strings[i].translated = translated
        else:
            # VNTools format
            translation_map = {
                s['index']: s.get('translated', '')
                for s in import_data.get('strings', [])
            }
            for string in self.strings:
                if string.index in translation_map:
                    string.translated = translation_map[string.index]

    def rebuild(self) -> bytes:
        """Rebuild NNN file with translated strings."""
        result = bytearray(self.raw_data)

        sorted_strings = sorted(self.strings, key=lambda s: s.offset, reverse=True)

        for string in sorted_strings:
            if not string.translated:
                continue

            # Find original string end
            orig_end = string.offset
            while orig_end < len(result) and result[orig_end] != 0:
                orig_end += 1

            try:
                new_bytes = string.translated.encode('shift-jis')
            except UnicodeEncodeError:
                print(f"Warning: Could not encode string at index {string.index}")
                continue

            result[string.offset:orig_end] = new_bytes

        return bytes(result)


def is_nnn_file(data: bytes) -> bool:
    """Check if data is an NNN dev script file."""
    return (b'--MESSAGEDATA' in data[:0x1000] or
            b'-COMMANDDATA' in data[:0x1000])


# =============================================================================
# LLM Translation Engine
# =============================================================================

class TranslationCache:
    """Simple cache to avoid re-translating identical strings."""

    def __init__(self, cache_file: Optional[str] = None):
        self.cache: Dict[str, str] = {}
        self.cache_file = cache_file
        if cache_file and os.path.exists(cache_file):
            self._load()

    def _load(self):
        try:
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                self.cache = json.load(f)
        except:
            self.cache = {}

    def save(self):
        if self.cache_file:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=2)

    def get(self, text: str) -> Optional[str]:
        return self.cache.get(text)

    def set(self, original: str, translated: str):
        self.cache[original] = translated


class LLMTranslator:
    """Base class for LLM-based translation."""

    def __init__(self,
                 api_key: Optional[str] = None,
                 model: str = "",
                 base_url: Optional[str] = None,
                 target_lang: str = "English",
                 context: str = ""):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url
        self.target_lang = target_lang
        self.context = context
        self.cache = TranslationCache()

    def translate_batch(self, texts: List[str], batch_size: int = 10) -> List[str]:
        """Translate a batch of texts."""
        results = []

        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            batch_results = []

            for text in batch:
                # Check cache first
                cached = self.cache.get(text)
                if cached:
                    batch_results.append(cached)
                    continue

                # Translate
                try:
                    translated = self._translate_single(text)
                    self.cache.set(text, translated)
                    batch_results.append(translated)
                except Exception as e:
                    print(f"Translation error: {e}")
                    batch_results.append("")

                # Rate limiting
                time.sleep(0.5)

            results.extend(batch_results)
            print(f"  Translated {min(i + batch_size, len(texts))}/{len(texts)}")

        self.cache.save()
        return results

    def _translate_single(self, text: str) -> str:
        """Translate a single text. Override in subclasses."""
        raise NotImplementedError

    def _build_prompt(self, text: str) -> str:
        """Build translation prompt."""
        context_str = f"\nContext: {self.context}" if self.context else ""
        return f"""Translate the following Japanese visual novel text to {self.target_lang}.
Preserve the original meaning and tone. Keep character names unchanged.
Maintain any formatting like newlines.{context_str}

Japanese text:
{text}

{self.target_lang} translation:"""


class OpenAITranslator(LLMTranslator):
    """OpenAI API translator (also works with compatible APIs)."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.model = self.model or "gpt-4o-mini"
        self.base_url = self.base_url or "https://api.openai.com/v1"

    def _translate_single(self, text: str) -> str:
        try:
            import urllib.request
            import urllib.error
        except ImportError:
            raise RuntimeError("urllib required for API calls")

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }

        data = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": f"You are a professional Japanese to {self.target_lang} translator specializing in visual novels. Translate accurately while preserving the original tone and style."},
                {"role": "user", "content": self._build_prompt(text)}
            ],
            "temperature": 0.3,
            "max_tokens": 2000
        }

        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(data).encode('utf-8'),
            headers=headers,
            method='POST'
        )

        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                result = json.loads(response.read().decode('utf-8'))
                return result['choices'][0]['message']['content'].strip()
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8') if e.fp else str(e)
            raise RuntimeError(f"API error {e.code}: {error_body}")


class AnthropicTranslator(LLMTranslator):
    """Anthropic Claude API translator."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.model = self.model or "claude-3-haiku-20240307"
        self.base_url = "https://api.anthropic.com/v1"

    def _translate_single(self, text: str) -> str:
        try:
            import urllib.request
            import urllib.error
        except ImportError:
            raise RuntimeError("urllib required for API calls")

        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01"
        }

        data = {
            "model": self.model,
            "max_tokens": 2000,
            "messages": [
                {"role": "user", "content": self._build_prompt(text)}
            ]
        }

        req = urllib.request.Request(
            f"{self.base_url}/messages",
            data=json.dumps(data).encode('utf-8'),
            headers=headers,
            method='POST'
        )

        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                result = json.loads(response.read().decode('utf-8'))
                return result['content'][0]['text'].strip()
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8') if e.fp else str(e)
            raise RuntimeError(f"API error {e.code}: {error_body}")


class DeepLTranslator(LLMTranslator):
    """DeepL API translator."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Detect if using free or pro API
        if self.api_key and self.api_key.endswith(':fx'):
            self.base_url = "https://api-free.deepl.com/v2"
        else:
            self.base_url = "https://api.deepl.com/v2"

        # Map language names to DeepL codes
        self.lang_map = {
            "english": "EN",
            "portuguese": "PT-BR",
            "spanish": "ES",
            "french": "FR",
            "german": "DE",
            "italian": "IT",
            "dutch": "NL",
            "polish": "PL",
            "russian": "RU",
            "chinese": "ZH",
            "korean": "KO"
        }

    def _translate_single(self, text: str) -> str:
        try:
            import urllib.request
            import urllib.error
            import urllib.parse
        except ImportError:
            raise RuntimeError("urllib required for API calls")

        target_lang = self.lang_map.get(self.target_lang.lower(), "EN")

        data = urllib.parse.urlencode({
            "auth_key": self.api_key,
            "text": text,
            "source_lang": "JA",
            "target_lang": target_lang
        }).encode('utf-8')

        req = urllib.request.Request(
            f"{self.base_url}/translate",
            data=data,
            method='POST'
        )

        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                result = json.loads(response.read().decode('utf-8'))
                return result['translations'][0]['text']
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8') if e.fp else str(e)
            raise RuntimeError(f"API error {e.code}: {error_body}")


def get_translator(api: str, **kwargs) -> LLMTranslator:
    """Factory function to get the appropriate translator."""
    translators = {
        "openai": OpenAITranslator,
        "anthropic": AnthropicTranslator,
        "deepl": DeepLTranslator,
        "openai-compatible": OpenAITranslator,  # Same as OpenAI but with custom base_url
    }

    if api not in translators:
        raise ValueError(f"Unknown API: {api}. Available: {list(translators.keys())}")

    return translators[api](**kwargs)


def translate_json_file(input_path: str, output_path: str, translator: LLMTranslator) -> bool:
    """Translate a JSON file containing extracted strings."""
    print(f"Loading: {input_path}")

    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Handle both VNTools and VNT formats
    if isinstance(data, list):
        # VNT format
        texts = [item.get('message', '') for item in data]
        print(f"Found {len(texts)} strings (VNT format)")

        translations = translator.translate_batch(texts)

        for i, item in enumerate(data):
            if translations[i]:
                item['translated'] = translations[i]
    else:
        # VNTools format
        strings = data.get('strings', [])
        texts = [s.get('original', '') for s in strings if not s.get('translated')]
        print(f"Found {len(texts)} untranslated strings")

        if not texts:
            print("All strings already translated!")
            return True

        translations = translator.translate_batch(texts)

        trans_idx = 0
        for s in strings:
            if not s.get('translated') and trans_idx < len(translations):
                s['translated'] = translations[trans_idx]
                trans_idx += 1

    # Save
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"Saved to: {output_path}")
    return True


def translate_directory(input_dir: str, output_dir: str, translator: LLMTranslator) -> bool:
    """Translate all JSON files in a directory."""
    os.makedirs(output_dir, exist_ok=True)

    json_files = list(Path(input_dir).glob('*.json'))
    print(f"Found {len(json_files)} JSON files")

    for json_file in json_files:
        output_file = Path(output_dir) / json_file.name
        translate_json_file(str(json_file), str(output_file), translator)

    return True


# =============================================================================
# Export Format Conversion
# =============================================================================

def convert_to_vnt_format(input_path: str, output_path: str) -> bool:
    """Convert VNTools JSON to VNTranslationTools format."""
    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    if isinstance(data, list):
        print("Already in VNT format")
        return False

    vnt_data = []
    for s in data.get('strings', []):
        original = s.get('original', '')
        # Try to split name and message
        if '\n' in original:
            parts = original.split('\n', 1)
            vnt_data.append({
                "name": parts[0].strip(),
                "message": parts[1].strip() if len(parts) > 1 else ""
            })
        else:
            vnt_data.append({"message": original})

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(vnt_data, f, ensure_ascii=False, indent=2)

    print(f"Converted {len(vnt_data)} strings to VNT format")
    return True


# =============================================================================
# CLI Interface
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='SystemNNN/PIL/SLASH Visual Novel Tools',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Extract archive
  %(prog)s extract archive.dat -o extracted/

  # Extract text from all scripts
  %(prog)s extract-text extracted/ -o translations/

  # Translate with OpenAI
  %(prog)s translate translations/ -o translated/ --api openai

  # Translate with Claude
  %(prog)s translate translations/ -o translated/ --api anthropic

  # Translate with local LLM (Ollama, LM Studio, etc.)
  %(prog)s translate translations/ -o translated/ --api openai-compatible --base-url http://localhost:11434/v1

  # Translate with DeepL
  %(prog)s translate translations/ -o translated/ --api deepl --lang Portuguese

  # Insert translations and create patched scripts
  %(prog)s insert-text extracted/main05.hxb translations/main05.json -o patched/main05.hxb

  # Repack archive
  %(prog)s repack patched/ -o archive_patched.dat

  # Convert JSON to VNTranslationTools format
  %(prog)s convert-format input.json -o output.json --format vnt

  # Analyze archive
  %(prog)s analyze archive.dat

Environment variables for API keys:
  OPENAI_API_KEY      - OpenAI API key
  ANTHROPIC_API_KEY   - Anthropic API key
  DEEPL_API_KEY       - DeepL API key
'''
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Extract command
    extract_parser = subparsers.add_parser('extract', help='Extract DDP archive')
    extract_parser.add_argument('archive', help='Path to DDP archive')
    extract_parser.add_argument('-o', '--output', help='Output directory')
    extract_parser.add_argument('--no-decrypt', action='store_true', help='Do not decrypt HXB files')

    # Extract text command
    extract_text_parser = subparsers.add_parser('extract-text', help='Extract text from scripts (HXB/SPT/NNN)')
    extract_text_parser.add_argument('input', help='Script file or directory')
    extract_text_parser.add_argument('-o', '--output', help='Output JSON file or directory')
    extract_text_parser.add_argument('--format', choices=['vntools', 'vnt'], default='vntools',
                                     help='Output format: vntools (default) or vnt (VNTranslationTools)')

    # Translate command (NEW!)
    translate_parser = subparsers.add_parser('translate', help='Translate JSON files using LLM APIs')
    translate_parser.add_argument('input', help='JSON file or directory')
    translate_parser.add_argument('-o', '--output', help='Output JSON file or directory')
    translate_parser.add_argument('--api', required=True,
                                  choices=['openai', 'anthropic', 'deepl', 'openai-compatible'],
                                  help='Translation API to use')
    translate_parser.add_argument('--api-key', help='API key (or use environment variable)')
    translate_parser.add_argument('--model', help='Model name (optional, uses default)')
    translate_parser.add_argument('--base-url', help='Base URL for OpenAI-compatible APIs')
    translate_parser.add_argument('--lang', default='English', help='Target language (default: English)')
    translate_parser.add_argument('--context', default='', help='Additional context for translation')

    # Convert format command (NEW!)
    convert_parser = subparsers.add_parser('convert-format', help='Convert between JSON formats')
    convert_parser.add_argument('input', help='Input JSON file')
    convert_parser.add_argument('-o', '--output', required=True, help='Output JSON file')
    convert_parser.add_argument('--format', choices=['vnt', 'vntools'], default='vnt',
                                help='Target format: vnt (VNTranslationTools) or vntools')

    # Insert text command
    insert_parser = subparsers.add_parser('insert-text', help='Insert translated text into scripts')
    insert_parser.add_argument('script', help='Original script file')
    insert_parser.add_argument('translation', help='Translation JSON file')
    insert_parser.add_argument('-o', '--output', required=True, help='Output script file')

    # Repack command
    repack_parser = subparsers.add_parser('repack', help='Repack files into DDP archive')
    repack_parser.add_argument('input', help='Directory containing files')
    repack_parser.add_argument('-o', '--output', required=True, help='Output archive path')
    repack_parser.add_argument('--version', type=int, choices=[2, 3], default=3, help='DDP version')
    repack_parser.add_argument('--compress', action='store_true', help='Compress files')

    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze archive structure')
    analyze_parser.add_argument('archive', help='Path to DDP archive')

    args = parser.parse_args()

    if args.command == 'extract':
        output = args.output or args.archive + '_extracted'
        extract_archive(args.archive, output, decrypt=not args.no_decrypt)

    elif args.command == 'extract-text':
        input_path = Path(args.input)
        output_format = getattr(args, 'format', 'vntools')

        if input_path.is_dir():
            output = args.output or str(input_path) + '_text'
            extract_all_text_with_format(str(input_path), output, output_format)
        else:
            output = args.output or str(input_path.with_suffix('.json'))
            extract_text_with_format(str(input_path), output, output_format)

    elif args.command == 'translate':
        # Get API key from args or environment
        api_key = args.api_key
        if not api_key:
            env_keys = {
                'openai': 'OPENAI_API_KEY',
                'openai-compatible': 'OPENAI_API_KEY',
                'anthropic': 'ANTHROPIC_API_KEY',
                'deepl': 'DEEPL_API_KEY'
            }
            env_var = env_keys.get(args.api)
            api_key = os.environ.get(env_var, '')

        if not api_key:
            print(f"Error: API key required. Set {env_keys.get(args.api)} or use --api-key")
            sys.exit(1)

        # Create translator
        translator = get_translator(
            args.api,
            api_key=api_key,
            model=args.model or "",
            base_url=args.base_url,
            target_lang=args.lang,
            context=args.context
        )

        input_path = Path(args.input)
        if input_path.is_dir():
            output = args.output or str(input_path) + '_translated'
            translate_directory(str(input_path), output, translator)
        else:
            output = args.output or str(input_path.with_stem(input_path.stem + '_translated'))
            translate_json_file(str(input_path), output, translator)

    elif args.command == 'convert-format':
        if args.format == 'vnt':
            convert_to_vnt_format(args.input, args.output)
        else:
            # Convert VNT to VNTools format
            with open(args.input, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if isinstance(data, list):
                vntools_data = {
                    'source_file': '',
                    'format': 'converted-from-vnt',
                    'string_count': len(data),
                    'strings': [
                        {
                            'index': i,
                            'offset': 0,
                            'original': item.get('message', ''),
                            'translated': item.get('translated', ''),
                            'context': item.get('name', '')
                        }
                        for i, item in enumerate(data)
                    ]
                }
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(vntools_data, f, ensure_ascii=False, indent=2)
                print(f"Converted {len(data)} strings to VNTools format")
            else:
                print("Already in VNTools format")

    elif args.command == 'insert-text':
        insert_text(args.script, args.translation, args.output)

    elif args.command == 'repack':
        repack_archive(args.input, args.output, args.version, args.compress)

    elif args.command == 'analyze':
        archive = DDPArchive(args.archive)
        if archive.open():
            print(f"Format: DDP{archive.version}")
            print(f"Files: {len(archive.entries)}")
            print("\nFirst 20 entries:")
            for i, entry in enumerate(archive.entries[:20]):
                packed_info = f" (packed: {entry.packed_size})" if entry.is_packed else ""
                print(f"  {i:4d}: {entry.name:30s} @ 0x{entry.offset:08X}  size: {entry.unpacked_size:8d}{packed_info}")
            if len(archive.entries) > 20:
                print(f"  ... and {len(archive.entries) - 20} more")
    else:
        parser.print_help()


def extract_text_with_format(script_path: str, output_path: str, format: str = "vntools") -> bool:
    """Extract translatable text from a script with format option."""
    print(f"Parsing script: {script_path}")

    with open(script_path, 'rb') as f:
        data = f.read()

    # Auto-detect format
    if is_nnn_file(data):
        print("Detected: NNN dev format (Shift-JIS)")
        script = NNNScript()
    elif is_spt_file(data):
        print("Detected: SPT format (Shift-JIS)")
        script = SPTScript()
    elif len(data) >= 7 and (data[:4] == b'DDSx' or data[:4] == b'DDWu'):
        print("Detected: HXB format (UTF-16LE)")
        if data[:4] == b'DDWu':
            data = fix_hxb_signature(data)
            data = decrypt_hxb(data)
        script = HXBScript()
    else:
        print("Unknown script format")
        return False

    if not script.parse(data):
        print("Failed to parse script")
        return False

    print(f"Found {len(script.strings)} text strings")

    # Export with format option
    if hasattr(script, 'export_strings'):
        if isinstance(script, NNNScript):
            script.export_strings(output_path, format)
        else:
            script.export_strings(output_path)
            # Convert if VNT format requested
            if format == 'vnt':
                convert_to_vnt_format(output_path, output_path)

    print(f"Exported to: {output_path}")
    return True


def extract_all_text_with_format(input_dir: str, output_dir: str, format: str = "vntools") -> bool:
    """Extract text from all scripts in a directory with format option."""
    os.makedirs(output_dir, exist_ok=True)

    # Find all script files
    hxb_files = list(Path(input_dir).glob('*.hxb'))
    spt_files = list(Path(input_dir).glob('*.spt'))
    nnn_files = list(Path(input_dir).glob('*.nnn'))
    all_files = hxb_files + spt_files + nnn_files

    print(f"Found {len(hxb_files)} HXB, {len(spt_files)} SPT, {len(nnn_files)} NNN files")

    total_strings = 0
    for script_path in all_files:
        json_path = Path(output_dir) / (script_path.stem + '.json')
        extract_text_with_format(str(script_path), str(json_path), format)

    return True


if __name__ == '__main__':
    main()
