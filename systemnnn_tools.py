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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nnn_engine as nne  # noqa: E402
import llm_translate as llm  # noqa: E402


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
# SJIS Tunneling - Character Mapping for Unsupported Characters
# =============================================================================

class SJISTunnelEncoder(nne.SJISTunnel):
    """
    VNTextProxy-compatible SJIS tunneling (same algorithm and sjis_ext.bin
    layout as arcusmaximus' VNTextPatch).

    Characters CP932 cannot encode get a code made of an SJIS lead byte and an
    invalid trail byte (0x01-0x3F). Real Japanese characters are never touched.
    sjis_ext.bin is the list of tunneled characters as raw UTF-16LE; put it next
    to the game exe together with VNTextProxy, which draws the real glyphs.
    """

    def encode(self, text: str, encoding: str = 'cp932') -> bytes:
        return b''.join(self.encode_char(c) for c in text)

    def tunnel_index(self, hi: int, lo: int) -> int:
        rev = {self.tunnel_bytes(c): i for i, c in enumerate(self.chars)}
        return rev.get(bytes([hi, lo]), -1)

    def decode(self, data: bytes, encoding: str = 'cp932') -> str:
        rev = {self.tunnel_bytes(c): i for i, c in enumerate(self.chars)}
        out = []
        i = 0
        while i < len(data):
            b = data[i]
            if (0x81 <= b < 0xA0) or (0xE0 <= b < 0xFD):
                if i + 1 < len(data):
                    idx = rev.get(data[i:i + 2], -1)
                    if idx >= 0:
                        out.append(self.chars[idx])
                    else:
                        out.append(data[i:i + 2].decode('cp932', 'replace'))
                i += 2
            else:
                out.append(bytes([b]).decode('cp932', 'replace'))
                i += 1
        return ''.join(out)

    def save_mapping(self, filepath: str):
        self.save(filepath)

    def load_mapping(self, filepath: str):
        if os.path.exists(filepath):
            self.load(filepath)

    def get_mapping(self) -> Dict[str, str]:
        return {self.tunnel_bytes(c).hex(): c for c in list(self.chars)}

    def get_stats(self) -> Dict[str, Any]:
        return {
            'mapped_chars': len(self.chars),
            'available_slots': self.LIMIT - len(self.chars),
            'usage_percent': len(self.chars) / self.LIMIT * 100,
        }
# =============================================================================
# Character Name Management
# =============================================================================

class CharacterNameManager:
    """
    Manage character name translations for consistency across scripts.

    Inspired by VNTextPatch's names.xml system.
    Stores original -> translated name mappings for reuse.
    """

    def __init__(self, filepath: str = 'names.json'):
        self.filepath = filepath
        self.names: Dict[str, str] = {}
        self.load()

    def add_name(self, original: str, translated: str):
        """Add or update a character name mapping."""
        if original and translated:
            self.names[original] = translated

    def get_translation(self, original: str) -> Optional[str]:
        """Get translated name for an original name."""
        return self.names.get(original)

    def load(self):
        """Load names from JSON file."""
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, 'r', encoding='utf-8') as f:
                    self.names = json.load(f)
            except Exception as e:
                print(f"Warning: Could not load {self.filepath}: {e}")

    def save(self):
        """Save names to JSON file."""
        try:
            with open(self.filepath, 'w', encoding='utf-8') as f:
                json.dump(self.names, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Error saving {self.filepath}: {e}")

    def extract_names_from_json(self, json_data: List[Dict[str, str]]):
        """
        Extract character names from VNTranslationTools JSON format.

        Looks for entries with non-empty 'name' fields.
        """
        for entry in json_data:
            name = entry.get('name', '').strip()
            if name and name not in self.names:
                # Add with empty translation for manual filling
                self.names[name] = ''

    def auto_translate_names(self, json_data: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Auto-fill translated names in JSON data using stored mappings.

        Args:
            json_data: List of {"name": "...", "message": "..."} entries

        Returns:
            Modified json_data with translated names filled in
        """
        for entry in json_data:
            original_name = entry.get('name', '')
            if original_name in self.names and self.names[original_name]:
                entry['translated_name'] = self.names[original_name]

        return json_data


# =============================================================================
# Word Wrapping for Text Display
# =============================================================================

class WordWrapper:
    """
    Word wrapper for preventing text overflow in VN text boxes.

    Inspired by VNTextPatch's word wrapping system.
    Supports both monospace and proportional fonts.
    """

    def __init__(self, chars_per_line: int = 40, mode: str = 'monospace'):
        """
        Initialize word wrapper.

        Args:
            chars_per_line: Maximum characters per line
            mode: 'monospace' or 'proportional'
        """
        self.chars_per_line = chars_per_line
        self.mode = mode

        # Character width table for proportional fonts (rough estimates)
        # Based on typical VN font metrics
        self.char_widths = {
            # ASCII narrow characters
            'i': 0.5, 'l': 0.5, 'I': 0.5, 't': 0.6, 'f': 0.6,
            # ASCII wide characters
            'W': 1.4, 'M': 1.4, 'm': 1.2, 'w': 1.2,
            # Punctuation
            '.': 0.4, ',': 0.4, ':': 0.4, ';': 0.4, '!': 0.5, '?': 0.8,
            # Spaces and quotes
            ' ': 0.5, '"': 0.6, "'": 0.4,
        }

    def wrap(self, text: str) -> str:
        """
        Wrap text to fit within character limit.

        Args:
            text: Text to wrap

        Returns:
            Text with line breaks inserted
        """
        if self.mode == 'monospace':
            return self._wrap_monospace(text)
        else:
            return self._wrap_proportional(text)

    def _wrap_monospace(self, text: str) -> str:
        """Wrap text assuming monospace font (1 char = 1 unit width)."""
        lines = []
        current_line = []
        current_length = 0

        words = text.split()

        for word in words:
            word_length = len(word)

            # Check if adding this word would exceed limit
            if current_length + len(current_line) + word_length > self.chars_per_line:
                # Start new line
                if current_line:
                    lines.append(' '.join(current_line))
                    current_line = [word]
                    current_length = word_length
                else:
                    # Single word too long - break it
                    lines.append(word[:self.chars_per_line])
                    current_line = [word[self.chars_per_line:]]
                    current_length = len(current_line[0])
            else:
                current_line.append(word)
                current_length += word_length

        # Add remaining line
        if current_line:
            lines.append(' '.join(current_line))

        return '\n'.join(lines)

    def _wrap_proportional(self, text: str) -> str:
        """Wrap text for proportional fonts using width estimates."""
        lines = []
        current_line = []
        current_width = 0.0

        words = text.split()

        for word in words:
            word_width = sum(self.char_widths.get(c, 1.0) for c in word)
            space_width = 0.5 if current_line else 0

            if current_width + space_width + word_width > self.chars_per_line:
                if current_line:
                    lines.append(' '.join(current_line))
                    current_line = [word]
                    current_width = word_width
                else:
                    # Word too long - add anyway
                    lines.append(word)
                    current_line = []
                    current_width = 0
            else:
                current_line.append(word)
                current_width += space_width + word_width

        if current_line:
            lines.append(' '.join(current_line))

        return '\n'.join(lines)

    def calculate_line_count(self, text: str) -> int:
        """Calculate how many lines the text will occupy."""
        wrapped = self.wrap(text)
        return wrapped.count('\n') + 1


# =============================================================================
# SPT Script Parser (table-based, see nnn_engine.py)
# =============================================================================

SPTString = nne.SPTEntry


class SPTScript(nne.SPTScript):
    """
    SPT script (System-NNN / BlackCyc / Mugen Kairou 2 ...).

    Strings are read through the two pointer tables in the header, so every
    message and choice is found exactly, with the speaker name split off.
    Rebuilding writes a translation in place when it fits and otherwise appends
    it to the end of the file and repoints its table entry, so translations can
    be any length without breaking the bytecode.
    """

    def export_strings(self, filepath: str, source_file: str = ''):
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.to_json(source_file), f, ensure_ascii=False, indent=2)

    def import_strings(self, filepath: str):
        with open(filepath, 'r', encoding='utf-8') as f:
            self.import_json(json.load(f))

    def rebuild(self, encoder: Optional['nne.MessageEncoder'] = None,
                names: Optional[Dict[str, str]] = None) -> bytes:
        return super().rebuild(encoder or nne.MessageEncoder(), names)
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
# LLM Translation (context-aware, chunked; see llm_translate.py)
# =============================================================================

Line = llm.Line


def load_doc(path: str) -> dict:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_doc(path: str, doc: dict):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def entry_id(s: dict) -> str:
    return str(s.get('id', s.get('index')))


def source_text(doc: dict, s: dict) -> str:
    """Text sent to the translator. SPT originals are unwrapped: the Japanese
    line breaks and full-width indents are layout, re-done at insert time."""
    text = s.get('original', '')
    if doc.get('format') == 'spt-table':
        text = text.replace('\r\n', '\n').rstrip('\n')
        text = re.sub(r'\n[　 ]*(?=\S)', '', text)
    return text


def doc_lines(doc: dict) -> List[Line]:
    return [Line(id=entry_id(s), text=source_text(doc, s), name=s.get('name', '') or '')
            for s in doc.get('strings', [])]


def load_style_guide(path: Optional[str]) -> str:
    if not path:
        return ''
    with open(path, 'r', encoding='utf-8') as f:
        return f.read().strip()


def apply_results(doc: dict, results: Dict[str, str], dictionary: Optional['GPTDictionary'] = None,
                  overwrite: bool = False):
    for s in doc.get('strings', []):
        sid = entry_id(s)
        if sid in results and (overwrite or not s.get('translated')):
            text = results[sid]
            if dictionary:
                text = dictionary.apply_post_processing(text)
            s['translated'] = text
        if dictionary and s.get('name') and not s.get('name_translated'):
            nm = dictionary.post_translation.get(s['name'])
            if nm:
                s['name_translated'] = nm


def make_chunk_translator(api: str, api_key: str = '', model: str = '', base_url: str = '',
                          target_lang: str = 'English', effort: str = 'medium',
                          chunk_size: int = 30, context_lines: int = 8,
                          dictionary: Optional['GPTDictionary'] = None, style_guide: str = '',
                          notes: str = '', dict_context: str = '') -> 'llm.ChunkTranslator':
    backend = llm.make_backend(api, api_key=api_key, model=model, base_url=base_url,
                               target_lang=target_lang, effort=effort)
    glossary = dictionary.get_context_prompt(dict_context) if dictionary else ''
    if api == 'deepl':
        chunk_size = min(chunk_size, 50)
    return llm.ChunkTranslator(backend, chunk_size=chunk_size, context_lines=context_lines,
                               glossary=glossary, style_guide=style_guide, notes=notes)


def translate_json_file(input_path: str, output_path: str, translator: 'llm.ChunkTranslator',
                        dictionary: Optional['GPTDictionary'] = None,
                        overwrite: bool = False, **_ignored) -> bool:
    """Translate one VNTools JSON. Progress is saved after every chunk, so an
    interrupted run resumes where it stopped (already translated lines are kept
    unless overwrite=True)."""
    doc = load_doc(output_path if os.path.exists(output_path) and not overwrite else input_path)
    lines = doc_lines(doc)
    done = {} if overwrite else {entry_id(s): s['translated']
                                 for s in doc.get('strings', []) if s.get('translated')}
    print(f'Translating {input_path}: {len(lines) - len(done)} of {len(lines)} lines to do')

    def progress(res):
        apply_results(doc, res, dictionary, overwrite=True)
        save_doc(output_path, doc)

    res = translator.translate(lines, done=done, on_progress=progress)
    apply_results(doc, res, dictionary, overwrite=True)
    save_doc(output_path, doc)
    u = translator.backend.usage
    if u['input'] or u['output']:
        print(f"  tokens so far: {u['input']} in ({u['cache_read']} cached), {u['output']} out")
    return True


def translate_directory(input_dir: str, output_dir: str, translator: 'llm.ChunkTranslator',
                        dictionary: Optional['GPTDictionary'] = None, overwrite: bool = False,
                        batch_api: bool = False) -> bool:
    os.makedirs(output_dir, exist_ok=True)
    files = sorted(Path(input_dir).glob('*.json'))
    if batch_api:
        prepared = []
        docs = {}
        for p in files:
            out = os.path.join(output_dir, p.name)
            doc = load_doc(out if os.path.exists(out) and not overwrite else str(p))
            done = {} if overwrite else {entry_id(s): s['translated']
                                         for s in doc.get('strings', []) if s.get('translated')}
            docs[p.name] = (doc, out)
            prepared.append((p.name, doc_lines(doc), done))
        results = translator.translate_batch_api(prepared)
        for name, (doc, out) in docs.items():
            apply_results(doc, results.get(name, {}), dictionary, overwrite=True)
            save_doc(out, doc)
        print(f'Batch finished: {sum(len(v) for v in results.values())} lines translated')
        return True
    for p in files:
        translate_json_file(str(p), os.path.join(output_dir, p.name), translator,
                            dictionary=dictionary, overwrite=overwrite)
    return True


def build_glossary_file(input_path: str, dict_path: str, api: str, api_key: str, model: str = '',
                        base_url: str = '', target_lang: str = 'English',
                        charaname: Optional[str] = None) -> bool:
    paths = sorted(Path(input_path).glob('*.json')) if os.path.isdir(input_path) else [Path(input_path)]
    lines: List[Line] = []
    for p in paths:
        lines += doc_lines(load_doc(str(p)))
    extra = nne.read_charaname(charaname) if charaname else []
    backend = llm.make_backend(api, api_key=api_key, model=model, base_url=base_url,
                               target_lang=target_lang, effort='high')
    terms = llm.build_glossary(backend, lines, extra)
    d = GPTDictionary(dict_path)
    added = 0
    for t in terms:
        src, tgt = t.get('source', ''), t.get('target', '')
        if not src or not tgt or src in d.post_translation:
            continue
        d.add_post_translation(src, tgt)
        if t.get('kind') == 'character' and t.get('note'):
            d.add_character_context(f'{tgt} ({src})', t['note'])
        elif t.get('note'):
            d.add_pre_translation(src, t['note'])
        added += 1
    d.save()
    print(f'Glossary: {added} new terms written to {dict_path} (review it before translating)')
    return True


# =============================================================================
# GalTransl / LinguaGacha interchange (json_jp list of {name, message})
# =============================================================================

def export_galtransl(input_path: str, output_dir: str) -> int:
    os.makedirs(output_dir, exist_ok=True)
    paths = sorted(Path(input_path).glob('*.json')) if os.path.isdir(input_path) else [Path(input_path)]
    n = 0
    for p in paths:
        doc = load_doc(str(p))
        items = []
        for s in doc.get('strings', []):
            item = {}
            if s.get('name'):
                item['name'] = s['name']
            item['message'] = source_text(doc, s)
            items.append(item)
        with open(os.path.join(output_dir, p.name), 'w', encoding='utf-8') as f:
            json.dump(items, f, ensure_ascii=False, indent=2)
        n += len(items)
    print(f'Exported {n} lines to {output_dir} (GalTransl json_jp / LinguaGacha MESSAGEJSON)')
    return n


def import_galtransl(json_dir: str, translated_dir: str, output_dir: str) -> int:
    os.makedirs(output_dir, exist_ok=True)
    n = 0
    for p in sorted(Path(json_dir).glob('*.json')):
        tp = Path(translated_dir) / p.name
        if not tp.exists():
            continue
        doc = load_doc(str(p))
        items = load_doc(str(tp))
        strings = doc.get('strings', [])
        if len(items) != len(strings):
            print(f'  {p.name}: {len(items)} translated lines but {len(strings)} expected, skipped')
            continue
        for s, it in zip(strings, items):
            msg = it.get('message') or it.get('dst') or ''
            if msg and msg != source_text(doc, s):
                s['translated'] = msg
                n += 1
            nm = it.get('name')
            if s.get('name') and nm and nm != s['name']:
                s['name_translated'] = nm
        save_doc(str(Path(output_dir) / p.name), doc)
    print(f'Imported {n} translations into {output_dir}')
    return n


def migrate_old_spt_json(old_path: str, new_path: str, output_path: str) -> int:
    """Carry translations from a pre-2.0 (heuristic) SPT JSON into a new
    table-based extraction by matching the Japanese text."""
    old = load_doc(old_path)
    new = load_doc(new_path)

    def norm(t: str) -> str:
        return re.sub(r'\s+', '', t.replace('\r', ''))

    table = {}
    for s in old.get('strings', []):
        if s.get('translated'):
            o = norm(s.get('original', ''))
            for k in range(0, 3):  # old extractor kept up to 2 junk chars
                table.setdefault(o[k:], s['translated'])
    n = 0
    for s in new.get('strings', []):
        full = norm((s.get('name', '') or '') + s.get('original', ''))
        body = norm(s.get('original', ''))
        tr = table.get(full) or table.get(body)
        if tr and not s.get('translated'):
            if s.get('name') and '\n' in tr.replace('\r\n', '\n'):
                head, rest = tr.replace('\r\n', '\n').split('\n', 1)
                s['name_translated'] = head.strip()
                tr = rest
            s['translated'] = tr
            n += 1
    save_doc(output_path, new)
    print(f'Migrated {n} translations')
    return n
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
# GPT Dictionary System (Terminology & Character Context)
# =============================================================================

class GPTDictionary:
    """
    GPT dictionary system for consistent translation of character names and terminology.

    Inspired by GalTransl's triple dictionary system:
    - Pre-translation: Japanese terms/names to guide recognition
    - Post-translation: Target language terms to guide output
    - Conditional: Context-specific translations
    """

    def __init__(self, filepath: str = 'gpt_dictionary.json'):
        self.filepath = filepath
        self.pre_translation: Dict[str, str] = {}  # JP -> Description/Context
        self.post_translation: Dict[str, str] = {}  # JP -> Target language
        self.conditional: Dict[str, Dict[str, str]] = {}  # Context -> {JP -> Target}
        self.character_contexts: Dict[str, str] = {}  # Character -> Background/personality
        self.load()

    def load(self):
        """Load dictionary from JSON file."""
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.pre_translation = data.get('pre_translation', {})
                    self.post_translation = data.get('post_translation', {})
                    self.conditional = data.get('conditional', {})
                    self.character_contexts = data.get('character_contexts', {})
            except Exception as e:
                print(f"Warning: Could not load {self.filepath}: {e}")

    def save(self):
        """Save dictionary to JSON file."""
        try:
            data = {
                'pre_translation': self.pre_translation,
                'post_translation': self.post_translation,
                'conditional': self.conditional,
                'character_contexts': self.character_contexts
            }
            with open(self.filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Error saving {self.filepath}: {e}")

    def add_pre_translation(self, japanese: str, description: str):
        """Add pre-translation entry (recognition hint)."""
        self.pre_translation[japanese] = description

    def add_post_translation(self, japanese: str, translation: str):
        """Add post-translation entry (required translation)."""
        self.post_translation[japanese] = translation

    def add_conditional(self, context: str, japanese: str, translation: str):
        """Add context-specific translation."""
        if context not in self.conditional:
            self.conditional[context] = {}
        self.conditional[context][japanese] = translation

    def add_character_context(self, name: str, context: str):
        """Add character background/personality context."""
        self.character_contexts[name] = context

    def get_context_prompt(self, context: str = '') -> str:
        """
        Generate prompt segment with dictionary information.

        Args:
            context: Optional context identifier for conditional translations

        Returns:
            Formatted string for inclusion in LLM prompt
        """
        prompt_parts = []

        # Character contexts
        if self.character_contexts:
            prompt_parts.append("## Character Information:")
            for char, desc in self.character_contexts.items():
                prompt_parts.append(f"- {char}: {desc}")
            prompt_parts.append("")

        # Pre-translation (recognition hints)
        if self.pre_translation:
            prompt_parts.append("## Terms to Recognize:")
            for jp, desc in self.pre_translation.items():
                prompt_parts.append(f"- {jp}: {desc}")
            prompt_parts.append("")

        # Post-translation (required translations)
        if self.post_translation:
            prompt_parts.append("## Required Translations:")
            for jp, trans in self.post_translation.items():
                prompt_parts.append(f"- {jp} → {trans}")
            prompt_parts.append("")

        # Conditional translations for current context
        if context and context in self.conditional:
            prompt_parts.append(f"## Context-Specific Translations ({context}):")
            for jp, trans in self.conditional[context].items():
                prompt_parts.append(f"- {jp} → {trans}")
            prompt_parts.append("")

        return '\n'.join(prompt_parts)

    def apply_post_processing(self, text: str) -> str:
        """
        Apply post-translation dictionary replacements.

        Args:
            text: Translated text

        Returns:
            Text with dictionary terms enforced
        """
        result = text
        for jp, trans in self.post_translation.items():
            # Only replace if Japanese term somehow leaked through
            result = result.replace(jp, trans)
        return result


# =============================================================================
# Translation QA & Validation
# =============================================================================

class TranslationQA:
    """
    Automated quality assurance for translations.

    Inspired by GalTransl's QA system. Detects common translation errors:
    - Repeated words
    - Punctuation mismatches
    - Leftover Japanese characters
    - Line break discrepancies
    - Length violations
    - Dictionary compliance failures
    """

    # Japanese character ranges
    HIRAGANA = range(0x3040, 0x309F + 1)
    KATAKANA = range(0x30A0, 0x30FF + 1)
    KANJI_1 = range(0x4E00, 0x9FFF + 1)
    KANJI_2 = range(0x3400, 0x4DBF + 1)

    def __init__(self, dictionary: Optional[GPTDictionary] = None):
        self.dictionary = dictionary
        self.issues: List[Dict[str, Any]] = []

    def validate(self, original: str, translated: str, index: int = 0) -> List[str]:
        """
        Validate a translated string and return list of issues.

        Args:
            original: Original text
            translated: Translated text
            index: String index for reporting

        Returns:
            List of issue descriptions
        """
        issues = []

        # Check for repeated words (more than 2 consecutive)
        words = translated.split()
        for i in range(len(words) - 2):
            if words[i] == words[i+1] == words[i+2] and len(words[i]) > 2:
                issues.append(f"Repeated word: '{words[i]}'")

        # Check for leftover Japanese characters
        if self._contains_japanese(translated):
            issues.append("Contains untranslated Japanese characters")

        # Check punctuation balance
        punct_pairs = [('(', ')'), ('[', ']'), ('{', '}'), ('「', '」'), ('『', '』')]
        for open_p, close_p in punct_pairs:
            orig_open = original.count(open_p)
            orig_close = original.count(close_p)
            trans_open = translated.count(open_p)
            trans_close = translated.count(close_p)

            if orig_open != orig_close and trans_open != trans_close:
                issues.append(f"Unbalanced punctuation: {open_p}{close_p}")

        # Check line break count difference
        orig_lines = original.count('\n')
        trans_lines = translated.count('\n')
        if abs(orig_lines - trans_lines) > 1:
            issues.append(f"Line break mismatch: {orig_lines} → {trans_lines}")

        # Check length (warn if translation is much longer/shorter)
        orig_len = len(original)
        trans_len = len(translated)
        if trans_len > orig_len * 2.5:
            issues.append(f"Translation too long: {trans_len} chars (original: {orig_len})")
        elif trans_len < orig_len * 0.3 and trans_len > 0:
            issues.append(f"Translation too short: {trans_len} chars (original: {orig_len})")

        # Check empty translation
        if not translated.strip() and original.strip():
            issues.append("Empty translation for non-empty original")

        # Dictionary compliance check
        if self.dictionary:
            for jp, required_trans in self.dictionary.post_translation.items():
                if jp in original and required_trans not in translated:
                    issues.append(f"Missing required translation: {jp} → {required_trans}")

        # Store issues for reporting
        if issues:
            self.issues.append({
                'index': index,
                'original': original[:50] + '...' if len(original) > 50 else original,
                'translated': translated[:50] + '...' if len(translated) > 50 else translated,
                'issues': issues
            })

        return issues

    def _contains_japanese(self, text: str) -> bool:
        """Check if text contains Japanese characters."""
        for char in text:
            code = ord(char)
            if (code in self.HIRAGANA or code in self.KATAKANA or
                code in self.KANJI_1 or code in self.KANJI_2):
                return True
        return False

    def generate_report(self) -> str:
        """Generate QA report of all issues found."""
        if not self.issues:
            return "✓ No issues found!"

        lines = [f"\n{'='*60}", "Translation QA Report", '='*60, ""]
        lines.append(f"Total issues found: {len(self.issues)}\n")

        for item in self.issues:
            lines.append(f"[String {item['index']}]")
            lines.append(f"Original: {item['original']}")
            lines.append(f"Translated: {item['translated']}")
            lines.append("Issues:")
            for issue in item['issues']:
                lines.append(f"  - {issue}")
            lines.append("")

        return '\n'.join(lines)

    def clear(self):
        """Clear accumulated issues."""
        self.issues = []


# =============================================================================
# Checkpoint System for Resuming Translations
# =============================================================================

class CheckpointManager:
    """
    Checkpoint system for saving and resuming translation progress.

    Inspired by GalTransl's checkpoint system.
    Allows resuming interrupted translations without losing progress.
    """

    def __init__(self, checkpoint_dir: str = '.checkpoints'):
        self.checkpoint_dir = checkpoint_dir
        os.makedirs(checkpoint_dir, exist_ok=True)

    def save_checkpoint(self, project_name: str, data: Dict[str, Any]):
        """
        Save translation checkpoint.

        Args:
            project_name: Unique identifier for this translation project
            data: Checkpoint data (progress, cache, etc.)
        """
        checkpoint_path = os.path.join(self.checkpoint_dir, f"{project_name}.json")

        checkpoint = {
            'timestamp': time.time(),
            'project_name': project_name,
            'data': data
        }

        try:
            with open(checkpoint_path, 'w', encoding='utf-8') as f:
                json.dump(checkpoint, f, ensure_ascii=False, indent=2)
            print(f"Checkpoint saved: {checkpoint_path}")
        except Exception as e:
            print(f"Error saving checkpoint: {e}")

    def load_checkpoint(self, project_name: str) -> Optional[Dict[str, Any]]:
        """
        Load translation checkpoint.

        Args:
            project_name: Project identifier

        Returns:
            Checkpoint data or None if not found
        """
        checkpoint_path = os.path.join(self.checkpoint_dir, f"{project_name}.json")

        if not os.path.exists(checkpoint_path):
            return None

        try:
            with open(checkpoint_path, 'r', encoding='utf-8') as f:
                checkpoint = json.load(f)

            timestamp = checkpoint.get('timestamp', 0)
            age_hours = (time.time() - timestamp) / 3600

            print(f"Found checkpoint from {age_hours:.1f} hours ago")
            return checkpoint.get('data')

        except Exception as e:
            print(f"Error loading checkpoint: {e}")
            return None

    def delete_checkpoint(self, project_name: str):
        """Delete checkpoint after successful completion."""
        checkpoint_path = os.path.join(self.checkpoint_dir, f"{project_name}.json")
        if os.path.exists(checkpoint_path):
            try:
                os.remove(checkpoint_path)
                print(f"Checkpoint deleted: {checkpoint_path}")
            except Exception as e:
                print(f"Error deleting checkpoint: {e}")

    def list_checkpoints(self) -> List[Dict[str, Any]]:
        """List all available checkpoints."""
        checkpoints = []

        for filename in os.listdir(self.checkpoint_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(self.checkpoint_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        checkpoint = json.load(f)
                        checkpoints.append({
                            'project': checkpoint.get('project_name'),
                            'timestamp': checkpoint.get('timestamp'),
                            'file': filename
                        })
                except:
                    pass

        return sorted(checkpoints, key=lambda x: x['timestamp'], reverse=True)


# =============================================================================
# CLI Interface
# =============================================================================

def _api_key(api: str, given: Optional[str]) -> str:
    key = given or os.environ.get(llm.API_KEY_ENV.get(api, ''), '')
    return key


def insert_text_cli(script: str, translation: str, output: str, wrap: str = 'auto',
                    code_byte: int = 2, tunnel_path: Optional[str] = None,
                    names_path: Optional[str] = None, spt_key: Optional[str] = None,
                    max_lines: int = 0) -> bool:
    with open(script, 'rb') as f:
        data = f.read()
    if not nne.is_spt_data(data, spt_key):
        return insert_text(script, translation, output)

    spt = SPTScript(spt_key)
    if not spt.parse(data):
        print('Failed to parse SPT script')
        return False
    spt.import_strings(translation)
    width, orig_lines = nne.measure_layout(spt.entries)
    if wrap == 'auto':
        # Original width is measured in full-width cells; codeByte=1 halves Latin letters.
        wrap_width = width
    else:
        wrap_width = int(wrap)
    if wrap_width:
        for e in spt.entries:
            if e.translated and e.kind == 'message':
                e.translated = nne.wrap_text(e.translated, wrap_width, code_byte)
    names = {}
    if names_path and os.path.exists(names_path):
        if names_path.endswith('.json'):
            d = load_doc(names_path)
            names = d.get('post_translation', d) if isinstance(d, dict) else {}
    tunnel = SJISTunnelEncoder(tunnel_path) if tunnel_path else None
    if code_byte == 1 and tunnel:
        print('  ! --tunnel is ignored with --code-byte 1 (single-byte mode is ASCII only)')
        tunnel = None
    encoder = nne.MessageEncoder(tunnel=tunnel, code_byte=code_byte)
    if code_byte == 1:
        untranslated = sorted({e.name for e in spt.entries
                               if e.name and not e.name_translated and e.name not in names})
        if untranslated:
            print('  ! codeByte 1 cannot draw Japanese; untranslated speaker names: '
                  + ', '.join(untranslated[:15]) + ' (use --names gpt_dictionary.json)')
    out = spt.rebuild(encoder, names)
    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
    with open(output, 'wb') as f:
        f.write(out)
    if tunnel:
        tunnel.save_mapping(tunnel_path)
    limit = max_lines or orig_lines
    over = [e.id for e in spt.entries if e.translated and e.kind == 'message'
            and len(e.translated.rstrip('\n').split('\n')) > limit]
    n = sum(1 for e in spt.entries if e.translated)
    print(f'{os.path.basename(script)}: {n} translated, wrap {wrap_width} units '
          f'(codeByte {code_byte}), window {orig_lines} lines')
    if over:
        print(f'  ! {len(over)} messages longer than {limit} lines: {", ".join(over[:10])}'
              + (' ...' if len(over) > 10 else ''))
    for w in sorted(set(encoder.warnings))[:10]:
        print(f'  ! {w}')
    return True


def qa_cli(path: str, code_byte: int = 2, width: int = 0, dictionary: Optional['GPTDictionary'] = None,
           tunnel: bool = False) -> int:
    paths = sorted(Path(path).glob('*.json')) if os.path.isdir(path) else [Path(path)]
    total = 0
    for p in paths:
        doc = load_doc(str(p))
        strings = doc.get('strings', [])
        is_spt = doc.get('format') == 'spt-table'
        w, lines_max = (0, 0)
        if is_spt:
            ents = [nne.SPTEntry(id=s['id'], table=1, slot=0, word=0, raw=b'', text=s.get('original', ''),
                                 kind=s.get('kind', 'message')) for s in strings]
            w, lines_max = nne.measure_layout(ents)
        w = width or w
        qa = TranslationQA(dictionary=dictionary)
        report = []
        missing = 0
        for s in strings:
            tr = s.get('translated', '')
            if not tr:
                missing += 1
                continue
            issues = qa.validate(s.get('original', ''), tr, s.get('index', 0))
            if is_spt:
                # SPT text is unwrapped for translation and re-wrapped on insert,
                # so the generic line-break / length heuristics do not apply.
                issues = [i for i in issues if not i.startswith(('Line break mismatch', 'Translation too long'))]
            if is_spt and s.get('kind') == 'message':
                wrapped = nne.wrap_text(tr, w, code_byte) if w else tr
                extra = nne.qa_entry(s.get('original', ''), wrapped, w, lines_max, code_byte, tunnel)
                if any(i.startswith('Contains untranslated Japanese') for i in issues):
                    extra = [i for i in extra if i != 'still contains Japanese']
                issues += extra
            if issues:
                report.append((entry_id(s), issues))
        total += len(report)
        if report or missing:
            print(f'{p.name}: {len(report)} lines with issues, {missing} untranslated')
            for sid, issues in report[:50]:
                print(f'  [{sid}] ' + '; '.join(dict.fromkeys(issues)))
    print(f'QA done: {total} lines with issues')
    return total


def main():
    parser = argparse.ArgumentParser(
        description='System-NNN / DDSystem / BlackCyc visual novel translation tools',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Typical System-NNN (Mugen Kairou 2) workflow:
  %(prog)s probe-exe game/mugen2.exe
  %(prog)s extract-text game/spt/ -o jp/
  %(prog)s glossary jp/ --api anthropic --charaname game/spt/charaname.xtx -d gpt_dictionary.json
  %(prog)s translate jp/ -o en/ --api anthropic -d gpt_dictionary.json --style-guide style.md
  %(prog)s qa en/
  %(prog)s insert-text game/spt/ en/ -o patch/spt/ --wrap auto
  %(prog)s nnn-config set game/ game codeByte 1     # if probe-exe says it is supported

DDSystem (.dat archives with HXB scripts):
  %(prog)s extract sin_text.dat -o extracted/
  %(prog)s extract-text extracted/ -o jp/
  ... translate / qa ...
  %(prog)s insert-text extracted/main05.hxb en/main05.json -o patched/main05.hxb
  %(prog)s repack patched/ -o sin_text_patched.dat

Other translators:
  %(prog)s export-galtransl jp/ -o galtransl/json_jp/     # GalTransl / LinguaGacha
  %(prog)s import-galtransl jp/ galtransl/json_cn/ -o en/

API keys: ANTHROPIC_API_KEY, OPENAI_API_KEY, DEEPL_API_KEY (or --api-key)
''')
    sub = parser.add_subparsers(dest='command', help='Available commands')

    p = sub.add_parser('extract', help='Extract DDP archive')
    p.add_argument('archive')
    p.add_argument('-o', '--output')
    p.add_argument('--no-decrypt', action='store_true', help='Do not decrypt HXB files')

    p = sub.add_parser('extract-text', help='Extract text from scripts (SPT/HXB/NNN)')
    p.add_argument('input', help='Script file or directory')
    p.add_argument('-o', '--output', help='Output JSON file or directory')
    p.add_argument('--format', choices=['vntools', 'vnt'], default='vntools')
    p.add_argument('--spt-key', help='Custom SPT key "xor,addXor,addInc" (default 0xFFFFFFFF,0,0)')

    p = sub.add_parser('translate', help='Translate JSON files with an LLM or DeepL')
    p.add_argument('input', help='JSON file or directory')
    p.add_argument('-o', '--output', help='Output JSON file or directory')
    p.add_argument('--api', required=True, choices=['anthropic', 'openai', 'openai-compatible', 'deepl'])
    p.add_argument('--api-key')
    p.add_argument('--model', help='Model (defaults: anthropic=claude-opus-5-5, openai=gpt-5-mini)')
    p.add_argument('--effort', default='medium', choices=['low', 'medium', 'high', 'xhigh', 'max'],
                   help='Anthropic effort level (default medium)')
    p.add_argument('--base-url', help='Server URL for openai-compatible (e.g. http://localhost:11434/v1)')
    p.add_argument('--lang', default='English', help='Target language')
    p.add_argument('-d', '--dictionary', help='gpt_dictionary.json (names, terms, character notes)')
    p.add_argument('--style-guide', help='Markdown/text file with translation rules')
    p.add_argument('--context', default='', help='Extra notes for the translator (game premise, etc.)')
    p.add_argument('--chunk-size', type=int, default=30, help='Lines per request (default 30)')
    p.add_argument('--context-lines', type=int, default=8, help='Previous lines sent as context')
    p.add_argument('--batch-api', action='store_true',
                   help='Anthropic Message Batches: half price, asynchronous (directories only)')
    p.add_argument('--overwrite', action='store_true', help='Retranslate lines that already have a translation')

    p = sub.add_parser('glossary', help='Bootstrap gpt_dictionary.json (names/terms) with an LLM')
    p.add_argument('input', help='Extracted JSON file or directory')
    p.add_argument('-d', '--dictionary', default='gpt_dictionary.json')
    p.add_argument('--api', required=True, choices=['anthropic', 'openai', 'openai-compatible'])
    p.add_argument('--api-key')
    p.add_argument('--model')
    p.add_argument('--base-url')
    p.add_argument('--lang', default='English')
    p.add_argument('--charaname', help='spt/charaname.xtx from the game (extra name list)')

    p = sub.add_parser('qa', help='Check translations (codes, encoding, line width, leftovers)')
    p.add_argument('input', help='Translated JSON file or directory')
    p.add_argument('--code-byte', type=int, choices=[1, 2], default=2)
    p.add_argument('--width', type=int, default=0, help='Line width in half-width units (default: from original)')
    p.add_argument('-d', '--dictionary')
    p.add_argument('--tunnel', action='store_true', help='Characters will be SJIS-tunneled')

    p = sub.add_parser('insert-text', help='Insert translations into scripts')
    p.add_argument('script', help='Original script file or directory')
    p.add_argument('translation', help='Translation JSON file or directory')
    p.add_argument('-o', '--output', required=True, help='Output script file or directory')
    p.add_argument('--wrap', default='auto',
                   help='SPT: line width in half-width units, "auto" (= original width) or 0 for none')
    p.add_argument('--code-byte', type=int, choices=[1, 2], default=2,
                   help='2 (default): ASCII shown full-width; 1: game set to codeByte 1 (half-width Latin)')
    p.add_argument('--max-lines', type=int, default=0, help='Warn above this many lines (default: original)')
    p.add_argument('--tunnel', metavar='SJIS_EXT_BIN',
                   help='Tunnel characters CP932 lacks into this sjis_ext.bin (for VNTextProxy)')
    p.add_argument('--names', help='JSON with name translations (gpt_dictionary.json works)')
    p.add_argument('--spt-key')

    p = sub.add_parser('export-galtransl', help='Export to GalTransl json_jp / LinguaGacha format')
    p.add_argument('input')
    p.add_argument('-o', '--output', required=True)

    p = sub.add_parser('import-galtransl', help='Import GalTransl/LinguaGacha output')
    p.add_argument('jp_json', help='Directory of extracted VNTools JSON')
    p.add_argument('translated', help='Directory of translated GalTransl JSON')
    p.add_argument('-o', '--output', required=True)

    p = sub.add_parser('migrate-json', help='Carry translations from an old (pre-2.0) SPT JSON to a new extraction')
    p.add_argument('old')
    p.add_argument('new')
    p.add_argument('-o', '--output', required=True)

    p = sub.add_parser('nnn-config', help='Read/edit init/*.xtx and init2/*.fxf engine settings')
    p.add_argument('action', choices=['show', 'set', 'decode', 'encode'])
    p.add_argument('path', help='Game folder (show/set) or a .xtx/.fxf file (decode/encode)')
    p.add_argument('args', nargs='*', help='set: <file> <key> <value>, e.g. game codeByte 1')
    p.add_argument('-o', '--output')

    p = sub.add_parser('probe-exe', help='Check which translation-friendly engine options a game exe supports')
    p.add_argument('exe')

    p = sub.add_parser('convert-format', help='Convert between VNTools and VNTranslationTools JSON')
    p.add_argument('input')
    p.add_argument('-o', '--output', required=True)
    p.add_argument('--format', choices=['vnt', 'vntools'], default='vnt')

    p = sub.add_parser('repack', help='Repack files into DDP archive')
    p.add_argument('input')
    p.add_argument('-o', '--output', required=True)
    p.add_argument('--version', type=int, choices=[2, 3], default=3)
    p.add_argument('--compress', action='store_true')

    p = sub.add_parser('analyze', help='Analyze archive structure')
    p.add_argument('archive')

    args = parser.parse_args()
    cmd = args.command

    if cmd == 'extract':
        extract_archive(args.archive, args.output or args.archive + '_extracted', decrypt=not args.no_decrypt)

    elif cmd == 'extract-text':
        ip = Path(args.input)
        if ip.is_dir():
            extract_all_text_with_format(str(ip), args.output or str(ip) + '_text', args.format, args.spt_key)
        else:
            extract_text_with_format(str(ip), args.output or str(ip.with_suffix('.json')), args.format, args.spt_key)

    elif cmd == 'translate':
        key = _api_key(args.api, args.api_key)
        if not key and args.api in ('openai', 'deepl'):
            print(f'Error: set {llm.API_KEY_ENV[args.api]} or use --api-key')
            sys.exit(1)
        dictionary = GPTDictionary(args.dictionary) if args.dictionary else None
        ip = Path(args.input)
        common = dict(api_key=key, model=args.model or '', base_url=args.base_url or '',
                      target_lang=args.lang, effort=args.effort, chunk_size=args.chunk_size,
                      context_lines=args.context_lines, dictionary=dictionary,
                      style_guide=load_style_guide(args.style_guide), notes=args.context)
        if ip.is_dir():
            out = args.output or str(ip) + '_translated'
            if args.batch_api:
                tr = make_chunk_translator(args.api, **common)
                translate_directory(str(ip), out, tr, dictionary, args.overwrite, batch_api=True)
            else:
                os.makedirs(out, exist_ok=True)
                for f in sorted(ip.glob('*.json')):
                    tr = make_chunk_translator(args.api, dict_context=f.stem, **common)
                    translate_json_file(str(f), os.path.join(out, f.name), tr, dictionary, args.overwrite)
        else:
            out = args.output or str(ip.with_name(ip.stem + '_translated.json'))
            tr = make_chunk_translator(args.api, dict_context=ip.stem, **common)
            translate_json_file(str(ip), out, tr, dictionary, args.overwrite)

    elif cmd == 'glossary':
        build_glossary_file(args.input, args.dictionary, args.api, _api_key(args.api, args.api_key),
                            args.model or '', args.base_url or '', args.lang, args.charaname)

    elif cmd == 'qa':
        d = GPTDictionary(args.dictionary) if args.dictionary else None
        qa_cli(args.input, args.code_byte, args.width, d, args.tunnel)

    elif cmd == 'insert-text':
        sp, tp = Path(args.script), Path(args.translation)
        opts = dict(wrap=args.wrap, code_byte=args.code_byte, tunnel_path=args.tunnel,
                    names_path=args.names, spt_key=args.spt_key, max_lines=args.max_lines)
        if sp.is_dir():
            os.makedirs(args.output, exist_ok=True)
            for js in sorted(tp.glob('*.json')):
                for ext in ('.spt', '.hxb', '.nnn'):
                    cand = sp / (js.stem + ext)
                    if cand.exists():
                        insert_text_cli(str(cand), str(js), os.path.join(args.output, cand.name), **opts)
                        break
        else:
            insert_text_cli(str(sp), str(tp), args.output, **opts)

    elif cmd == 'export-galtransl':
        export_galtransl(args.input, args.output)

    elif cmd == 'import-galtransl':
        import_galtransl(args.jp_json, args.translated, args.output)

    elif cmd == 'migrate-json':
        migrate_old_spt_json(args.old, args.new, args.output)

    elif cmd == 'nnn-config':
        nnn_config_cli(args)

    elif cmd == 'probe-exe':
        r = nne.probe_exe(args.exe)
        print('Engine setting keys found in exe:')
        for k, v in r['strings'].items():
            print(f'  {"yes" if v else " no"}  {k}')
        print('Imports / APIs referenced:')
        for k, v in r['imports'].items():
            if v:
                print(f'  {k}')
        print('\nRecommendations:')
        for line in r['recommendations']:
            print(f'  - {line}')

    elif cmd == 'convert-format':
        if args.format == 'vnt':
            convert_to_vnt_format(args.input, args.output)
        else:
            data = load_doc(args.input)
            if isinstance(data, list):
                doc = {'source_file': '', 'format': 'converted-from-vnt', 'string_count': len(data),
                       'strings': [{'index': i, 'id': str(i), 'name': it.get('name', ''),
                                    'original': it.get('message', ''), 'translated': it.get('translated', '')}
                                   for i, it in enumerate(data)]}
                save_doc(args.output, doc)
                print(f'Converted {len(data)} strings to VNTools format')
            else:
                print('Already in VNTools format')

    elif cmd == 'repack':
        repack_archive(args.input, args.output, args.version, args.compress)

    elif cmd == 'analyze':
        archive = DDPArchive(args.archive)
        if archive.open():
            print(f"Format: DDP{archive.version}")
            print(f"Files: {len(archive.entries)}")
            for i, entry in enumerate(archive.entries[:20]):
                packed_info = f" (packed: {entry.packed_size})" if entry.is_packed else ""
                print(f"  {i:4d}: {entry.name:30s} @ 0x{entry.offset:08X}  size: {entry.unpacked_size:8d}{packed_info}")
            if len(archive.entries) > 20:
                print(f"  ... and {len(archive.entries) - 20} more")
    else:
        parser.print_help()


def nnn_config_cli(args):
    if args.action == 'show':
        for fname in sorted({k[0] for k in nne.TRANSLATION_KEYS}):
            path = nne.find_config(args.path, fname)
            if not path:
                print(f'{fname}: not found (init/{fname}.xtx or init2/{fname}.fxf)')
                continue
            cfg = nne.parse_config(nne.read_config_text(path))
            print(f'{path}:')
            for f2, key, desc in nne.TRANSLATION_KEYS:
                if f2 == fname:
                    print(f'  {key:22s} = {cfg.get(key, "(unset)"):10s}  {desc}')
        if os.path.isdir(os.path.join(args.path, 'init2')):
            print('\nNote: init2/ exists, so the engine reads the .fxf files there, not init/*.xtx.')
    elif args.action == 'set':
        if len(args.args) != 3:
            print('usage: nnn-config set <game_dir> <file> <key> <value>   e.g. game codeByte 1')
            sys.exit(1)
        fname, key, value = args.args
        path = nne.find_config(args.path, fname)
        if not path:
            path = os.path.join(args.path, 'init', fname + '.xtx')
            os.makedirs(os.path.dirname(path), exist_ok=True)
            text = ''
        else:
            text = nne.read_config_text(path)
            bak = path + '.bak'
            if not os.path.exists(bak):
                with open(path, 'rb') as src, open(bak, 'wb') as dst:
                    dst.write(src.read())
        nne.write_config_text(path, nne.set_config_value(text, key, value))
        print(f'{path}: {key} = {value}')
    elif args.action == 'decode':
        out = args.output or os.path.splitext(args.path)[0] + '.xtx'
        text = nne.read_config_text(args.path)
        with open(out, 'w', encoding='utf-8', newline='') as f:
            f.write(text)
        print(f'Decoded to {out} (UTF-8)')
    elif args.action == 'encode':
        out = args.output or os.path.splitext(args.path)[0] + '.fxf'
        with open(args.path, 'r', encoding='utf-8', newline='') as f:
            nne.write_config_text(out, f.read())
        print(f'Encoded to {out}')


def extract_text_with_format(script_path: str, output_path: str, format: str = "vntools",
                             spt_key: Optional[str] = None) -> bool:
    """Extract translatable text from a script (auto-detects SPT/HXB/NNN)."""
    with open(script_path, 'rb') as f:
        data = f.read()

    if is_nnn_file(data):
        script = NNNScript()
    elif nne.is_spt_data(data, spt_key):
        script = SPTScript(spt_key)
    elif len(data) >= 7 and (data[:4] == b'DDSx' or data[:4] == b'DDWu'):
        if data[:4] == b'DDWu':
            data = fix_hxb_signature(data)
            data = decrypt_hxb(data)
        script = HXBScript()
    else:
        print(f"{script_path}: unknown script format")
        return False

    if not script.parse(data):
        print(f"{script_path}: failed to parse")
        return False

    if isinstance(script, NNNScript):
        script.export_strings(output_path, format)
    elif isinstance(script, SPTScript):
        script.export_strings(output_path, os.path.basename(script_path))
        if format == 'vnt':
            convert_to_vnt_format(output_path, output_path)
    else:
        script.export_strings(output_path)
        if format == 'vnt':
            convert_to_vnt_format(output_path, output_path)
    print(f"{os.path.basename(script_path)}: {len(script.strings)} strings -> {output_path}")
    return True


def extract_all_text_with_format(input_dir: str, output_dir: str, format: str = "vntools",
                                 spt_key: Optional[str] = None) -> bool:
    """Extract text from all scripts in a directory."""
    os.makedirs(output_dir, exist_ok=True)
    files = sorted(list(Path(input_dir).glob('*.hxb')) + list(Path(input_dir).glob('*.spt'))
                   + list(Path(input_dir).glob('*.nnn')))
    print(f"Found {len(files)} script files")
    for script_path in files:
        extract_text_with_format(str(script_path), str(Path(output_dir) / (script_path.stem + '.json')),
                                 format, spt_key)
    return True


if __name__ == '__main__':
    main()
