#!/usr/bin/env python3
"""
SystemNNN/PIL/SLASH Visual Novel Tools
Supports DDP2/DDP3 archives and HXB script files

Tools for:
- Extracting DDP2/DDP3 archives
- Parsing HXB scripts and extracting translatable text (UTF-16LE)
- Reinserting translated text into HXB scripts
- Repacking DDP archives

Based on GARbro's format specifications and reverse engineering

Tested with: Shingakkou (神学校 -Noli me tangere-)
"""

import struct
import os
import sys
import json
import argparse
from pathlib import Path
from typing import List, Dict, Tuple, Optional, BinaryIO
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
    """Extract translatable text from an HXB script."""
    print(f"Parsing script: {script_path}")

    with open(script_path, 'rb') as f:
        data = f.read()

    script = HXBScript()
    if not script.parse(data):
        print("Failed to parse script")
        return False

    print(f"Found {len(script.strings)} text strings")
    script.export_strings(output_path)
    print(f"Exported to: {output_path}")
    return True


def extract_all_text(input_dir: str, output_dir: str) -> bool:
    """Extract text from all HXB scripts in a directory."""
    os.makedirs(output_dir, exist_ok=True)

    hxb_files = list(Path(input_dir).glob('*.hxb'))
    print(f"Found {len(hxb_files)} HXB script files")

    total_strings = 0
    for hxb_path in hxb_files:
        json_path = Path(output_dir) / (hxb_path.stem + '.json')

        with open(hxb_path, 'rb') as f:
            data = f.read()

        script = HXBScript()
        if script.parse(data):
            script.export_strings(str(json_path))
            total_strings += len(script.strings)
            print(f"  {hxb_path.name}: {len(script.strings)} strings")

    print(f"\nTotal: {total_strings} strings extracted")
    return True


def insert_text(script_path: str, translation_path: str, output_path: str) -> bool:
    """Insert translated text back into an HXB script."""
    print(f"Loading script: {script_path}")

    with open(script_path, 'rb') as f:
        data = f.read()

    script = HXBScript()
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

  # Insert translations and create patched scripts
  %(prog)s insert-text extracted/main05.hxb translations/main05.json -o patched/main05.hxb

  # Repack archive
  %(prog)s repack patched/ -o archive_patched.dat

  # Analyze archive
  %(prog)s analyze archive.dat
'''
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Extract command
    extract_parser = subparsers.add_parser('extract', help='Extract DDP archive')
    extract_parser.add_argument('archive', help='Path to DDP archive')
    extract_parser.add_argument('-o', '--output', help='Output directory')
    extract_parser.add_argument('--no-decrypt', action='store_true', help='Do not decrypt HXB files')

    # Extract text command
    extract_text_parser = subparsers.add_parser('extract-text', help='Extract text from HXB scripts')
    extract_text_parser.add_argument('input', help='HXB file or directory')
    extract_text_parser.add_argument('-o', '--output', help='Output JSON file or directory')

    # Insert text command
    insert_parser = subparsers.add_parser('insert-text', help='Insert translated text into HXB')
    insert_parser.add_argument('script', help='Original HXB script')
    insert_parser.add_argument('translation', help='Translation JSON file')
    insert_parser.add_argument('-o', '--output', required=True, help='Output HXB file')

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
        if input_path.is_dir():
            output = args.output or str(input_path) + '_text'
            extract_all_text(str(input_path), output)
        else:
            output = args.output or str(input_path.with_suffix('.json'))
            extract_text(str(input_path), output)

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


if __name__ == '__main__':
    main()
