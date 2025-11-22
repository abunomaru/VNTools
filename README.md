# VNTools

Personal collection of reverse engineering tools for Japanese visual novel translation patching.

## Supported Engines

This toolkit supports games built on the **System-NNN** family of visual novel engines, developed by PIL/SLASH and related brands.

### Engine Variants

| Engine | Developer | Example Games |
|--------|-----------|---------------|
| **System-NNN** | PIL/SLASH | Mugen Kairou series |
| **DDSystem** | CYCLET | Shingakkou -Noli me tangere- |
| **BlackCyc** | BLACK CYC | Various darker-themed titles |

## Supported Formats

### Script Formats (Currently Implemented)

| Format | Signature | Encoding | Encryption | Description |
|--------|-----------|----------|------------|-------------|
| **HXB** | `DDSxHXB` | UTF-16LE | XOR (length-based key) | Main script format for DDSystem/System-NNN |
| **SPT** | `SPTHEADER0` | Shift-JIS | XOR 0xFF | Script format for newer BlackCyc games |
| **NNN** | `--MESSAGEDATA` | Shift-JIS | None | Dev script format (VNTranslationTools compatible) |

### Archive Formats (Currently Implemented)

| Format | Signature | Description |
|--------|-----------|-------------|
| **DDP2** | `DDP2` | Older resource archive format |
| **DDP3** | `DDP3` | Main resource archive format with UTF-16LE filenames |

### Additional System-NNN Formats (Reference)

These formats are used by System-NNN games but not yet implemented in this toolkit:

| Format | Extension | Description |
|--------|-----------|-------------|
| **DWQ** | `.gtb` + `.gpk` | Image archives (BMP/JPEG with optional masks) |
| **VAW** | `.vtb` + `.vpk` | Voice/sound effect archives |
| **WGQ** | `.wgq` | BGM files (64-byte header + OGG data) |
| **MFT** | `.mft` | Bitmap font files (2/4/8-bit grayscale, Shift-JIS) |
| **XTX/FXF** | `.xtx`/`.fxf` | Encrypted script variants (XOR 0xFF) |

#### DWQ Image Pack Types

| Type | Description |
|------|-------------|
| 1 | Compressed BMP |
| 2 | Standard BMP with alpha mask |
| 3 | Compressed BMP with alpha mask |
| 5 | JPEG |
| 7 | JPEG with alpha mask |
| 8 | PNG (some versions) |

## Tested Games

- 神学校 -Noli me tangere- (Shingakkou) - DDSystem
- 夢幻廻廊2～螺旋～ (Mugen Kairou 2) - System-NNN
- Other PIL/SLASH/BlackCyc/CYCLET titles

## Features

- Extract DDP2/DDP3 archives
- Decompress SHS-compressed files
- Decrypt HXB/SPT script files
- Parse NNN dev scripts
- Extract translatable text strings to JSON
- **Translate using LLM APIs** (OpenAI, Anthropic, DeepL, local LLMs)
- Export in VNTranslationTools-compatible format
- Reinsert translated text
- Repack archives for creating translation patches

## Installation

Requires Python 3.7+

```bash
# Clone the repository
git clone https://github.com/tobidashite/VNTools.git
cd VNTools

# No additional dependencies required - uses only standard library
```

## Usage

### 1. Extract Archive

```bash
# Extract all files from a DDP archive
python3 systemnnn_tools.py extract sin_text.dat -o extracted/

# Extract without decrypting HXB files
python3 systemnnn_tools.py extract sin_text.dat -o extracted/ --no-decrypt
```

### 2. Extract Text for Translation

```bash
# Extract text from all scripts in a directory (auto-detects HXB/SPT)
python3 systemnnn_tools.py extract-text extracted/ -o translations/

# Extract text from a single HXB script
python3 systemnnn_tools.py extract-text extracted/main05.hxb -o main05.json

# Extract text from SPT scripts (Mugen Kairou 2, etc.)
python3 systemnnn_tools.py extract-text spt/ -o translations/
```

This creates JSON files with all translatable strings:

```json
{
  "source_file": "",
  "format": "utf-16le",
  "string_count": 728,
  "strings": [
    {
      "index": 0,
      "offset": 256,
      "original": "レオニードからは、今日は来なくていいと言われている。",
      "translated": "",
      "context": ""
    }
  ]
}
```

### 3. Translate

You can translate manually or use the built-in LLM translation:

```bash
# Translate with OpenAI GPT-4
python3 systemnnn_tools.py translate translations/ -o translated/ --api openai

# Translate with Anthropic Claude
python3 systemnnn_tools.py translate translations/ -o translated/ --api anthropic

# Translate with DeepL
python3 systemnnn_tools.py translate translations/ -o translated/ --api deepl --lang Portuguese

# Translate with local LLM (Ollama, LM Studio, etc.)
python3 systemnnn_tools.py translate translations/ -o translated/ --api openai-compatible --base-url http://localhost:11434/v1

# Translate a single file
python3 systemnnn_tools.py translate main05.json -o main05_translated.json --api openai
```

**API Keys**: Set via environment variables or `--api-key`:
- `OPENAI_API_KEY` - OpenAI
- `ANTHROPIC_API_KEY` - Anthropic
- `DEEPL_API_KEY` - DeepL

Or translate manually by filling in the `"translated"` field for each string in the JSON files.

### 4. Insert Translations

```bash
# Insert translated text back into HXB script
python3 systemnnn_tools.py insert-text extracted/main05.hxb translations/main05.json -o patched/main05.hxb
```

### 5. Repack Archive

```bash
# Create new archive with patched files
python3 systemnnn_tools.py repack patched/ -o sin_text_patched.dat

# With compression (may increase load time)
python3 systemnnn_tools.py repack patched/ -o sin_text_patched.dat --compress
```

### Analyze Archive

```bash
# View archive structure without extracting
python3 systemnnn_tools.py analyze sin_text.dat
```

## Translation Workflow

1. **Backup original files**
2. **Extract**: `python3 systemnnn_tools.py extract archive.dat -o extracted/`
3. **Extract text**: `python3 systemnnn_tools.py extract-text extracted/ -o translations/`
4. **Translate** JSON files (fill `"translated"` fields)
5. **Insert**: For each script file, run `insert-text`
6. **Repack**: `python3 systemnnn_tools.py repack patched/ -o archive_patched.dat`
7. **Replace** original archive with patched version

## Technical Details

### Game Directory Structure

System-NNN games typically organize assets in these directories:

```
game/
├── ev/          # Event CGs (DWQ format)
├── bg/          # Background images (DWQ format)
├── ta/          # Character sprites/textures (DWQ format)
├── sys/         # System graphics (DWQ format)
│   ├── sm/      # Small system images
│   └── sc/      # Screen images
├── se/          # Sound effects (VAW format)
├── bgm/         # Background music (WGQ/OGG format)
├── cdwave/      # Voice files (VAW format)
├── *.dat        # DDP archives containing scripts and resources
└── *.mft        # Font files
```

### DDP3 Archive Format

```
Offset  Size  Description
0x00    4     Signature "DDP3"
0x04    4     Header size (0x20)
0x08    4     Data section offset
0x0C    20    Reserved
0x20    256   Index section
0x120+  var   File entries (variable length)
        var   File data (compressed)
```

File entries contain UTF-16LE encoded filenames with variable-length headers.

### HXB Script Format

- Signature: `DDSxHXB` (stored as `DDWuHXB` in archives, encrypted)
- Text encoding: UTF-16LE
- Encryption: XOR with key derived from file length
- Contains dialogue, choices, and game logic

### SPT Script Format

- Signature: `SPTHEADER0` at offset 0x30 (after XOR decryption)
- Text encoding: Shift-JIS
- Encryption: XOR 0xFF (simple byte-wise XOR)
- Same encryption as XTX/FXF format
- Used by: Mugen Kairou 2 and similar BlackCyc games

### DWQ Image Format

Image archives consist of paired files:
- `.gtb` - Table file containing file index and metadata
- `.gpk` - Pack file containing compressed image data

Each image entry has a 64-byte ASCII header specifying the pack type (compression method).

### VAW Audio Format

Voice/sound archives consist of paired files:
- `.vtb` - Table file with 12-byte entries (8-byte filename + 4-byte offset)
- `.vpk` - Pack file containing audio data (WAV or OGG)

### MFT Font Format

```
Offset  Size  Description
0x00    3     Signature "MFT"
0x20    3     Font size (ASCII digits)
0x30    1     Bit depth (2, 4, or 8-bit per pixel)
0x40+   var   Character bitmap data (Shift-JIS order)
```

Characters are rendered as anti-aliased grayscale bitmaps covering the Shift-JIS character set (approximately 9,024 characters).

### Compression

Uses SHS Compression (LZSS variant) - same as GARbro implementation. Features:
- Sliding window up to 8191 bytes
- Extended literal count encodings
- Back-reference with overlap support

### VNTranslationTools Compatibility

Export to VNTranslationTools format for use with py3TranslateLLM:

```bash
# Extract in VNT format
python3 systemnnn_tools.py extract-text scripts/ -o translations/ --format vnt

# Convert existing JSON to VNT format
python3 systemnnn_tools.py convert-format input.json -o output.json --format vnt
```

VNT format structure:
```json
[
  {"name": "Character", "message": "Dialogue text"},
  {"message": "Narration without speaker"}
]
```

## Related Tools

| Tool | Purpose |
|------|---------|
| [VNTranslationTools](https://github.com/arcusmaximus/VNTranslationTools) | Alternative script extractor/patcher |
| [py3TranslateLLM](https://github.com/gdiaz384/py3TranslateLLM) | LLM translation for spreadsheets |
| [LunaTranslator](https://github.com/HIllya51/LunaTranslator) | Real-time translation while playing |
| [GARbro](https://github.com/morkt/GARbro) | Universal VN resource browser |

## Thanks

- [GARbro](https://github.com/morkt/GARbro) by morkt - Format specifications and compression algorithms
- [systemNNN_support](https://github.com/tinyan/systemNNN_support) by tinyan - Engine tools and format documentation (DWQ, VAW, MFT formats)
- [VNTranslationTools](https://github.com/arcusmaximus/VNTranslationTools) by arcusmaximus - NNN/SPT format reference
- [py3TranslateLLM](https://github.com/gdiaz384/py3TranslateLLM) by gdiaz384 - Translation workflow inspiration
- PIL/SLASH/BlackCyc/CYCLET - For creating amazing visual novels

## License

MIT License
