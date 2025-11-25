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

### Core Features
- Extract DDP2/DDP3 archives
- Decompress SHS-compressed files
- Decrypt HXB/SPT script files
- Parse NNN dev scripts
- Extract translatable text strings to JSON
- **Translate using LLM APIs** (OpenAI, Anthropic, DeepL, local LLMs)
- Export in VNTranslationTools-compatible format
- Reinsert translated text
- Repack archives for creating translation patches

### Advanced Translation Features ⭐ NEW
- **SJIS Tunneling** - Map unsupported characters to unused Shift-JIS code points (solves punctuation display issues in System-NNN games)
- **GPT Dictionary System** - Maintain consistent terminology and character name translations
  - Pre-translation hints (Japanese term recognition)
  - Post-translation enforcement (required translations)
  - Conditional translations (context-specific)
  - Character background/personality contexts
- **Translation QA** - Automated quality validation
  - Detects repeated words, unbalanced punctuation
  - Flags untranslated Japanese characters
  - Checks line break consistency
  - Validates translation length
  - Dictionary compliance checking
- **Character Name Management** - Reusable character name database
- **Word Wrapping** - Automatic line breaking for monospace/proportional fonts
- **Checkpoint System** - Save and resume interrupted translations
- **Translation Caching** - Avoid re-translating identical strings

## Installation

Requires Python 3.7+

```bash
# Clone the repository
git clone https://github.com/tobidashite/VNTools.git
cd VNTools

# No additional dependencies required - uses only standard library
```

## Web GUI 🎨

VNTools now includes a beautiful web-based GUI with full Tailwind styling!

### Quick Start

```bash
# Install Flask dependencies
pip install -r requirements.txt

# Start the web server
python3 app.py
```

Then open your browser to http://localhost:5000

### GUI Features

The web interface provides access to ALL VNTools functionality:

- **📦 Archives Tab**
  - Extract DDP2/DDP3 archives with drag-and-drop
  - Repack modified files back to archives
  - Analyze archive contents and compression ratios

- **📝 Scripts Tab**
  - Decrypt HXB/SPT/NNN scripts
  - Encrypt text files back to game format
  - Live preview of decrypted content

- **🌐 Text Extraction Tab**
  - Extract translatable strings to JSON
  - Insert translated text back into scripts
  - Preview extracted text

- **🤖 AI Translation Tab**
  - Translate using OpenAI, Anthropic, or DeepL
  - SJIS Tunneling support
  - GPT Dictionary integration
  - Automated Translation QA
  - Real-time progress tracking

- **⚙️ Advanced Tools Tab**
  - SJIS Tunneling encoder/decoder
  - Word wrapping with configurable width
  - Format conversion (VNT compatibility)
  - Character name management

- **❓ Help Tab**
  - Complete documentation
  - Quick start guide
  - Pro tips and best practices

### Why Use the GUI?

- **User-Friendly**: No command-line experience needed
- **Visual**: See previews and results in real-time
- **Drag & Drop**: Easy file uploads
- **Modern**: Beautiful Tailwind-inspired design
- **Complete**: Every CLI feature available in the GUI

## CLI Usage

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

## Advanced Features Usage

### SJIS Tunneling (Fixing Punctuation Display Issues)

The SJIS tunneling system solves the punctuation display problems reported in System-NNN games like Mugen Kairou 2. It maps unsupported characters (Western punctuation, accents) to unused Shift-JIS code points.

**Python API Usage:**
```python
from systemnnn_tools import SJISTunnelEncoder

# Create encoder
encoder = SJISTunnelEncoder()

# Encode text with tunneling
japanese_text = "こんにちは"
english_text = "Hello! How's it going?"

# English punctuation will be tunneled
encoded = encoder.encode(english_text)

# Save mapping for game runtime (use with VNTextProxy or similar)
encoder.save_mapping("sjis_ext.bin")

# Decode back
decoded = encoder.decode(encoded)

# Get statistics
stats = encoder.get_stats()
print(f"Mapped {stats['mapped_chars']} characters")
print(f"{stats['available_slots']} slots remaining")
```

**What it does:**
- Maps unsupported characters to unused SJIS byte ranges (0x81-0x9F, 0xE0-0xEC)
- Generates `sjis_ext.bin` mapping file (compatible with VNTextProxy)
- Supports ~4000+ character mappings
- Preserves standard SJIS characters unchanged

### GPT Dictionary System

Maintain consistent translations of character names, terminology, and context-specific phrases.

**Setup (`gpt_dictionary.json`):**
```json
{
  "pre_translation": {
    "神学校": "Theological school/seminary (important location)",
    "エルバート": "Elbert (male protagonist, cynical personality)"
  },
  "post_translation": {
    "エルバート": "Elbert",
    "レオニード": "Leonid",
    "神学校": "Seminary"
  },
  "conditional": {
    "chapter1": {
      "教室": "classroom"
    },
    "chapter5": {
      "教室": "lecture hall"
    }
  },
  "character_contexts": {
    "Elbert": "Male protagonist, cynical theology student, has a dark past",
    "Leonid": "Elbert's mentor, strict but caring priest"
  }
}
```

**Python API Usage:**
```python
from systemnnn_tools import GPTDictionary

# Load dictionary
dictionary = GPTDictionary('gpt_dictionary.json')

# Add entries programmatically
dictionary.add_character_context("Elbert", "Male protagonist, theology student")
dictionary.add_post_translation("エルバート", "Elbert")
dictionary.add_conditional("chapter1", "教室", "classroom")

# Get prompt context for LLM
context = dictionary.get_context_prompt(context="chapter1")
print(context)
# Output includes character backgrounds and required translations

# Apply post-processing (enforce dictionary terms)
translated = "エルバート went to the seminary"
fixed = dictionary.apply_post_processing(translated)
# Result: "Elbert went to the seminary"

dictionary.save()
```

### Translation QA (Quality Assurance)

Automatically detect common translation errors.

**Python API Usage:**
```python
from systemnnn_tools import TranslationQA, GPTDictionary

# Create QA validator
dictionary = GPTDictionary('gpt_dictionary.json')
qa = TranslationQA(dictionary=dictionary)

# Validate translations
original = "エルバートは神学校に行った。"
translated = "Elbert Elbert Elbert went to school."

issues = qa.validate(original, translated, index=0)
for issue in issues:
    print(f"⚠ {issue}")
# Output:
# ⚠ Repeated word: 'Elbert'
# ⚠ Missing required translation: 神学校 → Seminary

# Generate full report
qa.validate(original, translated, index=0)
qa.validate(original2, translated2, index=1)
# ... validate more strings ...

print(qa.generate_report())
# Outputs formatted report with all issues

qa.clear()  # Clear for next batch
```

**Checks performed:**
- Repeated words (3+ consecutive)
- Untranslated Japanese characters
- Unbalanced punctuation: `() [] {} 「」 『』`
- Line break count mismatches
- Translation length (too long/short)
- Empty translations
- Dictionary compliance

### Character Name Management

Maintain a reusable database of character name translations.

**Setup (`names.json`):**
```json
{
  "エルバート": "Elbert",
  "レオニード": "Leonid",
  "マリア": "Maria",
  "セシル": "Cecil"
}
```

**Python API Usage:**
```python
from systemnnn_tools import CharacterNameManager

# Load name database
names = CharacterNameManager('names.json')

# Add names
names.add_name("エルバート", "Elbert")
names.add_name("レオニード", "Leonid")

# Get translation
translated_name = names.get_translation("エルバート")
# Returns: "Elbert"

# Extract names from VNT-format JSON
with open('translations.json') as f:
    data = json.load(f)
names.extract_names_from_json(data)  # Extracts all "name" fields

# Auto-fill translations in JSON data
data = names.auto_translate_names(data)

names.save()
```

### Word Wrapping

Prevent text overflow in VN text boxes.

**Python API Usage:**
```python
from systemnnn_tools import WordWrapper

# Monospace font (typical for Japanese VNs)
wrapper = WordWrapper(chars_per_line=40, mode='monospace')

long_text = "This is a very long line of text that needs to be wrapped to fit within the game's text box constraints."
wrapped = wrapper.wrap(long_text)
print(wrapped)
# Output:
# This is a very long line of text
# that needs to be wrapped to fit within
# the game's text box constraints.

line_count = wrapper.calculate_line_count(wrapped)
print(f"Text occupies {line_count} lines")

# Proportional font (for English translations)
wrapper_prop = WordWrapper(chars_per_line=50, mode='proportional')
wrapped_prop = wrapper_prop.wrap(long_text)
# Uses character width estimates for better wrapping
```

### Checkpoint System

Save and resume translation progress.

**Python API Usage:**
```python
from systemnnn_tools import CheckpointManager

checkpoint_mgr = CheckpointManager('.checkpoints')

# Save checkpoint during translation
project_data = {
    'completed_files': ['main01.json', 'main02.json'],
    'current_file': 'main03.json',
    'current_index': 150,
    'translation_cache': { ... }
}
checkpoint_mgr.save_checkpoint('shingakkou_translation', project_data)

# Resume from checkpoint
data = checkpoint_mgr.load_checkpoint('shingakkou_translation')
if data:
    print(f"Resuming from file: {data['current_file']}")
    # Continue translation...

# List all checkpoints
checkpoints = checkpoint_mgr.list_checkpoints()
for cp in checkpoints:
    print(f"{cp['project']}: {cp['timestamp']}")

# Delete after completion
checkpoint_mgr.delete_checkpoint('shingakkou_translation')
```

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
| [VNTranslationTools](https://github.com/arcusmaximus/VNTranslationTools) | Alternative script extractor/patcher with Excel workflow |
| [VNTextPatch](https://github.com/rafael-vasconcellos/VNTextPatch-net8) | .NET 8 multi-engine tool (24+ engines, SJIS tunneling) |
| [vnilla](https://github.com/erengy/vnilla) | Minimal markup language for VN translation projects |
| [GalTransl](https://github.com/GalTransl/GalTransl) | Advanced LLM translation with GPT dictionary & QA system |
| [SoraTranslator](https://github.com/Immortalyzy/SoraTranslator) | VN translation with spreadsheet UI and token optimization |
| [py3TranslateLLM](https://github.com/gdiaz384/py3TranslateLLM) | LLM translation for spreadsheets |
| [LunaTranslator](https://github.com/HIllya51/LunaTranslator) | Real-time translation while playing |
| [GARbro](https://github.com/morkt/GARbro) | Universal VN resource browser |

## Thanks

### Core References
- [GARbro](https://github.com/morkt/GARbro) by morkt - Format specifications and compression algorithms
- [systemNNN_support](https://github.com/tinyan/systemNNN_support) by tinyan - Engine tools and format documentation (DWQ, VAW, MFT formats)
- [VNTranslationTools](https://github.com/arcusmaximus/VNTranslationTools) by arcusmaximus - NNN/SPT format reference
- [py3TranslateLLM](https://github.com/gdiaz384/py3TranslateLLM) by gdiaz384 - Translation workflow inspiration

### Advanced Features Inspiration
- [VNTextPatch](https://github.com/rafael-vasconcellos/VNTextPatch-net8) by rafael-vasconcellos - SJIS tunneling technique, word wrapping, character name management
- [GalTransl](https://github.com/GalTransl/GalTransl) by GalTransl team - GPT dictionary system, translation QA, checkpoint system
- [SoraTranslator](https://github.com/Immortalyzy/SoraTranslator) by Immortalyzy - Token optimization, integration patterns
- [vnilla](https://github.com/erengy/vnilla) by erengy - Minimal markup format concepts

### Community & Research
- [Fuwanovel Forums](https://forums.fuwanovel.moe/) - System-NNN/DDSystem research and discussions
- [Kungal Galgame Community](https://www.kungal.com/) - Chinese VN translation community insights
- PIL/SLASH/BlackCyc/CYCLET - For creating amazing visual novels

## License

MIT License
