# VNTools - SystemNNN Visual Novel Tools

Tools for extracting, translating, and repacking visual novels that use the SystemNNN/PIL/SLASH/CYCLET/BlackCyc engine.

## Supported Formats

- **DDP2/DDP3 Archives** - Resource archives used by SystemNNN games
- **HXB Scripts** (DDSxHXB) - Script files containing game text (UTF-16LE encoded)

## Tested Games

- 神学校 -Noli me tangere- (Shingakkou)
- Other PIL/SLASH/BlackCyc titles using SystemNNN

## Features

- Extract DDP2/DDP3 archives
- Decompress SHS-compressed files
- Decrypt HXB script files
- Extract translatable text strings to JSON
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
# Extract text from all HXB scripts in a directory
python3 systemnnn_tools.py extract-text extracted/ -o translations/

# Extract text from a single script
python3 systemnnn_tools.py extract-text extracted/main05.hxb -o main05.json
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

Fill in the `"translated"` field for each string in the JSON files. You can use:
- Manual translation
- DeepL API
- Google Translate API
- Any other translation service

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

### HXB Script Format

- Signature: `DDSxHXB` (stored as `DDWuHXB` in archives)
- Text encoding: UTF-16LE
- Encryption: XOR with key derived from file length

### Compression

Uses ShsCompression (LZSS variant) - same as GARbro implementation.

## Credits

- Based on format specifications from [GARbro](https://github.com/morkt/GARbro)
- [SystemNNN source code](https://github.com/tinyan/SystemNNN)

## License

MIT License
