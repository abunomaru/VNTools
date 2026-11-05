# VNTools

Tools for translating Japanese visual novels built on the **System-NNN** family of engines (PIL/SLASH, BlackCyc, CYCLET, …): unpack archives, extract script text, machine-translate it with context, and patch it back into the game.

## Supported engines and formats

| Engine | Developer | Example games |
|--------|-----------|---------------|
| **System-NNN** | PIL/SLASH, BlackCyc | Mugen Kairou 2 ~Rasen~, Yami no Koe series |
| **DDSystem** | CYCLET | Shingakkou -Noli me tangere- |

| Format | What it is | Status |
|--------|-----------|--------|
| **SPT** (`spt/*.spt`) | System-NNN compiled scripts, CP932, XOR-encrypted | extract / insert (any text length) |
| **HXB** (`DDSxHXB`) | DDSystem scripts, UTF-16LE | extract / insert |
| **NNN** (`--MESSAGEDATA`) | System-NNN dev scripts | extract / insert |
| **DDP2 / DDP3** (`*.dat`) | DDSystem archives | extract / repack |
| **XTX / FXF** (`init/*.xtx`, `init2/*.fxf`) | engine settings (fonts, text mode, layout) | read / edit |

Tested on 夢幻廻廊2～螺旋～ (Mugen Kairou 2, System-NNN) and 神学校 -Noli me tangere- (DDSystem).

## Installation

Requires Python 3.9+.

```bash
git clone https://github.com/abunomaru/VNTools.git
cd VNTools
pip install -r requirements.txt   # only needed for the web GUI and --api anthropic
```

The command-line tool itself uses only the Python standard library.

## Quick start: System-NNN (Mugen Kairou 2)

```bash
# 0. See which text options this game's exe supports (see "Getting English to display well")
python3 systemnnn_tools.py probe-exe game/mugen2.exe

# 1. Extract all messages and choices to JSON (one file per script)
python3 systemnnn_tools.py extract-text game/spt/ -o jp/

# 2. Build a glossary of names and terms, then review/edit it
python3 systemnnn_tools.py glossary jp/ --api anthropic \
    --charaname game/spt/charaname.xtx -d gpt_dictionary.json

# 3. Translate with context (resumable; progress is saved after every chunk)
python3 systemnnn_tools.py translate jp/ -o en/ --api anthropic \
    -d gpt_dictionary.json --style-guide style.md

# 4. Check the result
python3 systemnnn_tools.py qa en/ -d gpt_dictionary.json

# 5. Write patched scripts (wraps lines to the game's text box)
python3 systemnnn_tools.py insert-text game/spt/ en/ -o patch/spt/ --names gpt_dictionary.json
```

Copy `patch/spt/*.spt` over the game's `spt/` folder (keep a backup).

## Getting English to display well (System-NNN)

The System-NNN engine source is public ([tinyan/SystemNNN](https://github.com/tinyan/SystemNNN)). Its message renderer explains the problems people hit with Mugen Kairou 2:

- **Wide letter spacing.** In the default text mode (`codeByte 2`) every character gets one full-width cell, and each ASCII byte is converted to its full-width form (`a` → `ａ`). Latin text therefore looks spaced out, and only about half as many letters fit on a line as you'd expect.
- **No automatic wrapping.** The engine breaks lines only where the script contains a newline, so the patch has to wrap every message itself. `insert-text` does this, measuring the box width from the original Japanese lines.
- **`#` is a command prefix.** `#姓`/`#名` insert the player's name, `#［…#］` is ruby, `#強` is emphasis, and `#０`–`#９` are colors. A stray `#` in a translation breaks the line, so the encoder keeps codes copied from the original and turns any other `#` into `＃`.

There are three ways to handle this, from easiest to most involved:

1. **`codeByte 1` (built into newer engine builds).** In single-byte mode the engine draws ASCII half-width with an ANSI font (Consolas/Courier by default, or `defaultFont`). Run `probe-exe` to see whether the exe reads the `codeByte` key. If it does:
   ```bash
   python3 systemnnn_tools.py nnn-config set game/ game codeByte 1
   python3 systemnnn_tools.py nnn-config set game/ game defaultFont "Segoe UI"   # optional
   python3 systemnnn_tools.py insert-text game/spt/ en/ -o patch/spt/ --code-byte 1 --names gpt_dictionary.json
   ```
   Twice as many letters fit on each line. This mode is ASCII only: speaker names must be translated, and the encoder replaces smart quotes, dashes and accents with ASCII equivalents.
2. **Keep full-width cells** (`--code-byte 2`, the default). This works on every build. Lines are short (Mugen Kairou 2 fits 20 cells × 3 lines), so ask the translator for concise English (see the style guide below). `insert-text` warns about every message that needs more lines than the window has.
3. **VNTextProxy + SJIS tunneling.** Use this for characters CP932 doesn't have (é, —, …) and for custom fonts. `--tunnel patch/sjis_ext.bin` writes the same mapping format as arcusmaximus' VNTextPatch. Put `sjis_ext.bin` and a [VNTextProxy](https://github.com/arcusmaximus/VNTranslationTools) DLL next to the exe. A Fuwanovel thread on Mugen Kairou 2 reports that this combination with a custom font gave the best result so far. For builds with a Direct2D renderer (`useDirect2D`), [font_prop](https://github.com/louisbui63/font_prop) is a `d2d1.dll` proxy that proportionalizes the font.

`nnn-config show game/` lists the settings that matter (font, `codeByte`, `fontSize`, `nextX`/`nextY`, `windowMessageNumber`, …). If the game ships an `init2/` folder, the engine reads the encrypted `init2/*.fxf` instead of `init/*.xtx`. `nnn-config set` edits whichever file the engine will actually load and keeps a `.bak`.

## AI translation

```bash
python3 systemnnn_tools.py translate jp/ -o en/ --api anthropic            # Claude (default claude-opus-5-5)
python3 systemnnn_tools.py translate jp/ -o en/ --api anthropic --model claude-sonnet-5-5   # cheaper
python3 systemnnn_tools.py translate jp/ -o en/ --api anthropic --batch-api                 # 50% price, async
python3 systemnnn_tools.py translate jp/ -o en/ --api openai --model <model>
python3 systemnnn_tools.py translate jp/ -o en/ --api openai-compatible \
    --base-url http://localhost:11434/v1 --model qwen3:14b                  # Ollama / LM Studio / llama.cpp
python3 systemnnn_tools.py translate jp/ -o pt/ --api deepl --lang Portuguese
```

What it does differently from line-by-line MTL:

- **Chunks with context.** It sends 30 lines per request (`--chunk-size`), each tagged with its speaker, plus the 8 preceding lines (`--context-lines`) with their translations. Japanese leaves subjects out, so the model needs the scene to get pronouns and gender right.
- **Structured output.** The model returns JSON keyed by line id. If an id is missing or the JSON is bad, the chunk is split and retried, so lines can't shift or merge.
- **Glossary and style guide in a cached system prompt.** `gpt_dictionary.json` holds required renderings, character notes and term hints, and `conditional` entries can be keyed by script name. `--style-guide` takes your team's rules: honorifics, quote style, tone, line length.
- **Resumable.** Progress is saved after each chunk, and lines that already have a translation are skipped unless you pass `--overwrite`.
- **Retries.** It backs off and retries on 429/5xx errors. For Claude, a refused request automatically falls back to another model.
- **Batch mode.** `--batch-api` sends a whole folder through Anthropic's Message Batches API at half the price. Each chunk gets the preceding Japanese lines as context, because the earlier translations don't exist yet when the batch is built.

Before translating, SPT lines are unwrapped: the Japanese line breaks and full-width indents are only layout. `insert-text` re-wraps them for the target text mode.

### Glossary bootstrap

```bash
python3 systemnnn_tools.py glossary jp/ --api anthropic --charaname game/spt/charaname.xtx
```

This collects speaker names, katakana terms and names followed by honorifics, and asks the model for consistent renderings and short character notes. The results are written to `gpt_dictionary.json`. Review the file: it is used both in the prompt and to translate name plates.

### Example style guide (`style.md`)

```markdown
- Keep honorifics (-san, -chan, -sensei).
- 「」 dialogue → "double quotes". Thoughts in （） → (parentheses).
- Text box is 20 characters × 3 lines: prefer short sentences, avoid filler.
- Sayoko speaks formally and teasingly; Arisu is casual and blunt.
```

### Using GalTransl or LinguaGacha instead

[GalTransl](https://github.com/GalTransl/GalTransl) (agent mode, GenDic auto-glossary, Sakura models) and [LinguaGacha](https://github.com/neavo/LinguaGacha) both read the `[{"name", "message"}]` JSON format:

```bash
python3 systemnnn_tools.py export-galtransl jp/ -o galtransl_project/json_jp/
# ... translate there ...
python3 systemnnn_tools.py import-galtransl jp/ galtransl_project/json_cn/ -o en/
python3 systemnnn_tools.py insert-text game/spt/ en/ -o patch/spt/
```

## Command reference

| Command | Purpose |
|---------|---------|
| `extract ARCHIVE -o DIR` | Unpack DDP2/DDP3 (`--no-decrypt` keeps HXB encrypted) |
| `extract-text PATH -o OUT` | Scripts → JSON (`--format vnt` for VNTranslationTools, `--spt-key` for non-standard SPT keys) |
| `glossary PATH -d gpt_dictionary.json --api …` | LLM-built name/term glossary |
| `translate PATH -o OUT --api …` | Context-aware translation (see above) |
| `qa PATH` | Missing `#` codes, CP932-unencodable characters, leftover Japanese, lines too wide or too many lines, dictionary violations |
| `insert-text SCRIPT(S) JSON(S) -o OUT` | Patch scripts (`--wrap auto\|N\|0`, `--code-byte 1\|2`, `--tunnel sjis_ext.bin`, `--names dict.json`) |
| `export-galtransl` / `import-galtransl` | Interchange with GalTransl / LinguaGacha |
| `migrate-json OLD NEW -o OUT` | Move translations from a pre-2.0 SPT JSON to the new table-based extraction |
| `nnn-config show\|set\|decode\|encode` | Engine settings in `init/*.xtx` / `init2/*.fxf` |
| `probe-exe EXE` | Which text-mode/font options and proxy DLL entry points the game supports |
| `repack DIR -o ARCHIVE` | Build DDP2/DDP3 (`--compress`) |
| `analyze ARCHIVE` | List archive entries |
| `convert-format` | VNTools ⇄ VNTranslationTools JSON |

API keys come from `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` or `DEEPL_API_KEY`, or from `--api-key`.

### JSON format (SPT)

```json
{
  "format": "spt-table",
  "version": 2,
  "strings": [
    {"id": "m2", "kind": "message", "name": "小夜子", "name_translated": "Sayoko",
     "original": "「お久しぶりね。\n　まる２年かしら、あなたが籠ってから」\n",
     "translated": "\"Long time no see. Has it really been two years since you shut yourself away?\""},
    {"id": "s0", "kind": "choice", "original": "オープニングを見る", "translated": "Watch the opening"}
  ]
}
```

`m…` are messages from the script's message table, and `s…` are choices from the string table. File names, labels and other non-text strings in that table are skipped.

> **Upgrading from an older VNTools:** SPT extraction used to scan for text heuristically. It missed choices and sometimes kept junk characters, and its rebuild did not update the string tables, so any length change corrupted the script. Re-extract, then carry your work over with `migrate-json old.json new.json -o merged.json`.

## Web GUI

```bash
pip install -r requirements.txt
python3 app.py            # http://127.0.0.1:5000
```

It has tabs for archives, script decrypt/encrypt, text extraction and insertion, AI translation, SJIS tunneling, word wrap and format conversion. The server listens on localhost only. Set `VNTOOLS_HOST=0.0.0.0` to expose it, and `VNTOOLS_DEBUG=1` only on a trusted machine.

## Technical details

### SPT script format

Everything here comes from `nnnLib/execscript.cpp` in the engine source.

- The file is read as 32-bit words and decrypted with `w = (w ^ key) + inc; key += addXor; inc += addInc`. Shipped games use `key=0xFFFFFFFF, addXor=0, addInc=0`, which is the same as XOR-ing every byte with 0xFF. Other keys can be given with `--spt-key "xor,addXor,addInc"`.
- Header words: `[4]` message count, `[5]` message table offset, `[6]` string count, `[7]` string table offset (offsets are in words). `SPTHEADER0` sits at byte 0x30.
- Each table entry is the word offset of a NUL-terminated CP932 string. Bytecode refers to text only by table index, so `insert-text` writes a translation in place when it fits and otherwise appends it to the end of the file and repoints the table entry. The bytecode is never touched.
- Messages are `name\r\nbody` (dialogue) or `body` (narration).

### Engine settings (`init/*.xtx`, `init2/*.fxf`)

The files contain whitespace-separated `key value` pairs, and spaces inside a value are written as `?`. `.fxf` files are XOR 0xFF and take priority when an `init2/` folder exists. The keys that matter for patches:

| File | Key | Meaning |
|------|-----|---------|
| game | `codeByte` | `1` = single-byte text (ANSI font, half-width cells); default `2` |
| game | `defaultFont`, `gothicFontName`, `minchoFontName` | Font faces (`Segoe?UI`) |
| game | `rightShift1Byte`, `fontWeight`, `useDirect2D` | Single-byte x offset, weight, Direct2D renderer |
| printmessage | `fontSize`, `nextX`, `nextY`, `space`, `printX`, `printY` | Message layout |
| printmessage | `windowMessageNumber`, `nameX`, `nameLengthMax` | Line capacity and name plate |

### HXB script format

- Signature: `DDSxHXB` (stored as `DDWuHXB` in archives, encrypted)
- Text encoding: UTF-16LE
- Encryption: XOR with key derived from file length

### DDP3 archive format

```
Offset  Size  Description
0x00    4     Signature "DDP3"
0x04    4     Header size (0x20)
0x08    4     Data section offset
0x0C    20    Reserved
0x20    256   Index section
0x120+  var   File entries (UTF-16LE names, variable length)
        var   File data (SHS/LZSS compressed)
```

### Other System-NNN formats (reference, not implemented)

| Format | Files | Notes |
|--------|-------|-------|
| DWQ | `.gtb` + `.gpk` | Images: 64-byte ASCII header; BMP/JPEG/PNG, optional alpha mask |
| VAW | `.vtb` + `.vpk` | Voice/SE: 12-byte index entries; WAV/OGG data |
| WGQ | `.wgq` | BGM: 64-byte header + OGG |
| MFT | `.mft` | Bitmap fonts (2/4/8-bit, SJIS order) |

[GARbro](https://github.com/morkt/GARbro) opens DWQ/VAW for image and voice work.

## Related tools

| Tool | Purpose |
|------|---------|
| [tinyan/SystemNNN](https://github.com/tinyan/SystemNNN) | Official System-NNN engine source (and [systemNNN_support](https://github.com/tinyan/systemNNN_support) tools) |
| [GalTransl](https://github.com/GalTransl/GalTransl) | Agent-driven LLM translation with GenDic glossary and review passes |
| [LinguaGacha](https://github.com/neavo/LinguaGacha) | LLM translator for games and novels |
| [VNTranslationTools](https://github.com/arcusmaximus/VNTranslationTools) | VNTextPatch / VNTextProxy (SJIS tunneling, font proxy); archived 2023 |
| [font_prop](https://github.com/louisbui63/font_prop) | Font proportionalizer for System-NNN (Direct2D builds) |
| [system-nnn-translator](https://github.com/PicosonSoft/system-nnn-translator) | C++ SPT tools (Yami no Koe Zero) |
| [GARbro](https://github.com/morkt/GARbro) | Universal VN resource browser |
| [LunaTranslator](https://github.com/HIllya51/LunaTranslator) | Real-time translation while playing |

## Thanks

- [tinyan](https://github.com/tinyan) for publishing the System-NNN source
- [GARbro](https://github.com/morkt/GARbro) by morkt for format specifications and compression
- [VNTranslationTools](https://github.com/arcusmaximus/VNTranslationTools) by arcusmaximus for the SJIS tunneling scheme
- [GalTransl](https://github.com/GalTransl/GalTransl) for the GPT dictionary and QA ideas
- The [Fuwanovel](https://forums.fuwanovel.moe/) and Chinese galgame translation communities for System-NNN research

## License

MIT License
