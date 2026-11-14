<p align="center">
  <img src="docs/logo.svg" alt="text-serdes" width="720">
</p>

<p align="center">
  <strong>Turn any file or stream into a block of text that survives copy/paste, and turn it back.</strong>
</p>

<p align="center">
  <img alt="Python 3.12+" src="https://img.shields.io/badge/python-3.12%2B-34d399?labelColor=0f172a">
  <img alt="Wire format v2" src="https://img.shields.io/badge/wire%20format-v2-22d3ee?labelColor=0f172a">
  <a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-94a3b8?labelColor=0f172a"></a>
</p>

---

`text-serdes` is a tiny CLI for moving bytes through places that only carry text: paste sites like PasteBin and cl1p.net, chat windows, a terminal you can only copy out of. It compresses (only when that helps), encrypts, Base91-encodes, and prints a wrapped, clearly framed block. The same tool reads that block back, even out of a messy paste.

```console
$ printf 'TypeError: invalid literal for int()' | text-serdes enc
-ts-CA)YGBS0@L{ylDa%MrRk;Qg_3<,BK|Lx8?XcApA`we%CsL(qGsUK&H91khr}=nJ#As.0i=@_UK"A3zf;ViesC5W,P))-end-

$ text-serdes dec pasted.txt
TypeError: invalid literal for int()
```

> [!WARNING]
> By default this is **obfuscation, not secrecy**: the key travels inside the payload. Set [`TS_KEY`](#passphrase-ts_key) if decoding should require a secret. See [Security model](#security-model).

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Pasting](#pasting)
- [Security model](#security-model)
- [Wire format](#wire-format)
- [Library](#library)
- [Development](#development)

## Install

Install the `text-serdes` and `ts` commands as a [uv](https://docs.astral.sh/uv/) tool:

```bash
uv tool install git+https://github.com/smprather/text-serdes
```

Or from a checkout:

```bash
uv tool install .   # install the commands
uv sync             # or just set up a dev environment and use `uv run text-serdes`
```

Requires Python 3.12 or newer.

## Quick start

```bash
# Round trip through a pipe
text-serdes enc message.txt | text-serdes dec

# Encode a file, paste it somewhere, decode it on the other side
text-serdes enc notes.md > encoded.txt
text-serdes dec encoded.txt -o .        # restores ./notes.md

# Or let the shortcut work out which direction to go
ts notes.md                             # writes notes.md.ts
ts notes.md.ts                          # writes ./notes.md
```

## Commands

One executable, two subcommands, plus a shortcut:

| Command | Does |
| --- | --- |
| `text-serdes enc [INPUT_FILE]` | Compress, encrypt, encode. Alias: `encode`. |
| `text-serdes dec [INPUT_FILE]` | Find the payload, decode, decrypt, decompress. Alias: `decode`. |
| `ts FILE` | Toggle a file between plain and encoded. |

### `enc` and `dec`

```text
text-serdes enc [INPUT_FILE] [-o FILE] [-f] [-v]
text-serdes dec [INPUT_FILE] [-o PATH] [-f] [-v]
```

Both read `INPUT_FILE`, or stdin until EOF when it is omitted or `-`, and both write to stdout unless `--output` is given.

| Option | Meaning |
| --- | --- |
| `-o`, `--output` | Write to a file instead of stdout. For `dec`, a directory means "use the embedded filename". |
| `-f`, `--force` | Allow overwriting an existing output file. Without it, existing files are never touched. |
| `-v`, `--verbose` | Print a one-line summary to stderr, including any embedded filename. |

`enc` embeds the basename of a named input file in the payload. `dec` never writes a file on its own; it prints to stdout unless you ask:

```bash
text-serdes dec encoded.txt -o restored.txt   # write to this file
text-serdes dec encoded.txt -o .              # write ./<embedded filename>
text-serdes dec encoded.txt -o some/dir       # write some/dir/<embedded filename>
```

Only the final component of an embedded filename is ever used, so a payload cannot write outside the directory you chose.

### `ts`

`ts FILE` does the obvious thing for a file:

- If `FILE` contains an encoded payload with an embedded filename, the original is written to `./<filename>`.
- Otherwise `FILE` is encoded to `FILE.ts`. If `TEXT_SERDES_ENCODE_OUTPUT_DIR` names an existing directory, the `.ts` file goes there instead of next to `FILE`.

`ts` takes no options and, unlike `enc` and `dec`, **always overwrites** existing output files.

### Environment variables

| Variable | Used by | Effect |
| --- | --- | --- |
| `TS_KEY` | all commands | Passphrase folded into the key. Must match on both sides. |
| `TEXT_SERDES_ENCODE_OUTPUT_DIR` | `ts` | Directory for newly encoded `.ts` files, if it exists. |

## Pasting

The output is built to survive rough handling:

- `enc` wraps at 100 columns.
- `dec` only looks at what sits between the `-ts-` and `-end-` markers.
- Inside the markers, whitespace and terminal escape sequences are ignored.

So you can paste a whole terminal transcript, prompt lines and all, with the payload somewhere in the middle, and `dec` will find it.

## Security model

This is not secure storage, and it is not trying to be.

By default each encoded payload is self-contained: the key material needed to decode it is carried inside the payload itself, in an obfuscated form, combined with a fixed component baked into this tool. Any copy of `text-serdes` can decode any payload it produced.

The only thing this buys you is that the output does not read as plaintext to casual eyes glancing at a terminal, a chat log, or a paste. Anyone willing to read this source, or to point a capable tool at the encoded text, can recover the contents. Use it for short-lived transport convenience, not for anything that needs real key management.

### Passphrase (`TS_KEY`)

Set the `TS_KEY` environment variable to fold a passphrase into the key. When set, it must match on both sides:

```bash
TS_KEY=swordfish text-serdes enc message.txt | TS_KEY=swordfish text-serdes dec
```

This moves a secret out of the source entirely, so the encoded payload cannot be decoded without it. The key is derived with scrypt, salted per message, which slows down guessing, but a weak passphrase is still a weak passphrase. Leave `TS_KEY` unset and the tool behaves as above: self-contained, obfuscation only.

## Wire format

![text-serdes encode and decode flow](docs/codec-flow.svg)

```text
-ts-<Base91 text>-end-
```

The Base91 text decodes to:

| Bytes | Content |
| --- | --- |
| 1 | format version (currently `2`) |
| 1 | flags: `0x01` zlib-compressed, `0x02` filename embedded |
| 12 | random AES-GCM nonce |
| rest | AES-256-GCM ciphertext and tag; the two header bytes are authenticated |

The decrypted bytes are optionally zlib-compressed, and optionally start with a 2-byte length and a UTF-8 basename. `-` is not a Base91 character, so the markers cannot appear inside a payload.

**Compression.** The encoder tries zlib. If that makes the payload smaller, it stores the compressed bytes; otherwise it encrypts the raw bytes.

**Compatibility.** Payloads written by versions before 0.2.0 (which had separate `text-serdes-enc` and `text-serdes-dec` executables and no markers) are not readable by this version.

## Library

```python
from text_serdes import decode, encode

text = encode(b"hello", filename="hello.txt", passphrase="")
decoded = decode(text)  # Decoded(data=b"hello", filename="hello.txt", compressed=False)
```

`decode` raises `CodecError` when the text holds no decodable payload.

## Development

```bash
uv sync           # create the virtual environment
uv run pytest -q  # run the tests
```

| Path | What lives there |
| --- | --- |
| `src/text_serdes/cli.py` | The `text-serdes` command group and the `ts` shortcut. |
| `src/text_serdes/codec.py` | Encode/decode pipeline and wire format. |
| `tests/` | Codec and CLI tests. |

## License

[MIT](LICENSE)
