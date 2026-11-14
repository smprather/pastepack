# text-serdes

Tiny self-contained text transport for copy/paste sites, like PasteBin and Cl1p.net.

`text-serdes` takes bytes from a file or stdin, compresses them (only if it helps), encrypts, encodes with Base91, and prints copyable wrapped text. The same tool turns that text back into the original bytes.

## Install

```bash
uv sync
```

Or install it as a `uv` tool from this checkout:

```bash
uv tool install .
```

## Use

There is one executable with two subcommands: `enc` (alias `encode`) and `dec` (alias `decode`).

```bash
text-serdes enc [INPUT_FILE] [-o FILE] [-f] [-v]
text-serdes dec [INPUT_FILE] [-o PATH] [-f] [-v]
```

Both read `INPUT_FILE`, or stdin until EOF when it is omitted or `-`, and both write to stdout unless `--output` is given.

Encode stdin, then decode it again:

```bash
printf 'TypeError: invalid literal for int()' | text-serdes enc
text-serdes enc message.txt | text-serdes dec
```

Encode a file, and decode a file containing encoded text:

```bash
text-serdes enc message.txt > encoded.txt
text-serdes dec encoded.txt
```

### Output files

`enc` embeds the basename of a named input file in the payload. `dec` never writes a file on its own; it prints to stdout unless you ask:

```bash
text-serdes dec encoded.txt -o restored.txt   # write to this file
text-serdes dec encoded.txt -o .              # write ./<embedded filename>
text-serdes dec encoded.txt -o some/dir       # write some/dir/<embedded filename>
```

An existing file is never overwritten unless you add `-f`/`--force`. Only the final component of an embedded filename is ever used, so a payload cannot write outside the directory you chose.

`-v`/`--verbose` prints a one-line summary to stderr, including any embedded filename.

### Pasting

`enc` wraps its output at 100 columns. `dec` only looks at what sits between the `-ts-` and `-end-` markers, and ignores whitespace and terminal escape sequences inside them, so you can paste a whole terminal transcript with the payload somewhere in the middle.

## Format

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

Payloads written by versions before 0.2.0 (which had separate `text-serdes-enc` and `text-serdes-dec` executables and no markers) are not readable by this version.

![text-serdes encode and decode flow](docs/codec-flow.svg)

## Security Model

This is not secure storage, and it is not trying to be.

By default each encoded payload is self-contained: the key material needed to decode it is carried inside the payload itself, in an obfuscated form, combined with a fixed component baked into this tool. Any copy of `text-serdes` can decode any payload it produced. (The optional passphrase below changes this.)

The only thing this buys you is that the output does not read as plaintext to casual eyes glancing at a terminal, a chat log, or a paste. Anyone willing to read this source, or to point a capable tool at the encoded text, can recover the contents. Use it for short-lived transport convenience, not for anything that needs real key management.

### Optional passphrase

Set the `TS_KEY` environment variable to fold a passphrase into the key. When set, it must match on both sides:

```bash
TS_KEY=swordfish text-serdes enc message.txt | TS_KEY=swordfish text-serdes dec
```

This moves a secret out of the source entirely, so the encoded payload cannot be decoded without it. The key is derived with scrypt, salted per message, which slows down guessing, but a weak passphrase is still a weak passphrase. `TS_KEY` is optional: leave it unset and the tool behaves as above (self-contained, obfuscation only).

## Compression

The encoder tries zlib. If that makes the payload smaller, it stores the compressed bytes; otherwise it encrypts the raw bytes.

## Library

```python
from text_serdes import decode, encode

text = encode(b"hello", filename="hello.txt", passphrase="")
decoded = decode(text)  # Decoded(data=b"hello", filename="hello.txt", compressed=False)
```

`decode` raises `CodecError` when the text holds no decodable payload.

## Develop

```bash
uv run pytest -q
```

Useful files:

- `src/text_serdes/cli.py`: the `text-serdes` command group.
- `src/text_serdes/codec.py`: encode/decode pipeline and wire format.
