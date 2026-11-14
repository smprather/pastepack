"""Encode bytes into framed, copy/paste-safe text and back again.

Wire format (version 2)::

    -ts-<base91 text with the key token woven in>-end-

The Base91 text decodes to ``version (1) | flags (1) | nonce (12) | ciphertext``.
The two header bytes are authenticated but not encrypted. The plaintext is the
payload, optionally zlib-compressed, optionally prefixed with a filename.
"""

from __future__ import annotations

import re
import zlib
from dataclasses import dataclass
from hashlib import scrypt
from os import urandom

import base91
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT_VERSION = 2
FLAG_ZLIB = 0x01
FLAG_FILENAME = 0x02
KNOWN_FLAGS = FLAG_ZLIB | FLAG_FILENAME
HEADER_SIZE = 2
NONCE_SIZE = 12
GCM_TAG_SIZE = 16
MAX_FILENAME_SIZE = 4096

# Neither marker can occur inside a payload: "-" is not a Base91 character.
BEGIN_MARKER = "-ts-"
END_MARKER = "-end-"

_BASE91_CLASS = "[" + re.escape("".join(base91.base91_alphabet)) + "]"
_FRAME = re.compile(re.escape(BEGIN_MARKER) + f"({_BASE91_CLASS}+)" + re.escape(END_MARKER))
_CSI_SEQUENCE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_OSC_SEQUENCE = re.compile(r"\x1b\].*?(?:\x07|\x1b\\)", re.DOTALL)
_WHITESPACE = re.compile(r"\s+")


class CodecError(ValueError):
    """Raised when text cannot be decoded back into a payload."""


@dataclass(frozen=True)
class Decoded:
    data: bytes
    filename: str | None = None
    compressed: bool = False


# -- key plumbing ----------------------------------------------------------
# The AES-256 key is derived per message from a short token that travels woven
# into the encoded text, combined with a fixed component held below as masked
# bytes rather than a readable literal, and with the optional passphrase (empty
# when unset). Layout of these helpers is left deliberately opaque; the
# comments here are the only signposts.
_VEIL = 0x53
_GRAIN = (
    0x27, 0x20, 0x60, 0x7c, 0x37, 0x3c, 0x7e, 0x3d, 0x3c, 0x27,
    0x7e, 0x20, 0x27, 0x32, 0x21, 0x36, 0x7c, 0x25, 0x61,
)
_SPAN = 0b1010


def _seal(t: str, passphrase: str = "") -> bytes:
    base = bytes(g ^ _VEIL for g in _GRAIN) + passphrase.encode("utf-8")
    return scrypt(base, salt=t.encode("ascii"), n=1 << 14, r=8, p=1, dklen=32)


def _tag() -> str:
    a = base91.base91_alphabet
    return "".join(a[o % len(a)] for o in urandom(_SPAN))


def _knit(s: str, t: str) -> str:
    p = len(s) >> 1
    return s[:p] + t + s[p:]


def _part(s: str) -> tuple[str, str]:
    p = (len(s) - _SPAN) >> 1
    return s[:p] + s[p + _SPAN :], s[p : p + _SPAN]


# -- encode ----------------------------------------------------------------


def encode(data: bytes, filename: str | None = None, passphrase: str = "") -> str:
    """Return ``data`` as one line of framed text, embedding ``filename`` if given."""
    flags = 0
    plaintext = data
    if filename is not None:
        plaintext = _pack_filename(filename) + data
        flags |= FLAG_FILENAME

    compressed = zlib.compress(plaintext, 9)
    if len(compressed) < len(plaintext):
        plaintext = compressed
        flags |= FLAG_ZLIB

    header = bytes((FORMAT_VERSION, flags))
    nonce = urandom(NONCE_SIZE)
    token = _tag()
    ciphertext = AESGCM(_seal(token, passphrase)).encrypt(nonce, plaintext, header)
    body = _knit(base91.encode(header + nonce + ciphertext), token)
    return BEGIN_MARKER + body + END_MARKER


def wrap(text: str, columns: int) -> str:
    """Break encoded text into lines of at most ``columns`` characters."""
    return "\n".join(text[i : i + columns] for i in range(0, len(text), columns))


# -- decode ----------------------------------------------------------------


def decode(text: str, passphrase: str = "") -> Decoded:
    """Find the framed payload in ``text`` and decode it.

    ``text`` may be a messy paste: surrounding transcript, terminal escape
    sequences, and any whitespace inside the payload are all tolerated.
    """
    bodies = find_payloads(text)
    if not bodies:
        raise CodecError(_missing_frame_message(text))

    error: CodecError | None = None
    for body in bodies:
        try:
            return _decode_body(body, passphrase)
        except CodecError as exc:
            error = exc
    assert error is not None
    raise error


def find_payloads(text: str) -> list[str]:
    """Return the body of every ``-ts-...-end-`` frame found in ``text``."""
    return _FRAME.findall(_scrub(text))


def _scrub(text: str) -> str:
    text = _CSI_SEQUENCE.sub("", _OSC_SEQUENCE.sub("", text))
    return _WHITESPACE.sub("", text)


def _missing_frame_message(text: str) -> str:
    scrubbed = _scrub(text)
    start = scrubbed.rfind(BEGIN_MARKER)
    if start == -1:
        return f"no payload found; expected text starting with {BEGIN_MARKER!r}"
    if END_MARKER not in scrubbed[start:]:
        return f"payload is truncated; missing the closing {END_MARKER!r}"
    return "payload contains characters that are not valid Base91"


def _decode_body(body: str, passphrase: str) -> Decoded:
    if len(body) <= _SPAN:
        raise CodecError("payload is too short")
    core, token = _part(body)
    try:
        raw = bytes(base91.decode(core))
    except Exception as exc:
        raise CodecError("payload is not valid Base91") from exc

    if len(raw) < HEADER_SIZE + NONCE_SIZE + GCM_TAG_SIZE:
        raise CodecError("payload is too short")
    header = raw[:HEADER_SIZE]
    version, flags = header
    if version != FORMAT_VERSION:
        raise CodecError(f"unsupported format version {version}; this tool reads version {FORMAT_VERSION}")
    if flags & ~KNOWN_FLAGS:
        raise CodecError(f"payload uses unknown flags 0x{flags:02x}")

    nonce = raw[HEADER_SIZE : HEADER_SIZE + NONCE_SIZE]
    ciphertext = raw[HEADER_SIZE + NONCE_SIZE :]
    try:
        plaintext = AESGCM(_seal(token, passphrase)).decrypt(nonce, ciphertext, header)
    except InvalidTag as exc:
        raise CodecError("decrypt failed; the payload is corrupt or the passphrase does not match") from exc

    compressed = bool(flags & FLAG_ZLIB)
    if compressed:
        try:
            plaintext = zlib.decompress(plaintext)
        except zlib.error as exc:
            raise CodecError("compressed payload is invalid") from exc

    if flags & FLAG_FILENAME:
        filename, data = _unpack_filename(plaintext)
        return Decoded(data, filename, compressed)
    return Decoded(plaintext, None, compressed)


# -- filename metadata -----------------------------------------------------


def _pack_filename(filename: str) -> bytes:
    name = filename.encode("utf-8")
    if not name or len(name) > MAX_FILENAME_SIZE:
        raise CodecError("filename is empty or too long")
    return len(name).to_bytes(2, "big") + name


def _unpack_filename(plaintext: bytes) -> tuple[str, bytes]:
    size = int.from_bytes(plaintext[:2], "big")
    name = plaintext[2 : 2 + size]
    if len(plaintext) < 2 or size == 0 or size > MAX_FILENAME_SIZE or len(name) < size:
        raise CodecError("payload has an invalid filename")
    try:
        return name.decode("utf-8"), plaintext[2 + size :]
    except UnicodeDecodeError as exc:
        raise CodecError("payload has an invalid filename") from exc
