from __future__ import annotations

import time

import base91
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from text_serdes import CodecError, Decoded, decode, encode
from text_serdes.codec import (
    BEGIN_MARKER,
    END_MARKER,
    FLAG_FILENAME,
    FLAG_ZLIB,
    FORMAT_VERSION,
    _knit,
    _part,
    _seal,
    _tag,
    find_payloads,
    wrap,
)


def _raw(encoded: str) -> bytes:
    body = encoded[len(BEGIN_MARKER) : -len(END_MARKER)]
    core, _token = _part(body)
    return bytes(base91.decode(core))


def _forge(header: bytes, plaintext: bytes) -> str:
    """Build a correctly keyed payload with an arbitrary header and plaintext."""
    token = _tag()
    nonce = b"\x00" * 12
    ciphertext = AESGCM(_seal(token)).encrypt(nonce, plaintext, header)
    return BEGIN_MARKER + _knit(base91.encode(header + nonce + ciphertext), token) + END_MARKER


def test_round_trip_binary() -> None:
    plaintext = b"alpha\nbeta\n\x00\xff"

    encoded = encode(plaintext)

    assert decode(encoded) == Decoded(plaintext, None, False)


def test_round_trip_empty() -> None:
    assert decode(encode(b"")).data == b""


def test_encoded_text_is_one_framed_line() -> None:
    encoded = encode(b"x" * 500)

    assert encoded.startswith(BEGIN_MARKER)
    assert encoded.endswith(END_MARKER)
    assert not any(ch.isspace() for ch in encoded)
    assert "-" not in encoded[len(BEGIN_MARKER) : -len(END_MARKER)]


def test_each_encoding_is_unique() -> None:
    assert encode(b"same") != encode(b"same")


def test_header_carries_version_and_flags() -> None:
    assert _raw(encode(b"short"))[:2] == bytes((FORMAT_VERSION, 0))
    assert _raw(encode(b"again " * 50))[:2] == bytes((FORMAT_VERSION, FLAG_ZLIB))
    assert _raw(encode(b"short", filename="a.txt"))[:2] == bytes((FORMAT_VERSION, FLAG_FILENAME))


def test_compression_is_used_only_when_it_helps() -> None:
    assert decode(encode(b"TypeError: invalid literal")).compressed is False

    repetitive = b"TypeError: invalid literal\n" * 50
    encoded = encode(repetitive)
    assert decode(encoded).compressed is True
    assert len(encoded) < len(repetitive)


def test_filename_round_trips() -> None:
    decoded = decode(encode(b"file bytes\n", filename="méssage.txt"))

    assert decoded.filename == "méssage.txt"
    assert decoded.data == b"file bytes\n"


@pytest.mark.parametrize("filename", ["", "x" * 4097])
def test_bad_filename_is_rejected_on_encode(filename: str) -> None:
    with pytest.raises(CodecError, match="filename"):
        encode(b"data", filename=filename)


def test_passphrase_must_match() -> None:
    encoded = encode(b"with passphrase", passphrase="hunter2")

    assert decode(encoded, passphrase="hunter2").data == b"with passphrase"
    with pytest.raises(CodecError, match="passphrase"):
        decode(encoded, passphrase="wrong")
    with pytest.raises(CodecError, match="passphrase"):
        decode(encoded)


def test_every_single_character_corruption_is_detected() -> None:
    encoded = encode(b"secret")
    body_start = len(BEGIN_MARKER)
    body_end = len(encoded) - len(END_MARKER)

    for index in range(body_start, body_end):
        swap = "A" if encoded[index] != "A" else "B"
        broken = encoded[:index] + swap + encoded[index + 1 :]
        with pytest.raises(CodecError):
            decode(broken)


def test_text_without_a_payload_fails() -> None:
    with pytest.raises(CodecError, match="no payload found"):
        decode("not valid for this tool")


def test_truncated_payload_fails() -> None:
    encoded = encode(b"will be truncated")

    with pytest.raises(CodecError, match="truncated"):
        decode(encoded[:-8])


def test_foreign_characters_inside_frame_fail() -> None:
    encoded = encode(b"payload")
    mid = len(encoded) // 2

    with pytest.raises(CodecError, match="not valid Base91"):
        decode(encoded[:mid] + "é" + encoded[mid:])


def test_tiny_frame_fails() -> None:
    with pytest.raises(CodecError, match="too short"):
        decode(f"{BEGIN_MARKER}abc{END_MARKER}")
    with pytest.raises(CodecError, match="too short"):
        decode(f"{BEGIN_MARKER}{'A' * 20}{END_MARKER}")


def test_unsupported_version_fails() -> None:
    with pytest.raises(CodecError, match="unsupported format version 9"):
        decode(_forge(bytes((9, 0)), b"data"))


def test_unknown_flags_fail() -> None:
    with pytest.raises(CodecError, match="unknown flags"):
        decode(_forge(bytes((FORMAT_VERSION, 0x80)), b"data"))


def test_invalid_compressed_payload_fails() -> None:
    with pytest.raises(CodecError, match="compressed payload"):
        decode(_forge(bytes((FORMAT_VERSION, FLAG_ZLIB)), b"not zlib"))


@pytest.mark.parametrize("plaintext", [b"", b"\x00", b"\x00\x00", b"\x00\x05abc", b"\x00\x02\xff\xfe"])
def test_invalid_filename_metadata_fails(plaintext: bytes) -> None:
    with pytest.raises(CodecError, match="invalid filename"):
        decode(_forge(bytes((FORMAT_VERSION, FLAG_FILENAME)), plaintext))


def test_terminal_paste_sequences_are_ignored() -> None:
    encoded = encode(b"pasted through terminal")

    assert decode(f"\x1b[200~{encoded}\x1b[201~").data == b"pasted through terminal"
    assert decode(f"\x1b]0;title\x07{encoded[:9]}\x1b[0m{encoded[9:]}").data == b"pasted through terminal"


def test_whitespace_damage_is_ignored() -> None:
    encoded = encode(b"wrapped paste survives")
    damaged = f"  {encoded[:2]}\n{encoded[2:21]}\r\n{encoded[21:-3]}\t {encoded[-3:]} "

    assert decode(damaged).data == b"wrapped paste survives"


def test_noisy_paste_can_still_be_decoded() -> None:
    encoded = encode(b"noise around the payload")
    noisy = (
        "❯ uv run text-serdes enc\n"
        "sometranscriptbefore\n"
        f"  {encoded[:18]}\n"
        f"{encoded[18:52]}\n"
        f"{encoded[52:]}\n"
        "transcriptafter\n"
        "$ echo -ts- is not a payload\n"
    )

    assert decode(noisy).data == b"noise around the payload"


def test_first_decodable_payload_wins() -> None:
    wrong_key = encode(b"other", passphrase="someone else")
    first = encode(b"first")
    second = encode(b"second")

    assert find_payloads(f"{wrong_key}\n{first}\n{second}") == [
        text[len(BEGIN_MARKER) : -len(END_MARKER)] for text in (wrong_key, first, second)
    ]
    assert decode(f"{wrong_key}\n{first}\n{second}").data == b"first"


def test_large_undecodable_paste_fails_quickly() -> None:
    lines = "\n".join(["Abc,def" * 12] * 20_000)

    started = time.monotonic()
    with pytest.raises(CodecError):
        decode(lines)
    assert time.monotonic() - started < 2


def test_wrap_limits_line_length_and_keeps_content() -> None:
    encoded = encode(bytes(range(256)) * 4)

    lines = wrap(encoded, 100).splitlines()

    assert len(lines) > 1
    assert max(len(line) for line in lines) == 100
    assert "".join(lines) == encoded
    assert decode(wrap(encoded, 100)).data == bytes(range(256)) * 4
