from __future__ import annotations

import time

import base91
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pastepack import PackError, Unpacked, pack, unpack
from pastepack.codec import (
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


def _raw(packed: str) -> bytes:
    body = packed[len(BEGIN_MARKER) : -len(END_MARKER)]
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

    packed = pack(plaintext)

    assert unpack(packed) == Unpacked(plaintext, None, False)


def test_round_trip_empty() -> None:
    assert unpack(pack(b"")).data == b""


def test_packed_text_is_one_framed_line() -> None:
    packed = pack(b"x" * 500)

    assert packed.startswith(BEGIN_MARKER)
    assert packed.endswith(END_MARKER)
    assert not any(ch.isspace() for ch in packed)
    assert "-" not in packed[len(BEGIN_MARKER) : -len(END_MARKER)]


def test_each_packing_is_unique() -> None:
    assert pack(b"same") != pack(b"same")


def test_header_carries_version_and_flags() -> None:
    assert _raw(pack(b"short"))[:2] == bytes((FORMAT_VERSION, 0))
    assert _raw(pack(b"again " * 50))[:2] == bytes((FORMAT_VERSION, FLAG_ZLIB))
    assert _raw(pack(b"short", filename="a.txt"))[:2] == bytes((FORMAT_VERSION, FLAG_FILENAME))


def test_compression_is_used_only_when_it_helps() -> None:
    assert unpack(pack(b"TypeError: invalid literal")).compressed is False

    repetitive = b"TypeError: invalid literal\n" * 50
    packed = pack(repetitive)
    assert unpack(packed).compressed is True
    assert len(packed) < len(repetitive)


def test_filename_round_trips() -> None:
    unpacked = unpack(pack(b"file bytes\n", filename="méssage.txt"))

    assert unpacked.filename == "méssage.txt"
    assert unpacked.data == b"file bytes\n"


@pytest.mark.parametrize("filename", ["", "x" * 4097])
def test_bad_filename_is_rejected_on_pack(filename: str) -> None:
    with pytest.raises(PackError, match="filename"):
        pack(b"data", filename=filename)


def test_passphrase_must_match() -> None:
    packed = pack(b"with passphrase", passphrase="hunter2")

    assert unpack(packed, passphrase="hunter2").data == b"with passphrase"
    with pytest.raises(PackError, match="passphrase"):
        unpack(packed, passphrase="wrong")
    with pytest.raises(PackError, match="passphrase"):
        unpack(packed)


def test_every_single_character_corruption_is_detected() -> None:
    packed = pack(b"secret")
    body_start = len(BEGIN_MARKER)
    body_end = len(packed) - len(END_MARKER)

    for index in range(body_start, body_end):
        swap = "A" if packed[index] != "A" else "B"
        broken = packed[:index] + swap + packed[index + 1 :]
        with pytest.raises(PackError):
            unpack(broken)


def test_text_without_a_payload_fails() -> None:
    with pytest.raises(PackError, match="no payload found"):
        unpack("not valid for this tool")


def test_truncated_payload_fails() -> None:
    packed = pack(b"will be truncated")

    with pytest.raises(PackError, match="truncated"):
        unpack(packed[:-8])


def test_foreign_characters_inside_frame_fail() -> None:
    packed = pack(b"payload")
    mid = len(packed) // 2

    with pytest.raises(PackError, match="not valid Base91"):
        unpack(packed[:mid] + "é" + packed[mid:])


def test_tiny_frame_fails() -> None:
    with pytest.raises(PackError, match="too short"):
        unpack(f"{BEGIN_MARKER}abc{END_MARKER}")
    with pytest.raises(PackError, match="too short"):
        unpack(f"{BEGIN_MARKER}{'A' * 20}{END_MARKER}")


def test_unsupported_version_fails() -> None:
    with pytest.raises(PackError, match="unsupported format version 9"):
        unpack(_forge(bytes((9, 0)), b"data"))


def test_unknown_flags_fail() -> None:
    with pytest.raises(PackError, match="unknown flags"):
        unpack(_forge(bytes((FORMAT_VERSION, 0x80)), b"data"))


def test_invalid_compressed_payload_fails() -> None:
    with pytest.raises(PackError, match="compressed payload"):
        unpack(_forge(bytes((FORMAT_VERSION, FLAG_ZLIB)), b"not zlib"))


@pytest.mark.parametrize("plaintext", [b"", b"\x00", b"\x00\x00", b"\x00\x05abc", b"\x00\x02\xff\xfe"])
def test_invalid_filename_metadata_fails(plaintext: bytes) -> None:
    with pytest.raises(PackError, match="invalid filename"):
        unpack(_forge(bytes((FORMAT_VERSION, FLAG_FILENAME)), plaintext))


def test_terminal_paste_sequences_are_ignored() -> None:
    packed = pack(b"pasted through terminal")

    assert unpack(f"\x1b[200~{packed}\x1b[201~").data == b"pasted through terminal"
    assert unpack(f"\x1b]0;title\x07{packed[:9]}\x1b[0m{packed[9:]}").data == b"pasted through terminal"


def test_whitespace_damage_is_ignored() -> None:
    packed = pack(b"wrapped paste survives")
    damaged = f"  {packed[:2]}\n{packed[2:21]}\r\n{packed[21:-3]}\t {packed[-3:]} "

    assert unpack(damaged).data == b"wrapped paste survives"


def test_noisy_paste_can_still_be_unpacked() -> None:
    packed = pack(b"noise around the payload")
    noisy = (
        "❯ uv run pastepack pack\n"
        "sometranscriptbefore\n"
        f"  {packed[:18]}\n"
        f"{packed[18:52]}\n"
        f"{packed[52:]}\n"
        "transcriptafter\n"
        "$ echo -pack- is not a payload\n"
    )

    assert unpack(noisy).data == b"noise around the payload"


def test_first_unpackable_payload_wins() -> None:
    wrong_key = pack(b"other", passphrase="someone else")
    first = pack(b"first")
    second = pack(b"second")

    assert find_payloads(f"{wrong_key}\n{first}\n{second}") == [
        text[len(BEGIN_MARKER) : -len(END_MARKER)] for text in (wrong_key, first, second)
    ]
    assert unpack(f"{wrong_key}\n{first}\n{second}").data == b"first"


def test_large_unreadable_paste_fails_quickly() -> None:
    lines = "\n".join(["Abc,def" * 12] * 20_000)

    started = time.monotonic()
    with pytest.raises(PackError):
        unpack(lines)
    assert time.monotonic() - started < 2


def test_wrap_limits_line_length_and_keeps_content() -> None:
    packed = pack(bytes(range(256)) * 4)

    lines = wrap(packed, 100).splitlines()

    assert len(lines) > 1
    assert max(len(line) for line in lines) == 100
    assert "".join(lines) == packed
    assert unpack(wrap(packed, 100)).data == bytes(range(256)) * 4
