from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner, Result

from text_serdes.cli import main


def run(*args: str, input: bytes | None = None, env: dict[str, str] | None = None) -> Result:
    return CliRunner().invoke(main, list(args), input=input, env=env)


def enc(*args: str, input: bytes | None = None, env: dict[str, str] | None = None) -> bytes:
    result = run("enc", *args, input=input, env=env)
    assert result.exit_code == 0, result.stderr
    return result.stdout_bytes


@pytest.fixture(autouse=True)
def in_tmp_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("TS_KEY", raising=False)


def test_stdin_round_trip() -> None:
    plaintext = b"from stdin\nwith newline\n\x00\xff"

    encoded = enc(input=plaintext)
    result = run("dec", input=encoded)

    assert encoded.startswith(b"-ts-")
    assert encoded.endswith(b"-end-\n")
    assert result.exit_code == 0
    assert result.stdout_bytes == plaintext
    assert result.stderr == ""


def test_dash_means_stdin() -> None:
    encoded = enc("-", input=b"dash")

    assert run("dec", "-", input=encoded).stdout_bytes == b"dash"


def test_long_names_are_aliases() -> None:
    encoded = run("encode", input=b"aliased")

    assert encoded.exit_code == 0
    assert run("decode", input=encoded.stdout_bytes).stdout_bytes == b"aliased"


def test_enc_wraps_long_output() -> None:
    plaintext = os.urandom(4096)

    encoded = enc(input=plaintext)

    lines = encoded.splitlines()
    assert len(lines) > 1
    assert max(len(line) for line in lines) == 100
    assert run("dec", input=encoded).stdout_bytes == plaintext


def test_file_input_decodes_to_stdout_and_leaves_files_alone(tmp_path: Path) -> None:
    source = tmp_path / "message.txt"
    source.write_bytes(b"file bytes\n")
    encoded = enc(str(source))
    source.write_bytes(b"changed since encoding\n")

    result = run("dec", input=encoded)

    assert result.stdout_bytes == b"file bytes\n"
    assert source.read_bytes() == b"changed since encoding\n"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["message.txt"]


def test_dec_reads_encoded_file(tmp_path: Path) -> None:
    encoded_file = tmp_path / "encoded.txt"
    encoded_file.write_bytes(enc(input=b"from an encoded file"))

    assert run("dec", str(encoded_file)).stdout_bytes == b"from an encoded file"


def test_enc_output_file(tmp_path: Path) -> None:
    target = tmp_path / "encoded.txt"

    result = run("enc", "-o", str(target), input=b"to a file")

    assert result.exit_code == 0
    assert result.stdout_bytes == b""
    assert run("dec", str(target)).stdout_bytes == b"to a file"


def test_dec_output_file(tmp_path: Path) -> None:
    source = tmp_path / "embedded.txt"
    source.write_bytes(b"payload with file name")
    target = tmp_path / "chosen.txt"

    result = run("dec", "--output", str(target), input=enc(str(source)))

    assert result.exit_code == 0
    assert result.stdout_bytes == b""
    assert target.read_bytes() == b"payload with file name"


def test_dec_output_directory_uses_embedded_filename(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    source.write_bytes(b"directory target")
    out = tmp_path / "out"
    out.mkdir()

    result = run("dec", "-o", str(out), input=enc(str(source)))

    assert result.exit_code == 0
    assert (out / "source.txt").read_bytes() == b"directory target"


def test_dec_output_directory_requires_embedded_filename(tmp_path: Path) -> None:
    result = run("dec", "-o", str(tmp_path), input=enc(input=b"plain stdin payload"))

    assert result.exit_code == 1
    assert "no embedded filename" in result.stderr
    assert list(tmp_path.iterdir()) == []


def test_embedded_filename_cannot_escape_output_directory(tmp_path: Path) -> None:
    from text_serdes import encode

    out = tmp_path / "out"
    out.mkdir()
    hostile = encode(b"contained", filename="../../escape.txt").encode("ascii")

    result = run("dec", "-o", str(out), input=hostile)

    assert result.exit_code == 0
    assert (out / "escape.txt").read_bytes() == b"contained"
    assert not (tmp_path / "escape.txt").exists()


@pytest.mark.parametrize("command", ["enc", "dec"])
def test_existing_output_needs_force(tmp_path: Path, command: str) -> None:
    target = tmp_path / "existing.txt"
    target.write_bytes(b"precious")
    data = b"input" if command == "enc" else enc(input=b"input")

    refused = run(command, "-o", str(target), input=data)

    assert refused.exit_code == 1
    assert "already exists" in refused.stderr
    assert target.read_bytes() == b"precious"

    forced = run(command, "-o", str(target), "--force", input=data)

    assert forced.exit_code == 0
    assert target.read_bytes() != b"precious"


def test_dec_directory_target_needs_force(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    source.write_bytes(b"original")
    encoded = enc(str(source))

    refused = run("dec", "-o", str(tmp_path), input=encoded)
    assert refused.exit_code == 1
    assert "already exists" in refused.stderr

    source.write_bytes(b"clobber me")
    assert run("dec", "-o", ".", "-f", input=encoded).exit_code == 0
    assert source.read_bytes() == b"original"


def test_ts_key_must_match() -> None:
    encoded = enc(input=b"with passphrase", env={"TS_KEY": "swordfish"})

    assert run("dec", input=encoded, env={"TS_KEY": "swordfish"}).stdout_bytes == b"with passphrase"

    wrong = run("dec", input=encoded, env={"TS_KEY": "wrong"})
    assert wrong.exit_code == 1
    assert "passphrase" in wrong.stderr

    assert run("dec", input=encoded).exit_code == 1


def test_bad_input_reports_error_on_stderr() -> None:
    result = run("dec", input=b"\xff\xfe not a payload")

    assert result.exit_code == 1
    assert result.stdout_bytes == b""
    assert "no payload found" in result.stderr


def test_missing_input_file_fails(tmp_path: Path) -> None:
    for command in ("enc", "dec"):
        result = run(command, str(tmp_path / "missing.txt"))

        assert result.exit_code == 1
        assert "missing.txt" in result.stderr


def test_verbose_reports_on_stderr_only(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    source.write_bytes(b"verbose payload " * 20)

    encoded = run("enc", "-v", str(source))
    decoded = run("dec", "-v", input=encoded.stdout_bytes)

    assert "encoded 320 bytes from 'source.txt' (name embedded)" in encoded.stderr
    assert decoded.stdout_bytes == b"verbose payload " * 20
    assert decoded.stderr == "text-serdes: decoded 320 bytes (zlib, embedded filename: 'source.txt') to stdout\n"


def test_help_and_version() -> None:
    top = run("-h")
    assert top.exit_code == 0
    assert "enc" in top.stdout and "dec" in top.stdout

    assert run("dec", "--help").exit_code == 0
    assert run("--version").stdout.strip().endswith("0.2.0")
    assert run("bogus").exit_code == 2


@pytest.mark.parametrize(
    "argv",
    [[sys.executable, "-m", "text_serdes"], [str(Path(sys.executable).parent / "text-serdes")]],
    ids=["module", "console-script"],
)
def test_installed_entry_points(argv: list[str]) -> None:
    encoded = subprocess.run([*argv, "enc"], input=b"real process", capture_output=True, check=True).stdout
    decoded = subprocess.run([*argv, "dec"], input=encoded, capture_output=True, check=True).stdout

    assert decoded == b"real process"


# -- ts shortcut -----------------------------------------------------------


def run_ts(*args: str, env: dict[str, str] | None = None) -> Result:
    from text_serdes.cli import ts

    return CliRunner().invoke(ts, list(args), env=env)


def test_ts_encodes_plain_file_next_to_input(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "note.txt").write_bytes(b"hello")

    result = run_ts("sub/note.txt")

    assert result.exit_code == 0
    assert (tmp_path / "sub" / "note.txt.ts").read_bytes().startswith(b"-ts-")


def test_ts_encodes_into_output_dir_when_it_exists(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    Path("note.txt").write_bytes(b"hello")

    result = run_ts("note.txt", env={"TEXT_SERDES_ENCODE_OUTPUT_DIR": str(out)})

    assert result.exit_code == 0
    assert (out / "note.txt.ts").exists()
    assert not Path("note.txt.ts").exists()


def test_ts_ignores_missing_output_dir(tmp_path: Path) -> None:
    Path("note.txt").write_bytes(b"hello")

    result = run_ts("note.txt", env={"TEXT_SERDES_ENCODE_OUTPUT_DIR": str(tmp_path / "nope")})

    assert result.exit_code == 0
    assert Path("note.txt.ts").exists()


def test_ts_encode_overwrites_existing_output() -> None:
    Path("note.txt").write_bytes(b"hello")
    Path("note.txt.ts").write_bytes(b"old")

    assert run_ts("note.txt").exit_code == 0
    assert Path("note.txt.ts").read_bytes().startswith(b"-ts-")

def test_ts_decodes_to_embedded_filename_and_overwrites(tmp_path: Path) -> None:
    Path("note.txt").write_bytes(b"original\x00")
    assert run_ts("note.txt").exit_code == 0
    Path("note.txt").write_bytes(b"clobber me")

    result = run_ts("note.txt.ts")

    assert result.exit_code == 0
    assert Path("note.txt").read_bytes() == b"original\x00"


def test_ts_decode_uses_only_basename_of_embedded_name(tmp_path: Path) -> None:
    from text_serdes.codec import encode, wrap

    Path("evil.ts").write_text(wrap(encode(b"x", filename="../../escape.txt"), 100))

    assert run_ts("evil.ts").exit_code == 0
    assert Path("escape.txt").read_bytes() == b"x"


def test_ts_decode_without_embedded_filename_fails() -> None:
    from text_serdes.codec import encode

    Path("anon.ts").write_text(encode(b"x"))

    result = run_ts("anon.ts")

    assert result.exit_code != 0
    assert "no embedded filename" in result.stderr


def test_ts_wrong_passphrase_fails_without_reencoding() -> None:
    Path("note.txt").write_bytes(b"hello")
    assert run_ts("note.txt", env={"TS_KEY": "a"}).exit_code == 0

    result = run_ts("note.txt.ts", env={"TS_KEY": "b"})

    assert result.exit_code != 0
    assert not Path("note.txt.ts.ts").exists()
