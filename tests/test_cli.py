from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner, Result

from pastepack import cli
from pastepack.cli import main


def run(*args: str, input: bytes | None = None, env: dict[str, str] | None = None) -> Result:
    return CliRunner().invoke(main, list(args), input=input, env=env)


def pack_cli(*args: str, input: bytes | None = None, env: dict[str, str] | None = None) -> bytes:
    result = run("pack", *args, input=input, env=env)
    assert result.exit_code == 0, result.stderr
    return result.stdout_bytes


@pytest.fixture(autouse=True)
def in_tmp_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("PASTEPACK_KEY", raising=False)


def test_stdin_round_trip() -> None:
    plaintext = b"from stdin\nwith newline\n\x00\xff"

    packed = pack_cli(input=plaintext)
    result = run("unpack", input=packed)

    assert packed.startswith(b"-pack-")
    assert packed.endswith(b"-end-\n")
    assert result.exit_code == 0
    assert result.stdout_bytes == plaintext
    assert result.stderr == ""


def test_dash_means_stdin() -> None:
    packed = pack_cli("-", input=b"dash")

    assert run("unpack", "-", input=packed).stdout_bytes == b"dash"


def test_enc_wraps_long_output() -> None:
    plaintext = os.urandom(4096)

    packed = pack_cli(input=plaintext)

    lines = packed.splitlines()
    assert len(lines) > 1
    assert max(len(line) for line in lines) == 150
    assert run("unpack", input=packed).stdout_bytes == plaintext


def test_columns_option_sets_the_width() -> None:
    plaintext = os.urandom(2048)

    packed = pack_cli("--columns", "40", input=plaintext)

    assert max(len(line) for line in packed.splitlines()) == 40
    assert run("unpack", input=packed).stdout_bytes == plaintext


@pytest.mark.parametrize("value", ["0", "-1"])
def test_columns_must_be_positive(value: str) -> None:
    result = run("pack", "--columns", value, input=b"x")

    assert result.exit_code == 2
    assert "--columns" in result.stderr


def test_default_width_clamps_to_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLUMNS", "60")
    monkeypatch.setattr(cli, "_stdout_is_terminal", lambda: True)

    packed = pack_cli(input=os.urandom(2048))

    assert max(len(line) for line in packed.splitlines()) == 60


def test_explicit_width_ignores_the_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLUMNS", "60")
    monkeypatch.setattr(cli, "_stdout_is_terminal", lambda: True)

    packed = pack_cli("--columns", "120", input=os.urandom(2048))

    assert max(len(line) for line in packed.splitlines()) == 120


def test_file_output_ignores_the_terminal(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("COLUMNS", "60")
    monkeypatch.setattr(cli, "_stdout_is_terminal", lambda: True)
    target = tmp_path / "packed.txt"

    assert run("pack", "-o", str(target), input=os.urandom(2048)).exit_code == 0

    assert max(len(line) for line in target.read_bytes().splitlines()) == 150


def test_file_input_unpacks_to_stdout_and_leaves_files_alone(tmp_path: Path) -> None:
    source = tmp_path / "message.txt"
    source.write_bytes(b"file bytes\n")
    packed = pack_cli(str(source))
    source.write_bytes(b"changed since packing\n")

    result = run("unpack", input=packed)

    assert result.stdout_bytes == b"file bytes\n"
    assert source.read_bytes() == b"changed since packing\n"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["message.txt"]


def test_unpack_reads_packed_file(tmp_path: Path) -> None:
    packed_file = tmp_path / "packed.txt"
    packed_file.write_bytes(pack_cli(input=b"from a packed file"))

    assert run("unpack", str(packed_file)).stdout_bytes == b"from a packed file"


def test_enc_output_file(tmp_path: Path) -> None:
    target = tmp_path / "packed.txt"

    result = run("pack", "-o", str(target), input=b"to a file")

    assert result.exit_code == 0
    assert result.stdout_bytes == b""
    assert run("unpack", str(target)).stdout_bytes == b"to a file"


def test_unpack_output_file(tmp_path: Path) -> None:
    source = tmp_path / "embedded.txt"
    source.write_bytes(b"payload with file name")
    target = tmp_path / "chosen.txt"

    result = run("unpack", "--output", str(target), input=pack_cli(str(source)))

    assert result.exit_code == 0
    assert result.stdout_bytes == b""
    assert target.read_bytes() == b"payload with file name"


def test_unpack_output_directory_uses_embedded_filename(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    source.write_bytes(b"directory target")
    out = tmp_path / "out"
    out.mkdir()

    result = run("unpack", "-o", str(out), input=pack_cli(str(source)))

    assert result.exit_code == 0
    assert (out / "source.txt").read_bytes() == b"directory target"


def test_unpack_output_directory_requires_embedded_filename(tmp_path: Path) -> None:
    result = run("unpack", "-o", str(tmp_path), input=pack_cli(input=b"plain stdin payload"))

    assert result.exit_code == 1
    assert "no embedded filename" in result.stderr
    assert list(tmp_path.iterdir()) == []


def test_embedded_filename_cannot_escape_output_directory(tmp_path: Path) -> None:
    from pastepack import pack

    out = tmp_path / "out"
    out.mkdir()
    hostile = pack(b"contained", filename="../../escape.txt").encode("ascii")

    result = run("unpack", "-o", str(out), input=hostile)

    assert result.exit_code == 0
    assert (out / "escape.txt").read_bytes() == b"contained"
    assert not (tmp_path / "escape.txt").exists()


@pytest.mark.parametrize("command", ["pack", "unpack"])
def test_existing_output_needs_force(tmp_path: Path, command: str) -> None:
    target = tmp_path / "existing.txt"
    target.write_bytes(b"precious")
    data = b"input" if command == "pack" else pack_cli(input=b"input")

    refused = run(command, "-o", str(target), input=data)

    assert refused.exit_code == 1
    assert "already exists" in refused.stderr
    assert target.read_bytes() == b"precious"

    forced = run(command, "-o", str(target), "--force", input=data)

    assert forced.exit_code == 0
    assert target.read_bytes() != b"precious"


def test_unpack_directory_target_needs_force(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    source.write_bytes(b"original")
    packed = pack_cli(str(source))

    refused = run("unpack", "-o", str(tmp_path), input=packed)
    assert refused.exit_code == 1
    assert "already exists" in refused.stderr

    source.write_bytes(b"clobber me")
    assert run("unpack", "-o", ".", "-f", input=packed).exit_code == 0
    assert source.read_bytes() == b"original"


def test_pp_key_must_match() -> None:
    packed = pack_cli(input=b"with passphrase", env={"PASTEPACK_KEY": "swordfish"})

    assert run("unpack", input=packed, env={"PASTEPACK_KEY": "swordfish"}).stdout_bytes == b"with passphrase"

    wrong = run("unpack", input=packed, env={"PASTEPACK_KEY": "wrong"})
    assert wrong.exit_code == 1
    assert "passphrase" in wrong.stderr

    assert run("unpack", input=packed).exit_code == 1


def test_bad_input_reports_error_on_stderr() -> None:
    result = run("unpack", input=b"\xff\xfe not a payload")

    assert result.exit_code == 1
    assert result.stdout_bytes == b""
    assert "no payload found" in result.stderr


def test_missing_input_file_fails(tmp_path: Path) -> None:
    for command in ("pack", "unpack"):
        result = run(command, str(tmp_path / "missing.txt"))

        assert result.exit_code == 1
        assert "missing.txt" in result.stderr


def test_verbose_reports_on_stderr_only(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    source.write_bytes(b"verbose payload " * 20)

    packed = run("pack", "-v", str(source))
    unpacked = run("unpack", "-v", input=packed.stdout_bytes)

    assert "packed 320 bytes from 'source.txt' (name embedded)" in packed.stderr
    assert unpacked.stdout_bytes == b"verbose payload " * 20
    assert unpacked.stderr == "pastepack: unpacked 320 bytes (zlib, embedded filename: 'source.txt') to stdout\n"


def test_help_and_version() -> None:
    top = run("-h")
    assert top.exit_code == 0
    assert "pack" in top.stdout and "unpack" in top.stdout

    assert run("unpack", "--help").exit_code == 0
    assert run("--version").stdout.strip().endswith("0.1.0")
    assert run("bogus").exit_code == 2


@pytest.mark.parametrize(
    "argv",
    [[sys.executable, "-m", "pastepack"], [str(Path(sys.executable).parent / "pastepack")]],
    ids=["module", "console-script"],
)
def test_installed_entry_points(argv: list[str]) -> None:
    packed = subprocess.run([*argv, "pack"], input=b"real process", capture_output=True, check=True).stdout
    unpacked = subprocess.run([*argv, "unpack"], input=packed, capture_output=True, check=True).stdout

    assert unpacked == b"real process"


# -- pp shortcut -----------------------------------------------------------


def run_pp(*args: str, env: dict[str, str] | None = None) -> Result:
    from pastepack.cli import pp

    return CliRunner().invoke(pp, list(args), env=env)


def test_pp_packs_plain_file_next_to_input(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "note.txt").write_bytes(b"hello")

    result = run_pp("sub/note.txt")

    assert result.exit_code == 0
    assert (tmp_path / "sub" / "note.txt.pack").read_bytes().startswith(b"-pack-")


def test_pp_prints_the_equivalent_pack_command() -> None:
    Path("note.txt").write_bytes(b"hello")

    result = run_pp("note.txt")

    assert result.stdout == ""
    assert result.stderr == "pastepack pack --force --output note.txt.pack --columns 150 note.txt\n"


def test_pp_prints_the_equivalent_unpack_command() -> None:
    Path("note.txt").write_bytes(b"hello")
    assert run_pp("note.txt").exit_code == 0

    result = run_pp("note.txt.pack")

    assert result.stdout == ""
    assert result.stderr == "pastepack unpack --force --output note.txt note.txt.pack\n"


def test_pp_quotes_awkward_paths_in_the_printed_command() -> None:
    Path("my note.txt").write_bytes(b"hello")

    result = run_pp("my note.txt")

    assert result.stderr == (
        "pastepack pack --force --output 'my note.txt.pack' --columns 150 'my note.txt'\n"
    )


def test_pp_printed_pack_command_produces_the_same_payload() -> None:
    Path("sub").mkdir()
    Path("sub/note.txt").write_bytes(b"hello\x00")
    argv = shlex.split(run_pp("sub/note.txt").stderr)
    assert argv[0] == "pastepack"
    Path("sub/note.txt.pack").unlink()

    result = run(*argv[1:])

    assert result.exit_code == 0, result.stderr
    assert run("unpack", "sub/note.txt.pack").stdout_bytes == b"hello\x00"


def test_pp_printed_unpack_command_restores_the_same_file() -> None:
    Path("note.txt").write_bytes(b"payload")
    assert run_pp("note.txt").exit_code == 0
    Path("note.txt").unlink()
    argv = shlex.split(run_pp("note.txt.pack").stderr)
    assert argv[0] == "pastepack"
    Path("note.txt").unlink()

    result = run(*argv[1:])

    assert result.exit_code == 0, result.stderr
    assert Path("note.txt").read_bytes() == b"payload"


def test_pp_packs_into_output_dir_when_it_exists(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    Path("note.txt").write_bytes(b"hello")

    result = run_pp("note.txt", env={"PASTEPACK_OUTPUT_DIR": str(out)})

    assert result.exit_code == 0
    assert (out / "note.txt.pack").exists()
    assert not Path("note.txt.pack").exists()


def test_pp_ignores_missing_output_dir(tmp_path: Path) -> None:
    Path("note.txt").write_bytes(b"hello")

    result = run_pp("note.txt", env={"PASTEPACK_OUTPUT_DIR": str(tmp_path / "nope")})

    assert result.exit_code == 0
    assert Path("note.txt.pack").exists()


def test_pp_pack_overwrites_existing_output() -> None:
    Path("note.txt").write_bytes(b"hello")
    Path("note.txt.pack").write_bytes(b"old")

    assert run_pp("note.txt").exit_code == 0
    assert Path("note.txt.pack").read_bytes().startswith(b"-pack-")


def test_pp_unpacks_to_embedded_filename_and_overwrites(tmp_path: Path) -> None:
    Path("note.txt").write_bytes(b"original\x00")
    assert run_pp("note.txt").exit_code == 0
    Path("note.txt").write_bytes(b"clobber me")

    result = run_pp("note.txt.pack")

    assert result.exit_code == 0
    assert Path("note.txt").read_bytes() == b"original\x00"


def test_pp_unpack_uses_only_basename_of_embedded_name(tmp_path: Path) -> None:
    from pastepack.codec import pack, wrap

    Path("evil.pack").write_text(wrap(pack(b"x", filename="../../escape.txt"), 100))

    assert run_pp("evil.pack").exit_code == 0
    assert Path("escape.txt").read_bytes() == b"x"


def test_pp_unpack_without_embedded_filename_fails() -> None:
    from pastepack.codec import pack

    Path("anon.pack").write_text(pack(b"x"))

    result = run_pp("anon.pack")

    assert result.exit_code != 0
    assert "no embedded filename" in result.stderr


def test_pp_wrong_passphrase_fails_without_repacking() -> None:
    Path("note.txt").write_bytes(b"hello")
    assert run_pp("note.txt", env={"PASTEPACK_KEY": "a"}).exit_code == 0

    result = run_pp("note.txt.pack", env={"PASTEPACK_KEY": "b"})

    assert result.exit_code != 0
    assert not Path("note.txt.pack.pack").exists()


def test_pp_packs_file_that_only_mentions_a_payload() -> None:
    from pastepack.codec import pack

    Path("doc.md").write_text(f"An example payload:\n\n{pack(b'sample')}\n")

    assert run_pp("doc.md").exit_code == 0
    assert Path("doc.md.pack").read_bytes().startswith(b"-pack-")


def test_pp_unpacks_file_that_begins_with_a_payload_whatever_its_name() -> None:
    from pastepack.codec import pack

    Path("saved.txt").write_text("\n  " + pack(b"x", filename="orig.txt") + "\n")

    assert run_pp("saved.txt").exit_code == 0
    assert Path("orig.txt").read_bytes() == b"x"
    assert not Path("saved.txt.pack").exists()


def test_pp_pack_suffix_without_payload_fails_without_repacking() -> None:
    Path("empty.pack").write_text("nothing packed here")

    result = run_pp("empty.pack")

    assert result.exit_code != 0
    assert "no payload found" in result.stderr
    assert not Path("empty.pack.pack").exists()
