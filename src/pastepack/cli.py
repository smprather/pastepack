from __future__ import annotations

import os
from pathlib import Path

import rich_click as click

from .codec import BEGIN_MARKER, PackError, find_payloads, pack, unpack, wrap

WRAP_COLUMNS = 100
OUTPUT_DIR_ENV = "PASTEPACK_OUTPUT_DIR"
PACKED_SUFFIX = ".pack"

input_argument = click.argument("input_file", required=False, type=click.Path(dir_okay=False, allow_dash=True))
force_option = click.option("-f", "--force", is_flag=True, help="Overwrite the output file if it already exists.")
verbose_option = click.option("-v", "--verbose", is_flag=True, help="Describe what was done on stderr.")


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(package_name="pastepack")
def main() -> None:
    """Pack any file or stream into text that survives copy/paste, and unpack it.

    Set PASTEPACK_KEY to fold a passphrase into the key; it must match on both sides.
    """


@main.command("pack")
@input_argument
@click.option("-o", "--output", type=click.Path(path_type=Path, dir_okay=False), help="Write to FILE instead of stdout.")
@force_option
@verbose_option
def pack_command(input_file: str | None, output: Path | None, force: bool, verbose: bool) -> None:
    """Compress, encrypt, and encode INPUT_FILE as text, or stdin when omitted.

    A named INPUT_FILE has its basename embedded in the payload.
    """
    try:
        source = _source(input_file)
        data = _read(source)
        filename = None if source is None else source.name
        packed = pack(data, filename=filename, passphrase=_passphrase())
        _write(wrap(packed, WRAP_COLUMNS).encode("ascii") + b"\n", output, force)
    except (OSError, PackError) as exc:
        raise click.ClickException(str(exc)) from exc

    if verbose:
        source = "stdin" if filename is None else f"{filename!r} (name embedded)"
        _note(f"packed {len(data)} bytes from {source} into {len(packed)} characters")


@main.command("unpack")
@input_argument
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    help="Write to PATH instead of stdout. If PATH is a directory, use the filename embedded in the payload.",
)
@force_option
@verbose_option
def unpack_command(input_file: str | None, output: Path | None, force: bool, verbose: bool) -> None:
    """Find the payload in INPUT_FILE, or stdin when omitted, and restore it.

    The input may be a messy paste; everything outside the payload markers is
    ignored. Output goes to stdout unless --output is given.
    """
    try:
        text = _read(_source(input_file)).decode("utf-8", errors="replace")
        unpacked = unpack(text, passphrase=_passphrase())
        target = output
        if output is not None and output.is_dir():
            if unpacked.filename is None:
                raise PackError("--output is a directory, but the payload has no embedded filename")
            # Never trust a path from the payload: keep only its final component.
            target = output / Path(unpacked.filename).name
        _write(unpacked.data, target, force)
    except (OSError, PackError) as exc:
        raise click.ClickException(str(exc)) from exc

    if verbose:
        name = "none" if unpacked.filename is None else repr(unpacked.filename)
        packing = "zlib" if unpacked.compressed else "raw"
        destination = "stdout" if target is None else str(target)
        _note(f"unpacked {len(unpacked.data)} bytes ({packing}, embedded filename: {name}) to {destination}")


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(package_name="pastepack")
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def pp(input_file: Path) -> None:
    """Toggle INPUT_FILE between plain and packed.

    If INPUT_FILE holds a packed payload with an embedded filename, the
    original is written to ./<filename>. If it holds no payload, it is packed
    to <name>.pack, in the directory named by PASTEPACK_OUTPUT_DIR when
    that directory exists, otherwise next to INPUT_FILE. Existing output files
    are always overwritten.
    """
    try:
        data = input_file.read_bytes()
        text = data.decode("utf-8", errors="replace")
        if find_payloads(text) or BEGIN_MARKER in text:
            unpacked = unpack(text, passphrase=_passphrase())
            if unpacked.filename is None:
                raise PackError("payload has no embedded filename; use 'pastepack unpack' instead")
            # Never trust a path from the payload: keep only its final component.
            target = Path(Path(unpacked.filename).name)
            _write(unpacked.data, target, True)
            _note(f"unpacked {input_file} to {target}")
        else:
            out_dir = _pack_dir(input_file)
            target = out_dir / (input_file.name + PACKED_SUFFIX)
            packed = pack(data, filename=input_file.name, passphrase=_passphrase())
            _write(wrap(packed, WRAP_COLUMNS).encode("ascii") + b"\n", target, True)
            _note(f"packed {input_file} to {target}")
    except (OSError, PackError) as exc:
        raise click.ClickException(str(exc)) from exc


def _pack_dir(input_file: Path) -> Path:
    configured = os.environ.get(OUTPUT_DIR_ENV)
    if configured and Path(configured).expanduser().is_dir():
        return Path(configured).expanduser()
    return input_file.parent


def _source(input_file: str | None) -> Path | None:
    """Return the input path, or None when input comes from stdin."""
    return None if input_file is None or input_file == "-" else Path(input_file)


def _passphrase() -> str:
    return os.environ.get("PASTEPACK_KEY", "")


def _read(source: Path | None) -> bytes:
    if source is None:
        return click.get_binary_stream("stdin").read()
    return source.read_bytes()


def _write(payload: bytes, target: Path | None, force: bool) -> None:
    if target is None:
        click.get_binary_stream("stdout").write(payload)
        return
    try:
        with open(target, "wb" if force else "xb") as handle:
            handle.write(payload)
    except FileExistsError as exc:
        raise PackError(f"{target} already exists; use --force to overwrite it") from exc


def _note(message: str) -> None:
    click.echo(f"pastepack: {message}", err=True)
