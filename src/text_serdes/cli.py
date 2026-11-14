from __future__ import annotations

import os
from pathlib import Path

import rich_click as click

from .codec import CodecError, decode, encode, wrap

WRAP_COLUMNS = 100
ALIASES = {"encode": "enc", "decode": "dec"}

input_argument = click.argument("input_file", required=False, type=click.Path(dir_okay=False, allow_dash=True))
force_option = click.option("-f", "--force", is_flag=True, help="Overwrite the output file if it already exists.")
verbose_option = click.option("-v", "--verbose", is_flag=True, help="Describe what was done on stderr.")


class AliasGroup(click.RichGroup):
    def get_command(self, ctx: click.Context, cmd_name: str) -> click.Command | None:
        return super().get_command(ctx, ALIASES.get(cmd_name, cmd_name))


@click.group(cls=AliasGroup, context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(package_name="text-serdes")
def main() -> None:
    """Mangle text or files for transport over copy/paste interfaces.

    Set TS_KEY to fold a passphrase into the key; it must match on both sides.
    """


@main.command()
@input_argument
@click.option("-o", "--output", type=click.Path(path_type=Path, dir_okay=False), help="Write to FILE instead of stdout.")
@force_option
@verbose_option
def enc(input_file: str | None, output: Path | None, force: bool, verbose: bool) -> None:
    """Compress, encrypt, and encode INPUT_FILE, or stdin when omitted.

    A named INPUT_FILE has its basename embedded in the payload. Alias: encode.
    """
    try:
        source = _source(input_file)
        data = _read(source)
        filename = None if source is None else source.name
        encoded = encode(data, filename=filename, passphrase=_passphrase())
        _write(wrap(encoded, WRAP_COLUMNS).encode("ascii") + b"\n", output, force)
    except (OSError, CodecError) as exc:
        raise click.ClickException(str(exc)) from exc

    if verbose:
        source = "stdin" if filename is None else f"{filename!r} (name embedded)"
        _note(f"encoded {len(data)} bytes from {source} into {len(encoded)} characters")


@main.command()
@input_argument
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    help="Write to PATH instead of stdout. If PATH is a directory, use the filename embedded in the payload.",
)
@force_option
@verbose_option
def dec(input_file: str | None, output: Path | None, force: bool, verbose: bool) -> None:
    """Decode, decrypt, and decompress INPUT_FILE, or stdin when omitted.

    The input may be a messy paste; everything outside the payload markers is
    ignored. Output goes to stdout unless --output is given. Alias: decode.
    """
    try:
        text = _read(_source(input_file)).decode("utf-8", errors="replace")
        decoded = decode(text, passphrase=_passphrase())
        target = output
        if output is not None and output.is_dir():
            if decoded.filename is None:
                raise CodecError("--output is a directory, but the payload has no embedded filename")
            # Never trust a path from the payload: keep only its final component.
            target = output / Path(decoded.filename).name
        _write(decoded.data, target, force)
    except (OSError, CodecError) as exc:
        raise click.ClickException(str(exc)) from exc

    if verbose:
        name = "none" if decoded.filename is None else repr(decoded.filename)
        packing = "zlib" if decoded.compressed else "raw"
        destination = "stdout" if target is None else str(target)
        _note(f"decoded {len(decoded.data)} bytes ({packing}, embedded filename: {name}) to {destination}")


def _source(input_file: str | None) -> Path | None:
    """Return the input path, or None when input comes from stdin."""
    return None if input_file is None or input_file == "-" else Path(input_file)


def _passphrase() -> str:
    return os.environ.get("TS_KEY", "")


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
        raise CodecError(f"{target} already exists; use --force to overwrite it") from exc


def _note(message: str) -> None:
    click.echo(f"text-serdes: {message}", err=True)
