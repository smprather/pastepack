# Repository Guidelines

## Project Structure & Module Organization

This is a small Python CLI project. Runtime code lives in `src/text_serdes/`, with the `text-serdes` command group in `src/text_serdes/cli.py` and encode/decode logic in `src/text_serdes/codec.py`. Tests live in `tests/`, split into `test_codec.py` and `test_cli.py`. Package metadata, dependencies, console scripts, and pytest discovery settings are in `pyproject.toml`.

## Build, Test, and Development Commands

- `uv sync`: create or update the local virtual environment.
- `uv run text-serdes enc [input_file]`: compress, encrypt, Base91 encode, and print framed text to stdout.
- `uv run text-serdes dec [input_file]`: find the framed payload, Base91 decode, decrypt, decompress, and print the original bytes.
- `uv run pytest -q`: run the root test suite.

Commands should be run from the repository root, `/home/mylesp/text-serdes`.

## Coding Style & Naming Conventions

Target Python >=3.12. Use 4-space indentation, type hints for public functions, and `snake_case` for modules, functions, and variables. Keep CLI behavior small and predictable: each subcommand takes one optional positional input file, otherwise reads stdin until EOF, and writes to stdout unless `--output` is given. Never overwrite a file without `--force`. Keep generated files such as `__pycache__/`, build artifacts, and virtual environments out of git.

## Testing Guidelines

Use `pytest`. Test files should be named `test_*.py`, and tests should cover both library functions and CLI behavior. For codec changes, include round-trip tests, malformed input tests, and passphrase-mismatch tests. Any wire format change must bump `FORMAT_VERSION`. For CLI changes, verify file input, stdin input, stdout formatting, stderr errors, and exit codes.

## Commit & Pull Request Guidelines

Use short imperative commit subjects such as `Add daily codec CLI` or `Handle malformed Base91 input`. Keep commits focused. Pull requests should describe behavior changes, list verification commands, link related issues when relevant, and call out any CLI compatibility changes.

## Security & Configuration Tips

By default the key material travels inside the payload, so the output is obfuscated rather than secret: this tool is for simple short-lived transport, not high-security storage. Setting `TS_KEY` folds a passphrase into the key (via scrypt); only then does decoding require a secret. Treat any filename embedded in a payload as untrusted and use only its basename.
