# Contributing to re-unpacker

Thanks for your interest in improving re-unpacker. This document explains how
to set up a development environment, how the codebase is organized, the
patterns for adding new extraction / verification / classification capability,
and the standards every change is held to before it merges.

All participation in this project is governed by the
[Code of Conduct](CODE_OF_CONDUCT.md). Security vulnerabilities must be reported
privately per [SECURITY.md](SECURITY.md), never through public issues or pull
requests.

## Table of contents

1. [Ground rules](#ground-rules)
2. [Development setup](#development-setup)
3. [Project layout](#project-layout)
4. [Running the tests](#running-the-tests)
5. [Coding standards](#coding-standards)
6. [Adding an extractor](#adding-an-extractor)
7. [Adding a verifier](#adding-a-verifier)
8. [Adding a classifier](#adding-a-classifier)
9. [Adding a file kind](#adding-a-file-kind)
10. [Documentation](#documentation)
11. [Commit and pull-request process](#commit-and-pull-request-process)
12. [Pull-request checklist](#pull-request-checklist)

## Ground rules

- **Security first.** re-unpacker processes untrusted, often malicious input.
  Every subprocess call is an `argv` list; never build a command string from a
  filename, and never pass `shell=True`. New code must respect the timeout,
  bounded-output-capture, quota, and path-traversal-audit machinery already in
  place.
- **No runtime Python dependencies.** Extraction is performed via external
  system binaries. Do not add a package to `dependencies` in
  `pyproject.toml`. Optional Python bindings (for example ssdeep, yara, tlsh)
  are detected at runtime and used only when present; they are never required.
- **Complete changes only.** No placeholders, stubs, or partial
  implementations unless explicitly requested in the issue. Wire changes end to
  end: callers, signatures, return contracts, and error paths.
- **No em-dash.** The U+2014 character must not appear anywhere in code,
  comments, documentation, or output. Use `--`, `-`, `:`, or `,`. This is a
  hard rule enforced in CI.

## Development setup

re-unpacker targets Python 3.10 or newer and has no runtime Python
dependencies. Clone the repository and run straight from the tree, or install
in editable mode.

```bash
git clone https://github.com/Sandler73/RE-Unpacker.git
cd re-unpacker

# Option A: run straight from the clone (no install).
./re-unpacker --version

# Option B: editable install into a virtual environment.
python3 -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\Activate.ps1
pip install -e .
re-unpacker --version
```

For development you will also want the test and lint tooling:

```bash
pip install pytest ruff mypy
```

The extraction tools themselves (dpkg-deb, 7-Zip, binwalk, and so on) are
installed via the system package manager. On a fresh Kali / Debian / Ubuntu
box you can let re-unpacker provision them:

```bash
sudo ./re-unpacker --install --yes
```

See [`docs/SETUP_GUIDE.md`](docs/SETUP_GUIDE.md) for the full per-platform
provisioning instructions.

## Project layout

```text
src/re_unpacker/
  cli.py                 CLI surface, argument parsing, mode dispatch
  orchestrator.py        RecursiveUnpacker: BFS work queue, dedup, dispatch
  detection.py           FileKind enum + three-layer detect_file()
  constants.py           version, schema, tool package hints, magic table
  tools.py               ToolRegistry: probe/version external binaries
  pkg_manager.py         apt (Linux) and winget (Windows) install backends
  manual_install_windows.py   per-tool auto-install handlers for Windows
  platform_compat.py     OS detection, cache/config dirs, PATH probing
  safety.py              path-traversal audit, quota tracker, hashing
  manifest.py            ManifestBuilder, FileEntry, ErrorEntry, RunStats
  reporting.py           tree.txt and summary.txt generation
  logging_setup.py       dual console/file logging configuration
  subprocess_utils.py    argv-only subprocess execution, BOM-aware decoding
  exceptions.py          exception hierarchy
  extractors/            one module per format family; base.py has the registry
  verifiers/             signature/integrity verifiers; base.py has the registry
  classifiers/           enrichment passes; base.py has the registry
docs/                    Markdown guides + HTML companions
tests/                   pytest suite
wiki/                    mirrored wiki pages (parity with docs/)
```

The orchestrator does not hardcode any format. It asks the registries what can
handle a detected kind and dispatches accordingly, so new capability is added
by writing a class and registering it, never by editing the orchestrator.

## Running the tests

```bash
# From the repository root:
python -m pytest -q

# With coverage of the package:
python -m pytest --cov=re_unpacker -q
```

The suite is designed to run without the external extraction binaries present:
tool-dependent behavior is exercised through the registry and detection layers,
which degrade gracefully when a tool is absent. Tests that would require a
specific binary skip themselves when it is missing rather than failing.

## Coding standards

- **Header block.** Every module carries a docstring header with Synopsis /
  Description / Notes / Version sections (see any existing module for the
  house style). Scripts and wrappers carry the equivalent comment header.
- **Type hints.** Use modern typing (`X | None`, `list[str]`,
  `frozenset[FileKind]`). The codebase targets 3.10+ union syntax.
- **Minimal diffs.** Match existing naming, structure, and conventions. Do not
  reformat unrelated code or introduce a new style mid-project.
- **Evidence, not guesses.** Magic bytes, package names, and tool flags must be
  verified against the format specification, the tool's own documentation, or
  the distribution package, not recalled from memory. Cite the source in a
  comment where it is non-obvious.
- **Lint and type-check** before opening a PR:

  ```bash
  ruff check src/ tests/
  mypy src/re_unpacker
  ```

## Adding an extractor

Extractors live in `src/re_unpacker/extractors/`. Subclass
`re_unpacker.extractors.base.Extractor` and declare:

- `name: str` -- stable identifier used in manifest `extractor` fields and
  `_secondary_<name>/` directory names.
- `handles_kinds: frozenset[FileKind]` -- the kinds this extractor can open.
- `required_tools: tuple[str, ...]` -- binaries that must be on PATH. The
  registry auto-filters an extractor whose tools are missing, which is how
  platform-specific extractors coexist in one source tree.
- `priority: int` -- higher wins when multiple extractors handle a kind.
- `is_secondary: bool` -- `True` for resource / section dumpers that run
  alongside the primary extraction rather than instead of it.

Implement `extract(self, ctx: ExtractionContext) -> ExtractionResult`. Honor
the dispatch-chain contract precisely:

- Raise `ExtractorNotApplicable` when the extractor inspects the file and
  decides it is not the right job. The orchestrator catches this silently and
  tries the next extractor; it is **not** recorded as a manifest error.
- Raise `ExtractorFailure` when the extractor tried and failed (non-zero exit,
  malformed output). This is recorded as a manifest error and the orchestrator
  tries the next candidate.
- Let `ExtractorTimeout` propagate from the subprocess helper on timeout.

Register the instance in `build_default_registry()` in
`extractors/base.py` (primary or secondary tuple as appropriate). Add or extend
a test that exercises the new extractor's dispatch and its not-applicable path.

## Adding a verifier

Verifiers live in `src/re_unpacker/verifiers/`. Subclass the base `Verifier`,
declare `required_tools`, and implement the verification method so it records
`performed`, `applicable`, `signed`, `valid`, `signer`, and `error` per the
manifest `verification` schema. Verifiers run best-effort after a successful
extraction and are exempt from the classifier size cap. Register the instance
in `build_default_verifier_registry()` in `verifiers/base.py`.

## Adding a classifier

Classifiers live in `src/re_unpacker/classifiers/`. Subclass the base
`Classifier` and implement the enrichment pass. Classifiers honor
`--enrich-timeout` and the 256 MiB `ENRICHMENT_SIZE_CAP_BYTES`; files above the
cap record `enrichment_skipped="size_exceeds_cap"`. Prefer a Python binding
when one is present (see `PYTHON_BINDINGS` in `constants.py`) and fall back to
the CLI tool. Provide a `--no-<name>` opt-out flag in `cli.py`. Register the
instance in `build_default_classifier_registry()` in `classifiers/base.py`.

## Adding a file kind

New kinds are added to the `FileKind` enum in `detection.py`. If the kind has a
reliable magic signature, add it to `MAGIC_SIGNATURES` in `constants.py` with
the byte sequence and offset verified against the format specification. Add an
`EXTENSION_HINTS` entry only as a tertiary tiebreaker. Then add an extractor (or
mark the kind terminal-classify-only, as LUKS and encrypted-generic are).

## Documentation

Documentation is part of the change, not a follow-up. When behavior changes:

- Update the relevant `docs/` guide and its mirrored `wiki/` page together so
  they stay at parity.
- Add a dated, described entry to [`CHANGELOG.md`](CHANGELOG.md) following Keep
  a Changelog and Semantic Versioning.
- Keep the README's counts and schema notes accurate.

Read the existing document first and edit in place, preserving structure and
terminology. Do not replace a document with a fresh rewrite.

## Commit and pull-request process

1. Open an issue describing the problem or proposal before large work, so scope
   can be agreed. For ambiguous scope, ask rather than assume.
2. Branch from `main`. Keep the branch focused on one logical change.
3. Write clear commit messages: a concise summary line, then a body explaining
   the what and the why.
4. Ensure the pull-request checklist below is satisfied.
5. Automated checks (lint, type-check, tests, em-dash sweep) run on the PR.
   A maintainer reviews for correctness, security, and fit.

## Pull-request checklist

- [ ] `python -m pytest` passes locally.
- [ ] `ruff check` and `mypy src/re_unpacker` are clean (or deviations are
      justified in the PR description).
- [ ] No em-dash (U+2014) anywhere in the diff.
- [ ] No new runtime Python dependency added to `pyproject.toml`.
- [ ] Every subprocess call is argv-only, with no `shell=True`.
- [ ] New extractors / verifiers / classifiers are registered and declare
      `required_tools` correctly.
- [ ] Module header blocks are present and accurate.
- [ ] Documentation (`docs/` + mirrored `wiki/`) and `CHANGELOG.md` are updated.
- [ ] Magic bytes, package names, and tool flags are verified against an
      authoritative source, not recalled from memory.
- [ ] Security implications of the change are considered and described.
