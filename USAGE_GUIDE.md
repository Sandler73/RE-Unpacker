# re-unpacker Usage Guide

This guide is the recipe-driven handbook for re-unpacker: every CLI mode, every
flag, and the common workflows. For installation see
[SETUP_GUIDE.md](SETUP_GUIDE.md); for problems see
[TROUBLESHOOTING_GUIDE.md](TROUBLESHOOTING_GUIDE.md); for conceptual questions
see [FAQ.md](FAQ.md).

re-unpacker is at version 0.4.10 and writes a manifest at schema 1.1.0.

## Table of contents

1. [Invocation](#invocation)
2. [Quick start](#quick-start)
3. [How a run works](#how-a-run-works)
4. [Positional argument and output](#positional-argument-and-output)
5. [Recursion and performance flags](#recursion-and-performance-flags)
6. [Safety and resource limits](#safety-and-resource-limits)
7. [Feature flags](#feature-flags)
8. [Enrichment flags](#enrichment-flags)
9. [Filters](#filters)
10. [Modes](#modes)
11. [Logging and verbosity](#logging-and-verbosity)
12. [Reading the output](#reading-the-output)
13. [Programmatic use](#programmatic-use)
14. [Exit codes](#exit-codes)
15. [Full flag reference](#full-flag-reference)

## Invocation

re-unpacker can be launched five equivalent ways. Pick whichever fits your
platform and shell.

```text
Linux / macOS (bundled wrapper):   ./re-unpacker sample.deb
Windows PowerShell (preferred):    .\re-unpacker.ps1 sample.cab
Windows cmd.exe:                   re-unpacker.cmd sample.cab
Python module (any platform):      python -m re_unpacker sample.deb
Installed console script:          re-unpacker sample.deb
```

All five forward arguments to the same entry point and share an identical CLI
surface. The remainder of this guide writes `re-unpacker` for brevity; substitute
your launcher.

## Quick start

```bash
# Unpack a single file. Output goes to a derived directory next to your cwd.
re-unpacker ./sample.deb

# Unpack into an explicit output root, using 4 worker threads.
re-unpacker ./samples -o ./out -j 4

# See which extraction tools are installed and how to add the missing ones.
re-unpacker --tools-check

# Classify every file under a directory without extracting anything.
re-unpacker --dry-run ./samples
```

## How a run works

1. **Seed.** If the input is a file, it is the single seed. If it is a
   directory, re-unpacker walks it (honoring `--include` / `--exclude`) and
   seeds every regular file.
2. **Detect.** Each file's kind is determined by a three-layer detector: magic
   bytes (offset-aware), then `file(1)` / libmagic for disambiguation, then the
   extension as a tertiary tiebreaker. The reasons are recorded in the manifest
   `signals` list.
3. **Dispatch.** The orchestrator asks the extractor registry which extractors
   handle the detected kind and tries them in priority order until one
   succeeds. Secondary extractors (PE resources, ELF sections) then run
   alongside the primary output.
4. **Recurse.** Every newly extracted file is enqueued and processed the same
   way, up to `--max-depth`. Files are de-duplicated by SHA-256 so a
   byte-identical artifact appearing twice is extracted once.
5. **Enrich.** Verifiers (signature / integrity) and classifiers (entropy,
   fuzzy hash, exif, YARA) run best-effort per file.
6. **Report.** A consolidated `manifest.json`, a streaming `manifest.jsonl`,
   logs, a `tree.txt`, and a `summary.txt` are written to the output root.

## Positional argument and output

| Flag | Meaning |
|------|---------|
| `input` | File or directory to unpack. Required unless a non-extract mode is used (`--tools-check`, `--install`, `--uninstall`, `--repair`, `--dry-run-install`). |
| `-o`, `--output PATH` | Output root directory. Default: derived from the input name. |

## Recursion and performance flags

| Flag | Default | Meaning |
|------|---------|---------|
| `-d`, `--max-depth N` | 10 | Maximum recursion depth. |
| `-j`, `--jobs N` | 1 | Parallel worker threads. Sequential by default. |
| `--timeout SEC` | 1800 | Per-extraction timeout in seconds. |

Parallelism helps most on directories of many independent archives. A single
deeply nested archive is largely sequential regardless of `-j` because each
layer depends on the previous one.

## Safety and resource limits

| Flag | Default | Meaning |
|------|---------|---------|
| `--max-extracted-size N` | 50 GiB | Maximum bytes one archive may produce. |
| `--max-total-size N` | 500 GiB | Maximum bytes produced run-wide. |
| `--max-files N` | 1,000,000 | Maximum files one archive may produce. |

Enforcement has two layers. On POSIX, every extraction child runs under
`RLIMIT_FSIZE` sized to `--max-extracted-size`, so a single-file decompression
bomb is stopped by the kernel mid-write (preventive). In addition, after each
extraction step the produced byte and file counts are measured and checked
against all three ceilings; tripping any of them raises `SafetyLimitExceeded`,
exits with code 2, and preserves the partial output and manifest (detective, and
the primary guard on Windows, where `RLIMIT_FSIZE` is unavailable). Lower these
when triaging untrusted input on a constrained rig; raise them for legitimately
large disk images.

## Feature flags

Each of these defaults ON and has a `--no-` counterpart.

| Enable (default ON) | Disable | Meaning |
|---------------------|---------|---------|
| `--binwalk` | `--no-binwalk` | binwalk fallback for unknown binaries. |
| `--resources` | `--no-resources` | Extract PE resources and ELF sections. |
| `--hash` | `--no-hash` | Compute SHA-256 and MD5 for every file. |
| `--dedup` | `--no-dedup` | Skip re-processing files with an already-seen SHA-256. |

```bash
# Fast pass: no binwalk, no resource extraction.
re-unpacker firmware.bin --no-binwalk --no-resources

# Skip hashing on a very large input (also disables content-hash dedup value).
re-unpacker huge.iso --no-hash
```

## Enrichment flags

Classifiers can be disabled individually. Verifiers always run and have no
opt-out (they are cheap and best-effort).

| Flag | Meaning |
|------|---------|
| `--no-yara` | Skip YARA rule matching. |
| `--no-fuzzy-hash` | Skip ssdeep and TLSH fuzzy-hash computation. |
| `--no-exif` | Skip exiftool metadata extraction. |
| `--no-entropy` | Skip Shannon entropy (also disables the entropy-based encryption heuristic). |
| `--yara-rules PATH` | Use a specific YARA rules file or directory. Bypasses default auto-discovery. |
| `--enrich-timeout SEC` | Per-pass, per-file timeout for verifiers and classifiers. Default 30. |

When `--yara-rules` is not given, re-unpacker loads rules from its three default
directories as a union with namespacing so cross-directory rule-name collisions
resolve cleanly. Files larger than 256 MiB skip all classifier passes and record
`enrichment_skipped="size_exceeds_cap"`; verifiers are exempt from that cap.

## Filters

| Flag | Meaning |
|------|---------|
| `--include GLOB` | Only process files whose basename matches the glob. Repeatable. Applies to the initial seed walk only. |
| `--exclude GLOB` | Skip files whose basename matches the glob. Repeatable. |

```bash
# Only seed .deb and .rpm packages from a directory tree.
re-unpacker ./repo --include '*.deb' --include '*.rpm'

# Seed everything except large ISO images.
re-unpacker ./samples --exclude '*.iso'
```

Filters constrain which files are seeded from a directory. They do not stop
recursion into files discovered inside an archive.

## Modes

Modes are mutually exclusive. Extract mode is the default (no mode flag).

| Flag | Root/admin | Meaning |
|------|-----------|---------|
| `--tools-check` | no | Probe external tools, print a status table, and exit. |
| `--dry-run` | no | Detect file kinds without extracting anything. |
| `--install` | yes | Install all known unpack tools that are currently missing. |
| `--uninstall` | yes | Remove every currently-present unpack tool. |
| `--repair` | yes | Reinstall every currently-present unpack tool. |
| `--dry-run-install` | no | Print the exact package-manager commands install / uninstall / repair would run, without executing. |
| `-y`, `--yes` | -- | Skip the interactive confirmation prompt. |
| `--no-refresh-index` | -- | Skip the package-index refresh (apt-get update / winget source update) before `--install`. |

The package-management modes dispatch to the platform's package manager: `apt`
on Linux, `winget` on Windows. On Windows, `--install` additionally invokes the
per-tool manual-install handlers for tools that have no winget package.
`--uninstall` and `--repair` never touch the protected packages (`apt`, `dpkg`)
or protected tools (`apt-get`, `dpkg-query`), since removing them would break
the system.

```bash
# Preview what install would do, no changes, no root needed.
re-unpacker --dry-run-install

# Install everything missing, no prompt (needs root / Administrator).
sudo re-unpacker --install --yes

# Reinstall the present toolset after a partial package-manager failure.
sudo re-unpacker --repair
```

## Logging and verbosity

| Flag | Meaning |
|------|---------|
| `--log-level LEVEL` | Console log level: DEBUG, INFO, WARNING, ERROR, CRITICAL. Default INFO. Overrides `-v` / `-q` with a warning. |
| `-v`, `--verbose` | Increase verbosity. `-v` = INFO (default), `-vv` = DEBUG. |
| `-q`, `--quiet` | Decrease verbosity to WARNING. Mutually exclusive with `-v`. |
| `--log-file PATH` | Write the file log to PATH. Use `-` to disable file logging entirely. |

The file log always records at DEBUG regardless of console verbosity. In extract
mode the file log is always written to `<output>/extraction.log`. In non-extract
modes it defaults to a per-run file under the cache directory
(`$XDG_CACHE_HOME/re-unpacker/logs/` on Linux, the platform cache dir on
Windows).

```bash
# Quiet console, full DEBUG still captured in extraction.log.
re-unpacker ./samples -q

# Maximum console detail and an explicit log-file path.
re-unpacker ./sample.deb -vv --log-file ./run.log
```

## Reading the output

Every run writes this structure to the output root:

```text
<output_root>/
  manifest.json        consolidated final manifest (schema 1.1.0)
  manifest.jsonl       streaming JSONL, line-buffered, crash-resilient
  extraction.log       full DEBUG log
  errors.log           warnings and above, for quick triage
  tree.txt             tree-style listing of extracted/
  summary.txt          stats, top kinds, largest files, error summary
  extracted/
    <input-name>.unpacked/
      (primary extraction output)
      <nested>.unpacked/          recursive, same scheme at each depth
      _secondary_<extractor>/     PE resources, ELF sections, and similar
      _quarantine/                only present if a path-safety escape was caught
```

The `manifest.jsonl` is the friendliest for scripting. Each line is one record
whose `record_type` is `header`, `file`, `error`, or `footer`:

```bash
# Every extracted ELF, by path.
jq -c 'select(.record_type == "file" and .kind == "ELF") | .path' out/manifest.jsonl

# Files that a verifier flagged with a valid signature.
jq -c 'select(.record_type == "file") | select(.verification[]?.valid == true) | .rel_path' out/manifest.jsonl
```

See the [README manifest schema section](../README.md#manifest-schema) for the
full field-by-field description.

## Programmatic use

```python
from re_unpacker import main as cli_main

rc = cli_main(["./sample.deb", "-o", "./out", "--log-level", "WARNING"])
# rc is the same integer the CLI would have exited with.
```

For embedding the orchestrator directly inside a larger pipeline, see
`re_unpacker.cli._run_normal`, which is the canonical construction pattern for
logger, tool registry, manifest builder, quota tracker, and the
`RecursiveUnpacker`.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Run completed. Per-file errors, if any, are in the manifest; the run still succeeded. |
| 1 | Input path invalid or unreadable; no run attempted. |
| 2 | A safety limit tripped mid-run; partial output preserved. |
| 3 | `--tools-check`: one or more known tools are missing. |
| 4 | Unexpected fatal error (please file an issue). |
| 5 | Privilege required: install / uninstall / repair invoked without root. |
| 6 | Package-manager error during install / remove / reinstall. |

## Full flag reference

```text
positional:
  input                        File or directory to unpack.

output / recursion / limits:
  -o, --output PATH            Output root directory.
  -d, --max-depth N            Max recursion depth (default 10).
  -j, --jobs N                 Parallel worker threads (default 1).
      --timeout SEC            Per-extraction timeout (default 1800).
      --max-extracted-size N   Max bytes one archive may produce (default 50 GiB).
      --max-total-size N       Max bytes produced run-wide (default 500 GiB).
      --max-files N            Max files one archive may produce (default 1,000,000).

feature flags:
      --binwalk / --no-binwalk       binwalk fallback (default ON).
      --resources / --no-resources   PE resources + ELF sections (default ON).
      --hash / --no-hash             SHA-256 + MD5 per file (default ON).
      --dedup / --no-dedup           Skip re-processing seen SHA-256 (default ON).

enrichment:
      --no-yara                Skip YARA rule matching.
      --no-fuzzy-hash          Skip ssdeep + TLSH.
      --no-exif                Skip exiftool metadata.
      --no-entropy             Skip Shannon entropy.
      --yara-rules PATH        Explicit YARA rules file/dir.
      --enrich-timeout SEC     Per-pass per-file timeout (default 30).

filters:
      --include GLOB           Only seed basenames matching GLOB (repeatable).
      --exclude GLOB           Skip basenames matching GLOB (repeatable).

modes:
      --tools-check            Probe tools, print table, exit.
      --dry-run                Detect kinds without extracting.
      --install                Install missing tools (root).
      --uninstall              Remove present tools (root).
      --repair                 Reinstall present tools (root).
      --dry-run-install        Print package-manager commands, no execution.
  -y, --yes                    Skip confirmation prompts.
      --no-refresh-index       Skip index refresh before --install.

logging:
      --log-level LEVEL        Console level (default INFO).
  -v, --verbose                -v INFO, -vv DEBUG.
  -q, --quiet                  WARNING only.
      --log-file PATH          File log path ('-' disables file logging).

  -V, --version                Print version and exit.
```
