<div align="center">

# re-unpacker

**Recursive package / installer / archive / binary extractor for reverse-engineering triage.**

<!-- Dynamic status badges: these reflect live repository state. -->
[![CI](https://github.com/Sandler73/RE-Unpacker/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Sandler73/RE-Unpacker/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Sandler73/RE-Unpacker/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/Sandler73/RE-Unpacker/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/Sandler73/RE-Unpacker?display_name=tag&sort=semver)](https://github.com/Sandler73/RE-Unpacker/releases)
[![Last commit](https://img.shields.io/github/last-commit/Sandler73/RE-Unpacker)](https://github.com/Sandler73/RE-Unpacker/commits/main)
[![Open issues](https://img.shields.io/github/issues/Sandler73/RE-Unpacker)](https://github.com/Sandler73/RE-Unpacker/issues)

<!-- Project characteristic badges. -->
[![Version](https://img.shields.io/badge/version-0.4.10-blue.svg)](CHANGELOG.md)
[![Manifest schema](https://img.shields.io/badge/manifest%20schema-1.1.0-blue.svg)](#manifest-schema)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)](#install)
[![License](https://img.shields.io/github/license/Sandler73/RE-Unpacker?color=green)](LICENSE)
[![Runtime deps](https://img.shields.io/badge/runtime%20deps-none-brightgreen.svg)](pyproject.toml)
[![Code style](https://img.shields.io/badge/lint-ruff-black.svg)](https://docs.astral.sh/ruff/)
[![Formats](https://img.shields.io/badge/formats-70%20extractable%20kinds-blue.svg)](#supported-formats)

</div>

**Current release: 0.4.10** -- a patch release normalizing source headers across all 52 modules, synchronizing per-file version references with the framework version (now enforced by a test gate), and removing release annotations such as "added in vX.Y.Z" from code comments, docstrings, and documentation so they state fact-of behavior instead. No functional change. See [CHANGELOG.md](CHANGELOG.md) for the complete, versioned history from 0.1.0 onward. The manifest schema is **1.1.0** and is byte-compatible across Linux and Windows.

Hand it a file or a directory and it will pull apart every package, installer, archive, filesystem image, compressed stream, and packed binary it can recognize -- recursively, until it hits bedrock -- and write a structured tree plus a manifest describing everything it found.

Designed for the modified Kali Linux RE workflow on Linux and a winget-managed PowerShell workflow on Windows: zero external Python dependencies, all extraction is performed via well-known system binaries.

| At a glance | Count |
|---|---|
| Platforms supported | 2 (Linux, Windows) |
| Tracked external tools (Linux) | 93 |
| Tracked external tools (Windows) | 56 |
| Tools with version-probe coverage | 93 Linux / 56 Windows (full both) |
| Protected tools / packages | 2 / 2 |
| Known-unavailable packages (Linux) | 1 (libfsfat-utils) |
| Known-unavailable packages (Windows) | 14 (libyal binaries, signtool, and similar) |
| FileKind enum entries | 78 |
| Extractable kinds | 70 (parity on both platforms) |
| Primary kinds dispatchable | 70 |
| Registered extractor classes (primary + secondary) | 69 (66 primary + 3 secondary) |
| Root/admin-required extractors | 11 (Linux FUSE only) |
| Terminal-classify kinds (encrypted, no recursion) | 3 |
| Verifiers | 9 (gpgv, debsigs, dpkg-sig, debsums, rpm-K, apksigner, osslsigncode, powershell-authenticode, signtool) |
| Classifiers | 4 (entropy, fuzzy_hash, exif, yara) |
| Python bindings tracked | 3 (tlsh, yara, ssdeep) |
| Package manager backends | 2 (apt, winget) |
| Wrappers shipped | 3 (bash, PowerShell, cmd) |
| Hard size cap (classifier passes) | 256 MiB (verifiers exempt) |
| Default per-pass enrichment timeout | 30 seconds |
| YARA default rule directories | 3 (per-platform: Linux paths or Windows %PROGRAMDATA% / %APPDATA% paths) |
| Exit codes | 0--6 |
| CLI modes | 7 |
| CLI flags (argparse actions) | 37 |
| FileEntry fields | 25 |
| RunStats counters | 20 |
| Manifest schema version | 1.1.0 (byte-identical Linux / Windows manifests) |

**HTML companion documentation:** richly-formatted README and Usage Guide live in `docs/`:

- `docs/ReUnpacker-README.html` -- mirrors this README with a styled, navigable layout.
- `docs/ReUnpacker-Usage-Guide.html` -- procedural, recipe-driven handbook covering every CLI mode, every workflow, and every troubleshooting playbook. The companion document to read alongside the README.

Both are self-contained (no external CSS / JS / fonts) and render in any browser. Open them with `xdg-open docs/ReUnpacker-README.html` (Linux) or just point a browser at the file.

---

## Table of contents

1. [Supported formats](#supported-formats)
2. [Install](#install)
3. [Usage](#usage) -- includes the [Modes](#modes) subsection covering `--install` / `--uninstall` / `--repair` / `--dry-run-install`
4. [Output layout](#output-layout)
5. [Manifest schema](#manifest-schema)
6. [Safety model](#safety-model)
7. [Exit codes](#exit-codes)
8. [Programmatic use](#programmatic-use)
9. [Design overview](#design-overview)
10. [Documentation](#documentation)
11. [Contributing](#contributing)
12. [License](#license)
13. [Changelog](#changelog)

---

## Supported formats

| Category | Formats | Primary tool | Fallback(s) |
|----------|---------|--------------|-------------|
| Linux packages | `.deb` `.udeb` | `dpkg-deb` | `ar` + `tar` |
|  | `.rpm` | `rpm2cpio` \| `cpio` | `rpm2archive` + `tar` |
| Windows installers | `.msi` `.msp` | `msiextract` | `7z` |
|  | `.cab` | `cabextract` | `7z` |
|  | NSIS installers | `7z` | `binwalk` |
|  | InnoSetup | `innoextract` | `7z` |
|  | InstallShield (`setup.exe` + `data*.cab`) | `unshield` | `7z` |
|  | WiX Burn / generic PE installers | `7z` | `binwalk` |
| Filesystem images | `.iso` / UDF | `7z` | `bsdtar` |
|  | `.dmg` (unencrypted UDIF) | `7z` | -- |
|  | `.xar` / `.pkg` (macOS) | `7z` | -- |
|  | SquashFS | `unsquashfs` | -- |
|  | `.snap` (SquashFS) | `unsquashfs` | -- |
|  | AppImage | `unsquashfs` at offset | `--appimage-extract` |
| Traditional archives | `.tar` / `.tar.{gz,bz2,xz,zst,lzma}` | `tar` | -- |
|  | `.zip` / `.jar` / `.apk` / `.whl` / `.docx` / … | `unzip` | `7z` |
|  | `.7z` | `7z` | -- |
|  | `.rar` | `unrar` | `7z` |
|  | `.ar` / `.a` | `ar` | -- |
|  | `.cpio` | `cpio` | -- |
| Single-stream compression | `.gz` / `.bz2` / `.xz` / `.zst` / `.lzma` / `.lz4` / `.lzo` | corresponding CLI | -- |
| Binaries | UPX-packed ELF / PE / Mach-O | `upx -d` on copy | -- |
|  | PE resources (icons, manifests, embedded binaries) | `wrestool` (**secondary**) | -- |
|  | ELF sections (`.text`, `.rodata`, `.data`, `.note.*` …) | `objcopy` + `readelf` (**secondary**) | -- |
| Last resort | unknown binaries with embedded signatures | `binwalk -Me` | -- |
|  |  |  |  |
| **Extended and legacy archives** | `.arj` | `arj` | -- |
|  | `.lha` / `.lzh` | `lha` (lhasa) | `unar` |
|  | `.lz` (lzip single stream) | `lzip -d -c` | -- |
|  | `.tar.lz` / `.tlz` | `lzip -d \| tar -xf -` (pipeline) | -- |
|  | `.lrz` (lrzip) | `lrzip -d` on copy | -- |
|  | `.zpaq` | `zpaq x` | -- |
|  | `.arc` / `.ark` (ARC/ARK MS-DOS) | `nomarch` | -- |
|  | `.tnef` / `winmail.dat` | `tnef -C` | -- |
|  | `.shar` (POSIX shell archive) | `unshar -d` | -- |
|  | `.uu` / `.uue` (uuencoded) | `uudecode` | -- |
|  | `.sit` / `.sitx` (StuffIt) | `unar` | -- |
|  | `.alz` (Korean ALZ) | `unar` | -- |
|  | `.ace` | `unar` | -- |
|  |  |  |  |
| **Documents, disk images, and filesystems** | PDF (with attachments) | `pdfdetach -saveall` | -- |
|  | PDF (structure / streams) | `qpdf --qdf` | -- |
|  | `.apk` (Android package, decoded) | `apktool d` | `unzip` (raw fallback at priority 80) |
|  | `.vmdk` (VMware) | `vmdkmount` (FUSE, root) | `qemu-img convert` (no root) |
|  | `.qcow2` / `.qcow` (QEMU) | `qcowmount` (FUSE, root) | `qemu-img convert` |
|  | `.vhd` / `.vhdx` (Microsoft) | `vhdimount` (FUSE, root) | `qemu-img convert` |
|  | NTFS (in disk image) | `fsntfsmount` (FUSE, root) | -- |
|  | ext{2,3,4} (in disk image) | `fsextmount` (FUSE, root) | -- |
|  | XFS (in disk image) | `fsxfsmount` (FUSE, root) | -- |
|  | APFS (in disk image) | `fsapfsmount` (FUSE, root) | -- |
|  | HFS+ (in disk image) | `fshfsmount` (FUSE, root) | -- |
|  | FAT (in disk image) | `fsfatmount` (FUSE, root) | `mtools` |
|  | VSS shadow copies | `vshadowmount` (FUSE, root) | -- |
|  | LVM2 | `vslvmmount` (FUSE, root) | -- |
|  | JFFS2 / UBI / MTD (firmware) | `binwalk -e` (priority 80) | -- |
|  | `.kwaj` / `.szdd` (MS DOS-era) | `msexpand` | -- |
|  | macOS binary plist (BPLIST) | `plistutil -i -o -f xml` (secondary) | (terminal kind, no primary) |
|  |  |  |  |
| **Terminal-classify (no recursion)** | LUKS encrypted volumes | (none -- classify only, kind=LUKS_ENCRYPTED) | -- |
|  | Encrypted RAR/7z/DMG | (none -- classify only, kind=ENCRYPTED_GENERIC) | -- |

"Secondary" extractors run in addition to (not instead of) the primary extraction, and their output lands in a sibling `_secondary_<name>/` directory inside the unpack folder.

---

## Install

### Prerequisites

- Python 3.10+
- Kali Linux / Debian / Ubuntu with the relevant extraction tools. See the install hint `re-unpacker --tools-check` prints on first run -- it will tell you exactly which `apt` packages to add.

On a fresh Kali / Debian / Ubuntu box, the full set is:

```bash
sudo apt-get update
sudo apt-get install -y \
    arj binutils binwalk bzip2 cabextract cpio dpkg file gzip icoutils \
    innoextract lhasa libarchive-tools lrzip lz4 lzip lzop msitools \
    nomarch p7zip-full pixz plzip rpm rpm2cpio sharutils squashfs-tools \
    tar tnef unar unrar unshield unzip upx-ucl xz-utils zpaq zstd \
    apktool fuse libfsapfs-utils libfsext-utils libfshfs-utils \
    libfsntfs-utils libfsxfs-utils libluksde-utils libplist-utils \
    libqcow-utils libsmraw-utils libvhdi-utils libvmdk-utils \
    libvshadow-utils libvslvm-utils mscompress mtd-utils mtools \
    poppler-utils qemu-utils qpdf
```

On full Kali installs, the libyal `lib*-utils` packages ship the FUSE `*mount` binaries needed for the forensic-filesystem extractors. On Ubuntu and minimal Debian installs, only the `*info` companions ship; the FUSE-mount-based extractors will be silently filtered as unavailable (run `re-unpacker --tools-check` to see the gap).

Or simpler -- let re-unpacker install everything for you (see `--install` in the [Modes](#modes) section below):

```bash
sudo re-unpacker --install --yes
```

### The tool itself

No installer required. Clone the repository and run the bundled wrapper:

```bash
git clone <your-remote>/re-unpacker.git
cd re-unpacker
chmod +x re-unpacker
./re-unpacker --version
```

The `re-unpacker` wrapper adds `src/` to `PYTHONPATH` and invokes `python3 -m re_unpacker`. Drop a symlink into `~/.local/bin/` if you want it on your `PATH`.

### Installing on Windows

Same source tree, different package manager. Two choices for invocation:

```powershell
# PowerShell wrapper (preferred):
.\re-unpacker.ps1 --version

# cmd.exe shim (for restricted-execution-policy environments):
re-unpacker.cmd --version
```

**Prerequisites on Windows:**

- Python 3.10 or newer on PATH (`winget install Python.Python.3.12` or any equivalent install)
- Windows Package Manager (`winget`) -- ships with Windows 10 1809+ and Windows 11 as part of the App Installer system component
- PowerShell 5.1 (built into Windows 10+) for `re-unpacker.ps1`, or just cmd.exe for `re-unpacker.cmd`

**Tool installation on Windows.** The same `--install` mode dispatches to winget instead of apt:

```powershell
.\re-unpacker.ps1 --install --yes
```

This installs every winget-managed tool: `7zip.7zip`, `OliverBetz.ExifTool`, `VirusTotal.YARA`, `GnuPG.GnuPG`, `QPDF.QPDF`, `Microsoft.Sysinternals.Sigcheck`, `Microsoft.PowerShell` (PowerShell 7+). Built-in tools (`expand.exe`, `msiexec.exe`, `tar.exe`, Windows PowerShell 5.1) need no install.

**Manual-install tools on Windows.** Some tools have no winget package (libyal Windows binaries, `signtool` from the Windows SDK, `apksigner` from the Android SDK, `binwalk` via pip, etc.). `re-unpacker --tools-check` flags these as MISSING and the orchestrator's available-extractor filter lets the run continue without them. Each missing tool's row prints a manual-install hint from `KNOWN_UNAVAILABLE_PACKAGES_WIN`. See the Usage Guide's "Running on Windows" chapter for full per-tool install paths.

**Tool inventory parity.** The Windows tool set (56 tools) is smaller than Linux's (93) because 7-Zip on Windows handles many formats that need separate tools on Linux: deb (no `dpkg-deb` needed), rpm (no `rpm2cpio`), cab (no `cabextract`), KWAJ/SZDD (no `mscompress`), cpio + ar (no separate tools), VMDK / QCOW2 / VHD / VHDX (no FUSE-mount). The output-layer parity bar is met: every kind extractable on Linux is extractable on Windows, with identical FileEntry shape and manifest schema.

---

## Usage

### Basic

```bash
# Unpack a single file (output goes to ./<name>.re-unpacker/)
./re-unpacker sample.deb

# Explicit output root
./re-unpacker sample.deb -o ./out

# Recurse through every file under a directory
./re-unpacker ./samples -o ./out

# Use 4 worker threads
./re-unpacker ./samples -o ./out -j 4

# Bump recursion depth (default 10)
./re-unpacker firmware.bin -o ./out -d 20
```

### Preflight and dry-run

```bash
# What tools are installed? What's missing?
./re-unpacker --tools-check

# Scan and classify every file under a directory WITHOUT extracting
./re-unpacker --dry-run ./samples -o ./dryrun
cat ./dryrun/manifest.json | jq '.files[].kind' | sort | uniq -c
```

### Feature toggles

Every feature-flag defaults to the sensible ON position. Use the `--no-*` form to turn it off.

| Flag | Default | Effect |
|------|---------|--------|
| `--binwalk` / `--no-binwalk` | on | Fall back to `binwalk -Me` on unknown binaries |
| `--resources` / `--no-resources` | on | Dump PE resources and ELF sections |
| `--hash` / `--no-hash` | on | Compute SHA-256 + MD5 for every file |
| `--dedup` / `--no-dedup` | on | Skip re-processing files with a previously-seen SHA-256 |

### Filtering

```bash
# Only process specific filename patterns (applies to initial seed walk)
./re-unpacker ./samples --include '*.deb' --include '*.rpm'

# Skip files you don't care about
./re-unpacker ./samples --exclude '*.txt' --exclude '*.log'
```

### Modes

re-unpacker has six top-level modes, all mutually exclusive:

| Mode | What it does | Root required |
|------|-------------|---------------|
| (default) | Unpack the input file or directory | no |
| `--dry-run` | Detect file kinds without extracting | no |
| `--tools-check` | Probe external tools, print status table, exit | no |
| `--dry-run-install` | Print exact apt commands for install / uninstall / repair without executing | no |
| `--install` (alias `--install-missing`) | Install all known unpack tools that are currently missing | **yes** (exit 5 otherwise) |
| `--uninstall` | Remove every currently-present unpack tool from the system | **yes** (exit 5 otherwise) |
| `--repair` | Reinstall every currently-present unpack tool (recovers from broken / half-installed state) | **yes** (exit 5 otherwise) |

The `--install` / `--uninstall` / `--repair` modes prompt for confirmation by default. Use `-y` / `--yes` to skip the prompt:

```bash
# Install everything missing
sudo re-unpacker --install --yes

# Preview what install/uninstall/repair would do, no execution
re-unpacker --dry-run-install

# Reinstall the present toolset (e.g. after a partial dpkg failure)
sudo re-unpacker --repair --yes

# Skip the apt-get update step on repeated runs
sudo re-unpacker --install --yes --no-refresh-index
```

**Safety rails on the package-management modes:**

- `apt` and `dpkg` are tracked by the registry (so `--tools-check` surfaces their state) but are **never** targets of install / uninstall / repair. The two-tier `PROTECTED_TOOLS` (by tool name) and `PROTECTED_PACKAGES` (by package name) sets in `constants.py` enforce this.
- `--uninstall` skips packages flagged `Essential: yes` by dpkg (`tar`, `gzip`, `dpkg`, etc.). They are listed in the output as "excluded" so you know what was not touched and why. apt would refuse anyway; we filter at our layer so the user sees a clean summary instead of a non-zero apt error.
- `--repair` does NOT skip essentials -- a damaged `tar` is exactly the kind of thing repair exists to fix, and apt allows reinstall (just not removal) of essential packages.

### Resource / safety limits

```bash
# Per-extractor timeout (seconds)
--timeout 1800

# Hard byte ceilings
--max-extracted-size  50000000000      # 50 GiB per single archive
--max-total-size     500000000000      # 500 GiB across the whole run
--max-files          1000000           # files per archive
```

Hitting any of these aborts further extraction with `SafetyLimitExceeded` and exit code 2, but the manifest and logs written so far are preserved.

### Enrichment

After extraction completes, the orchestrator runs a per-file enrichment phase: signature/integrity verifiers (Subsystem B) plus classification passes (Subsystem C). Verifiers run on every file regardless of size; classifiers honor a hard 256 MiB cap (files above the cap record `enrichment_skipped="size_exceeds_cap"` and skip all classifier passes).

```bash
# Disable individual classifier passes (verifiers always run, no opt-out)
--no-yara              # Skip YARA rule matching pass
--no-fuzzy-hash        # Skip ssdeep + TLSH fuzzy hash computation
--no-exif              # Skip exiftool metadata extraction
--no-entropy           # Skip Shannon entropy computation (also disables
                       # the encryption heuristic that depends on it)

# YARA rule loading
--yara-rules PATH      # Single file or directory; bypasses default
                       # auto-discovery (UNION of /etc/yara/,
                       # ~/.config/re-unpacker/yara/, YARA Forge default)

# Per-pass per-file timeout (verifiers AND classifiers)
--enrich-timeout SEC   # Default: 30 seconds
```

**Default YARA rule auto-discovery (when `--yara-rules` is not given):** UNION of all three default directories, with each rule file's source dir contributing a namespace prefix (`etc:` / `user:` / `forge:`) so duplicate rule names across directories resolve cleanly.

**Verifier dispatch:** the orchestrator asks each verifier `applies_to(file_entry) -> bool`. Verifiers register in `src/re_unpacker/verifiers/` and use the `Verifier` ABC; they are best-effort and never abort the run on failure. Results land in `file_entry.verification` in the manifest.

| Verifier | Tool | File kinds it applies to |
|---|---|---|
| `gpgv` | gpgv | Any file with sibling `.sig` / `.asc` |
| `debsigs` | debsigs | DEB |
| `dpkg-sig` | dpkg-sig | DEB |
| `debsums` | debsums | DEB (DISABLED -- debsums operates on installed packages, not .deb files at rest. Tracked for tooling but never invoked.) |
| `rpm-K` | rpm | RPM |
| `apksigner` | apksigner | APK |
| `osslsigncode` | osslsigncode | PE_EXECUTABLE / PE_NSIS / PE_INNOSETUP / PE_INSTALLSHIELD / PE_WIXBURN / MSI / CAB |

**Classifier dispatch:** all 4 classifiers run on every file (subject to the 256 MiB cap and any `--no-*` disable flags). Pipeline order: `entropy` -> `fuzzy_hash` -> `exif` -> `yara` (cheapest first; YARA last because it dominates per-file enrichment cost on large rule sets).

| Classifier | Tools | Field(s) populated |
|---|---|---|
| `entropy` | `ent` (with pure-Python fallback) | `entropy`, `encrypted`, `encryption_scheme` |
| `fuzzy_hash` | `python3-tlsh` + `python3-ssdeep` (preferred) or `ssdeep` CLI | `ssdeep`, `tlsh` |
| `exif` | `exiftool` | `exif_metadata` (per-value 4096-char cap) |
| `yara` | `python3-yara` | `yara_matches` (list of rule_name / namespace / tags / meta dicts) |

### Logging

```bash
# Console log level (file log always records DEBUG)
--log-level {DEBUG|INFO|WARNING|ERROR|CRITICAL}

# Convenience verbosity shortcuts
-v, --verbose       # = --log-level INFO (default)
-vv                 # = --log-level DEBUG
-q, --quiet         # = --log-level WARNING (suppress INFO)

# (-v and -q are mutually exclusive; --log-level overrides both with a warning)

# File log path (extract mode adds it on top of <output>/extraction.log;
# non-extract modes use it instead of the default cache-dir path)
--log-file PATH
--log-file -        # disable file logging entirely
```

**Default file log locations:**

| Mode | Default file log path |
|---|---|
| Extract (default) | `<output>/extraction.log` (always written) |
| `--tools-check` | `~/.cache/re-unpacker/logs/tools-check-<UTC_YYYYMMDD-HHMMSS>-<pid>.log` |
| `--install` | `~/.cache/re-unpacker/logs/install-<ts>-<pid>.log` |
| `--uninstall` | `~/.cache/re-unpacker/logs/uninstall-<ts>-<pid>.log` |
| `--repair` | `~/.cache/re-unpacker/logs/repair-<ts>-<pid>.log` |
| `--dry-run-install` | `~/.cache/re-unpacker/logs/dry-run-install-<ts>-<pid>.log` |

When `XDG_CACHE_HOME` is set, `$XDG_CACHE_HOME/re-unpacker/logs/` is used instead of `~/.cache/...`. Each non-extract mode prints a one-line banner showing the resolved log file path:

```
$ sudo re-unpacker --install --yes
[install] Logging to /root/.cache/re-unpacker/logs/install-20260502-143625-12345.log
[apt-get update output...]
```

---

## Output layout

Every run writes to `<output_root>/` with this structure:

```text
<output_root>/
├── manifest.json                     # consolidated final manifest
├── manifest.jsonl                    # streaming JSONL, line-buffered (crash-resilient)
├── extraction.log                    # full DEBUG log (line-buffered)
├── errors.log                        # warnings+ only, for quick triage
├── tree.txt                          # pure-Python tree-style listing of extracted/
├── summary.txt                       # stats, top kinds, largest files, error summary
└── extracted/
    └── <input-name>.unpacked/        # top-level input
        ├── (files from primary extraction)
        ├── <nested>.unpacked/        # recursive: same scheme at each depth
        │   └── …
        ├── _secondary_<extractor>/   # e.g. _secondary_wrestool/ or _secondary_objcopy_ELF_sections/
        │   └── …
        └── _quarantine/              # (only if the path-safety audit moved anything here)
```

The `.unpacked` suffix makes it obvious in `ls` output which directories are re-unpacker products. `_secondary_…` subdirectories are the outputs of resource / section extractors (PE resources, ELF sections). `_quarantine` only appears if an escaping path was detected and relocated.

---

## Manifest schema

`manifest.json` is the authoritative machine-readable record. Schema version is currently **1.1.0** (tracked in `constants.SCHEMA_VERSION`). All fields are UTF-8 strings unless noted.

### Top-level

```jsonc
{
  "schema_version": "1.1.0",
  "tool": "re-unpacker",
  "tool_version": "0.3.2",
  "generated_at": "2026-04-21T17:48:30Z",
  "opened_at":    "2026-04-21T17:48:28Z",
  "host": "kali-rig-01",
  "os":   "Linux-6.6.x-…",
  "invocation": {
    "argv": ["…", "sample.deb", "-o", "out"],
    "cwd":  "/home/re/work",
    "pid":  12345
  },
  "input_root":  "/path/to/input",
  "output_root": "/path/to/out",
  "tools_detected": { /* per-tool: path, version, package_hint, available */ },
  "stats":  { /* see below */ },
  "errors": [ /* list of ErrorEntry */ ],
  "files":  [ /* list of FileEntry */ ]
}
```

### `stats` object

```jsonc
{
  "inputs_scanned":          22,
  "files_extracted":         22,
  "archives_processed":      3,
  "archives_failed":         0,
  "archives_skipped_dedup":  0,
  "bytes_in":                0,
  "bytes_out":               356826,
  "duration_seconds":        1.38,
  "max_depth_reached":       4,
  "errors_count":            0,
  "quarantined_paths":       0,
  "symlinks_neutralized":    0
}
```

### `FileEntry`

One per file the orchestrator looked at (both extracted and pass-through):

```jsonc
{
  "path":                    "/abs/path/to/file",
  "rel_path":                "extracted/…/file",
  "rel_path_from_source":    "inner/path/inside/archive",
  "source_archive":          "/abs/path/to/parent.tar.gz",
  "source_archive_sha256":   "27b4…",
  "size":                    51234,
  "sha256":                  "…",
  "md5":                     "…",
  "file_magic":              "ELF 64-bit LSB pie executable, x86-64, …",
  "mime_type":               "application/x-pie-executable",
  "kind":                    "ELF",
  "extractor":               null,
  "depth":                   3,
  "mode":                    "0755",
  "mtime":                   "2026-04-21T17:48:28Z",
  "signals":                 ["magic:ELF", "file_desc:ELF …", "mime:…", "ext:"],
  // -------- schema 1.1.0 additions, all optional --------
  "ssdeep":                  "768:abc...:xyz",          // null when not computed
  "tlsh":                    "T1A2B3C4...",              // null below TLSH min size / diversity
  "entropy":                 7.823,                       // bits/byte, range 0.0--8.0
  "encrypted":               false,
  "encryption_scheme":       null,                        // "luks" | "gpg" | "rar5-encrypted" | "age" | null
  "yara_matches":            [
    {
      "rule_name":  "Suspicious_Powershell",
      "namespace":  "etc:0:rules",
      "tags":       ["powershell", "obfuscated"],
      "meta":       {"author": "...", "severity": "high"}
    }
  ],
  "exif_metadata":           { "FileType": "ELF", "MachineType": "AMD64", /* ... */ },
  "enrichment_skipped":      null,                        // "size_exceeds_cap" when > 256 MiB
  "verification":            [
    {
      "verifier_name":     "rpm-K",
      "performed":         true,
      "applicable":        true,
      "signed":            true,
      "valid":             true,
      "signer":            null,
      "error":             null,
      "duration_seconds":  0.123
    }
  ]
}
```

### `ErrorEntry`

```jsonc
{
  "timestamp":       "2026-04-21T17:48:29Z",
  "path":            "/abs/path/to/source.exe",
  "extractor":       "innoextract",
  "error_class":     "ExtractorFailure",
  "message":         "Extractor 'innoextract' failed on '…' (rc=1)",
  "returncode":      1,
  "stderr_snippet":  "I/O error…",
  "context":         { /* per-error extras */ }
}
```

### `manifest.jsonl`

One JSON record per line (`record_type` is `"header"`, `"file"`, `"error"`, or `"footer"`). Line-buffered. Grep- and `jq -c`-friendly:

```bash
jq -c 'select(.record_type == "file" and .kind == "ELF") | .path' out/manifest.jsonl
```

---

## Safety model

re-unpacker takes adversarial input seriously -- archives dropped on RE rigs are often malicious.

- **No `shell=True`.** Every extractor invocation is an `argv` list. No construction of command strings from filenames.
- **Per-extractor timeout.** Default 1800s. On timeout, `SIGTERM` goes to the process group; `SIGKILL` follows 5s later if the leader hasn't exited. Raises `ExtractorTimeout` → recorded and next extractor tried.
- **Bounded subprocess output capture.** 1 MiB per stream; truncation is marked in the manifest with `stdout_truncated` / `stderr_truncated`.
- **Path-traversal audit after every extraction.** Every extracted symlink is resolved and compared to the output root. Escaping symlinks are *replaced* with a placeholder `*.escaping_symlink.txt` file recording the original target (so an analyst still sees what the archive tried to do). Escaping regular files are moved to `<output_root>/_quarantine/`. Counters are surfaced in `stats.symlinks_neutralized` and `stats.quarantined_paths`.
- **Output-size ceiling (preventive on POSIX).** Every extraction child runs under `RLIMIT_FSIZE` sized to `--max-extracted-size`, so a single-file decompression bomb (a tiny `.gz` that would expand to hundreds of GB, an xz/zip bomb) is stopped by the kernel *mid-write* rather than only after it lands. On Windows the stdlib has no clean `RLIMIT_FSIZE` analogue, so this cap is a no-op there and the post-extraction checks below are the safety net.
- **Quota tracker (detective, run-wide).** After each extraction step, the produced byte count and file count are measured and checked against the per-archive and run-wide ceilings (`--max-extracted-size`, `--max-total-size`, `--max-files`). Tripping one raises `SafetyLimitExceeded` → exit code 2, partial output and manifest preserved. This backstops the many-small-files case and the total-size case (and is the primary guard on Windows).
- **UPX always operates on a copy.** Source is never mutated.
- **AppImage extraction never executes the binary with install privileges.** When possible it bypasses execution entirely via `unsquashfs -o <offset>` against the SquashFS tail; when it falls back to `--appimage-extract`, the fallback runs in a tempdir with a freshly-copied file.

The deliberately-out-of-scope items are symmetrical-cryptography password recovery for password-protected archives, and recursion into file formats requiring OS-kernel-level mounting (loop-mount ISOs via `mount -o loop`). Both carry risks that outweigh their value for the RE-triage use case.

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Run completed. Any per-file errors are recorded in the manifest -- **the run still succeeded.** |
| 1 | Input path invalid or unreadable; no run attempted |
| 2 | `SafetyLimitExceeded` tripped mid-run; partial output preserved |
| 3 | `--tools-check` mode: one or more known tools are missing |
| 4 | Unexpected fatal error (bug). Please file an issue. |
| 5 | Privilege required: `--install`, `--uninstall`, or `--repair` invoked without root |
| 6 | Package manager error: apt failed during install / remove / reinstall |

---

## Programmatic use

Most users will stick with the CLI, but the package is import-friendly:

```python
from re_unpacker import main as cli_main

rc = cli_main(["./sample.deb", "-o", "./out", "--log-level", "WARNING"])
# rc is the same integer the CLI would have exited with.
```

For direct use of the orchestrator (e.g. to embed re-unpacker inside a larger pipeline), see `re_unpacker.cli._run_normal` -- it's the canonical construction pattern for logger → tools → manifest → quota → orchestrator.

---

## Design overview

### Three-layer file-type detection

1. **Magic bytes** read from the file head (and, for formats like DMG, from the tail). Offset-aware; handles ISO-9660 at offset 32769.
2. **`file(1)`** via libmagic -- used for PE sub-type disambiguation (NSIS vs InnoSetup vs InstallShield vs WiX Burn) and for formats the magic table doesn't cover.
3. **Extension** -- used only as a tertiary tiebreaker (e.g. disambiguating `.jar`/`.apk`/`.whl` among plain ZIPs, or confirming an OLE2 compound doc is specifically a `.msi`).

Each detection carries a `signals` list in the manifest so you can see exactly why a file was classified the way it was:

```jsonc
"signals": ["magic:GZIP", "file_desc:gzip compressed data, from Unix, …",
            "mime:application/gzip", "refine:tar_composite:.tar.gz", "ext:.tar.gz"]
```

### Extractor registry

Every extractor subclasses `re_unpacker.extractors.base.Extractor` and declares:

- `handles_kinds: frozenset[FileKind]` -- what it can open
- `required_tools: tuple[str, ...]` -- what binaries must be on PATH
- `priority: int` -- higher wins when multiple extractors handle the same kind
- `is_secondary: bool` -- True for resource / section dumpers that run *alongside* the primary

The registry builds two dispatch maps (primary, secondary) at startup. The orchestrator pulls the primary list for a detected kind, tries each in priority order until one succeeds (or all raise `ExtractorNotApplicable`), then runs every applicable secondary extractor regardless.

### Dispatch chain semantics

The key distinction is `ExtractorNotApplicable` vs `ExtractorFailure`:

- **`ExtractorNotApplicable`**: the extractor looked at the file and decided it's not the right job (UPX sees no magic; `binwalk` returns rc=3 "no signatures"). Orchestrator catches silently and tries the next extractor. **Not** recorded as a manifest error.
- **`ExtractorFailure`**: the extractor tried and failed (non-zero exit, malformed output). Recorded as a manifest error; orchestrator tries the next extractor.

This is why a run on a bare ELF binary produces `errors=0` even though UPX and binwalk were both attempted and declined.

### Recursion engine

BFS work queue of `(path, depth, source_archive, source_archive_sha256, rel_path)`. Dedup is by SHA-256 of the file contents -- a byte-identical archive appearing twice in the input is extracted once. Worker threads (`-j N`) share the queue, the dedup set, and the manifest; all access is lock-protected. Manifest writes are line-buffered JSONL so an interrupted run still has a valid partial record.

---

## Documentation

The full documentation set lives in two places: Markdown guides under `docs/`
and a mirrored [project wiki](https://github.com/Sandler73/RE-Unpacker/wiki).
The wiki pages are kept at parity with the `docs/` guides.

| Document | Path | Purpose |
|----------|------|---------|
| Usage Guide | [`docs/USAGE_GUIDE.md`](docs/USAGE_GUIDE.md) | Every CLI mode, flag, and workflow, recipe-driven. |
| Setup Guide | [`docs/SETUP_GUIDE.md`](docs/SETUP_GUIDE.md) | Install on Linux and Windows, tool provisioning, verification. |
| Troubleshooting Guide | [`docs/TROUBLESHOOTING_GUIDE.md`](docs/TROUBLESHOOTING_GUIDE.md) | Symptom-to-fix playbooks and exit-code triage. |
| FAQ | [`docs/FAQ.md`](docs/FAQ.md) | Common questions about scope, safety, and behavior. |
| Changelog | [`CHANGELOG.md`](CHANGELOG.md) | Full version history (0.1.0 onward). |
| Security policy | [`SECURITY.md`](SECURITY.md) | Supported versions and private vulnerability reporting. |
| Contributing | [`CONTRIBUTING.md`](CONTRIBUTING.md) | Dev setup, extractor/verifier/classifier patterns, PR checklist. |
| Code of Conduct | [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) | Community standards. |

Richly-formatted HTML companions also ship in `docs/`
(`ReUnpacker-README.html`, `ReUnpacker-Usage-Guide.html`); both are
self-contained and render in any browser.

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
development setup, the extractor / verifier / classifier authoring patterns,
the coding standards (including the hard no-em-dash rule and the header-block
convention), and the pull-request checklist. All participation is governed by
the [Code of Conduct](CODE_OF_CONDUCT.md). Security issues must be reported
privately per [SECURITY.md](SECURITY.md), never via public issues.

---

## License

re-unpacker is released under the [MIT License](LICENSE). The LICENSE file also
carries supplemental terms (disclaimer of warranty, limitation of liability,
indemnification, acceptable use, security, and compliance) that make explicit
the expectations for a security-focused reverse-engineering tool that operates
on untrusted, potentially malicious input. Those supplemental sections do not
narrow the rights granted by the MIT License; where any could be read to
conflict, the MIT License controls.

re-unpacker ships no bundled third-party runtime code. It invokes external
system binaries (dpkg-deb, 7-Zip, binwalk, qpdf, yara, exiftool, gpg, the
libyal toolset, and others) that are installed and licensed separately under
their own terms.

## Changelog

The complete, versioned history lives in [CHANGELOG.md](CHANGELOG.md), which
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The current release
is **0.4.8**; see the changelog for every entry back to 0.1.0.
