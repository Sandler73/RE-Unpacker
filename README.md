# re-unpacker

**Recursive package / installer / archive / binary extractor for reverse-engineering triage.**

**Version:** 0.4.8 -- Patch release. Three bugs and two documentation issues from v0.4.7 field test:

(1) **CLI-WINGET-MISSING-METHOD-01 (CRITICAL):** `--dry-run-install` crashed on Windows with `AttributeError: 'WingetBackend' object has no attribute 'is_essential_package'`. The method was implemented on `AptBackend` (Linux) but not `WingetBackend` (Windows). Fix: added `is_essential_package` to the `PackageManagerBackend` base class with a sensible default (returns `False`, since winget has no equivalent of dpkg's Essential:yes flag). `AptBackend` keeps its dpkg-query-based override; `WingetBackend` inherits the base default. Lesson L45: backend / strategy classes need a shared contract enforced at definition time -- a default in the base class eliminates the gap.

(2) **WINGET-SCOPE-APPDATA-01:** winget installs were going to `%LocalAppData%` paths despite the project policy that forbids APPDATA installs. The `winget install` argv lacked `--scope machine`. Fix: added `--scope machine` to `WingetBackend.install_packages`. Tools that support machine-scope (most via winget-pkgs, including the MSI variants of MSIX-only Microsoft Store apps) now land in `Program Files`. Tools that genuinely cannot do machine scope will surface their error explicitly via the existing graceful-failure path rather than silently falling back to user scope.

(3) **PATH-DIAGNOSTIC-01 (improvement):** When system PATH is already over the Windows-safe threshold from cumulative growth across runs, the framework now prints a comprehensive diagnostic to stdout (not just the log file): current vs threshold sizes, duplicate entries, dead entries, proposed cleanup savings, and step-by-step instructions for cleanup via System Properties > Environment Variables. The framework cannot self-clean other software's PATH entries safely, but it can identify them clearly so the user can act. Lesson L46: system-wide state changes accumulate across runs and must be self-cleaning OR self-monitoring.

(4) **Section 22.2 expanded:** the Usage Guide now contains a comprehensive table for every tool that has no winget Package ID, covering libyal toolset (28 tools, source-only upstream), external SDK tools (signtool, apksigner, apktool, aapt2), tools with no canonical Windows distribution (ent, file, qemu-img), and pip packages (binwalk, ssdeep). Each row documents what the tool provides, where to obtain it, and notes about substitutes or build requirements.

(5) **Documentation cleanup:** removed version-pointer noise throughout the descriptive sections of both README and Usage Guide. Section headings no longer carry version pills; description paragraphs and CLI option discussions describe the framework's current factual state rather than narrating its evolution. The changelog retains version history (that is its purpose); everything else now reads as present-tense fact.

v0.4.0 architectural decisions and inventory unchanged.

**v0.4.5 (prior):** Patch release. UnboundLocalError scoping bug fix: removed redundant `from .tools import build_and_probe_registry` from inside `_run_install` that was making the symbol function-local and breaking the earlier reference at line 777. Bytecode regression test added to catch this exact failure mode.

**v0.4.4 (prior):** Manual install handler subsystem. Closes the v0.4.0/v0.4.x scope gap where ~30 Windows tools without winget Package IDs were skipped by `--install`. New module `manual_install_windows.py` provides per-tool handlers that auto-download from upstream (binwalk via pip; upx, osslsigncode, innoextract, ewfinfo+ewfexport, plistutil, pdfdetach via GitHub releases). Honest skips for the 28 libyal-toolset members beyond libewf (joachimmetz publishes source-only). Out-of-scope per user direction: signtool, apksigner, apktool. Install location: `C:\Program Files\re-unpacker\bin\`. Bonus: sigcheck UTF-16 BOM mojibake fix.

**v0.4.3 (prior):** CRITICAL fix release. `--accept-source-agreements` removed from `winget source update` (flag invalid for that subcommand; produced red error). Five-pass well-known-directory probe in `_windows_well_known_lookup` covering WinGet Links shims, WinGet Packages portable layouts, `%LocalAppData%\Programs\` for Inno user-scope, and version-stamped glob patterns -- catches ExifTool, QPDF, Sigcheck, YARA, yarac which v0.4.2 missed.

**v0.4.2 (prior):** Patch release. Four field bugs from second Windows 11 Pro test run: msiexec /? probe opened Windows Installer GUI dialog AND crashed timeout cleanup with os.killpg AttributeError (POSIX-only); winget-installed tools not detected post-install (PATH captured at process start); --tools-check footer hardcoded for Linux; empty hints displayed as "unknown package". Plus: Microsoft.PowerShell wrongly recommended when Windows PowerShell 5.1 already detected.

**v0.4.1 (prior):** Patch release. Two bugs surfaced from a Windows 11 Pro field deployment of v0.4.0: (1) `WingetBackend.install_packages()` now runs `winget source update` before the install loop (analog to AptBackend's `apt-get update`), fixing the `0x80071130 Fast Cache data not found` error on fresh Windows installs; the install loop also now detects rc=2147946800 specifically and emits an actionable remediation message. (2) `--help` and bare-invocation error now surface concrete platform-aware invocation examples (Linux `./re-unpacker sample.deb`, Windows `.\re-unpacker.ps1 sample.cab`) so first-time Windows users know how to point the tool at a sample.

**v0.4.0 (prior):** Windows-tandem release. Cross-platform Python codebase with runtime platform detection: the same source tree runs on Linux and Windows. Adds `winget` package manager backend alongside the existing `apt`. New `platform_compat.py` module centralizes OS-specific behavior (cache dir, admin detection, executable-suffix resolution). New Windows-only verifiers `PowerShellAuthenticodeVerifier` (uses `Get-AuthenticodeSignature`) and `SigntoolVerifier` (uses Windows SDK `signtool.exe`); both auto-filter on Linux via the existing `required_tools` mechanism. Eight extractor modules grew Windows code paths: cab/embedded_fs use native `expand.exe`; cpio/ar/deb/rpm/msi shift to 7-Zip or `msiexec /a`; disk_image and forensic_fs add 7-Zip + libyal `*export` paths instead of FUSE-mount. New PowerShell wrapper `re-unpacker.ps1` and cmd shim `re-unpacker.cmd`. **Manifest schema unchanged at 1.1.0**: a Linux v0.3.2 manifest and a Windows v0.4.x manifest are interchangeable for downstream tooling. Output-layer parity preserved: identical FileEntry shape, identical RunStats counters, identical summary.txt sections, identical CLI surface (28 flags, no change).

Hand it a file or a directory and it will pull apart every package, installer, archive, filesystem image, compressed stream, and packed binary it can recognize -- recursively, until it hits bedrock -- and write a structured tree plus a manifest describing everything it found.

Designed for the modified Kali Linux RE workflow on Linux and a winget-managed PowerShell workflow on Windows: zero external Python dependencies, all extraction is performed via well-known system binaries.

| At a glance (v0.4.0) | Count |
|---|---|
| **Platforms supported (NEW)** | **2** (Linux + Windows) |
| Tracked external tools (Linux) | 93 |
| Tracked external tools (Windows, NEW) | 56 |
| Tools with version-probe coverage | 93 Linux / 56 Windows (full both) |
| Protected tools / packages | 2 / 2 |
| Known-unavailable packages (Linux) | 1 (libfsfat-utils) |
| Known-unavailable packages (Windows, NEW) | 14 (libyal binaries, signtool, etc.) |
| FileKind enum entries | 78 |
| Extractable kinds | 70 (parity on both platforms) |
| Primary kinds dispatchable | 70 |
| Registered extractor classes (primary + secondary) | 58 (with Windows variants in 8 modules) |
| Root/admin-required extractors | 11 (Linux FUSE only) |
| Terminal-classify kinds (encrypted, no recursion) | 3 |
| **Verifiers (NEW: +2 Windows-native)** | **9** (gpgv, debsigs, dpkg-sig, debsums, rpm-K, apksigner, osslsigncode, **powershell-authenticode**, **signtool**) |
| Classifiers | 4 (entropy, fuzzy_hash, exif, yara) |
| Python bindings tracked | 3 (tlsh, yara, ssdeep) |
| Package manager backends | 2 (apt + **winget**, NEW) |
| Wrappers shipped | 3 (bash + **PowerShell** + **cmd**, NEW: 2) |
| Hard size cap (classifier passes) | 256 MiB (verifiers exempt) |
| Default per-pass enrichment timeout | 30 seconds |
| YARA default rule directories | 3 (per-platform: Linux paths or Windows %PROGRAMDATA% / %APPDATA% paths) |
| Exit codes | 0--6 |
| CLI modes | 7 |
| CLI flags | 28 (UNCHANGED from v0.3.2 -- output-layer parity) |
| FileEntry fields | 25 (UNCHANGED from v0.3.2) |
| RunStats counters | 20 (UNCHANGED from v0.3.2) |
| **Manifest schema version** | **1.1.0 (UNCHANGED -- byte-identical Linux/Windows manifests)** |

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
10. [Changelog](#changelog)

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
| **v0.2.0 additions** | `.arj` | `arj` | -- |
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
| **v0.3.0 additions** | PDF (with attachments) | `pdfdetach -saveall` | -- |
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
| **v0.3.0 terminal-classify** | LUKS encrypted volumes | (none -- classify only, kind=LUKS_ENCRYPTED) | -- |
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

On full Kali installs, the libyal `lib*-utils` packages ship the FUSE `*mount` binaries needed for v0.3.0's forensic-filesystem extractors. On Ubuntu and minimal Debian installs, only the `*info` companions ship; the FUSE-mount-based extractors will be silently filtered as unavailable (run `re-unpacker --tools-check` to see the gap).

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

### Installing on Windows (v0.4.0)

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

### Enrichment (v0.3.2)

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
| `debsums` | debsums | DEB (DISABLED in v0.3.2 -- debsums operates on installed packages, not .deb files at rest. Tracked for tooling but never invoked.) |
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

### Logging (v0.3.1)

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

`manifest.json` is the authoritative machine-readable record. Schema version is currently **1.0.0** (tracked in `constants.SCHEMA_VERSION`). All fields are UTF-8 strings unless noted.

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
  // -------- v0.3.2 (schema 1.1.0) additions, all optional --------
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
- **Quota tracker.** Byte and file-count ceilings are checked per archive and run-wide. Tripping one raises `SafetyLimitExceeded` → exit code 2, manifest preserved.
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

## License

Internal tooling; license TBD per your project policy.

## Changelog

### 0.4.8 -- Patch release (cli AttributeError + winget --scope machine + PATH diagnostic + docs cleanup)

Three bugs and two documentation issues from v0.4.7 Windows 11 Pro field test.

**Bug CLI-WINGET-MISSING-METHOD-01 (CRITICAL).** `--dry-run-install` crashed:

```
File "...\src\re_unpacker\cli.py", line 1025, in _run_dry_run_install
    present_pkgs, present_tools, essentials_skipped = _compute_present_packages(...)
File "...\src\re_unpacker\cli.py", line 735, in _compute_present_packages
    if backend is not None and backend.is_essential_package(tool.package_hint):
AttributeError: 'WingetBackend' object has no attribute 'is_essential_package'
```

`AptBackend.is_essential_package` (Linux) wraps `dpkg-query -W -f='${Essential}'` to identify packages flagged Essential:yes (tar, gzip, dpkg, libc6) that cannot be removed without breaking the system. `WingetBackend` (Windows) lacked this method because winget has no equivalent flag. The caller `_compute_present_packages` invokes the method through duck typing without checking; on Linux it worked, on Windows it crashed.

Fix: moved `is_essential_package` to the `PackageManagerBackend` base class with a sensible default (returns `False` -- no concept of "essential" without backend support). `AptBackend` keeps its dpkg-query-based override; `WingetBackend` inherits the base default. Lesson L45: backend / strategy classes need a shared contract enforced at definition time. A method on the base class with a sensible default eliminates the gap entirely.

**Bug WINGET-SCOPE-APPDATA-01.** Winget installs were going to `%LocalAppData%` paths in violation of project policy. Field log evidence: `exiftool -> C:\Users\Administrator\AppData\Local\Programs\ExifTool\exiftool.EXE`, `pwsh -> C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\pwsh.EXE`. Cause: `WingetBackend.install_packages` invoked `winget install --id <pkg> --exact --silent --accept-source-agreements --accept-package-agreements` -- with no `--scope` flag, winget defaults to user-scope when running with `--silent`, putting binaries under `%LocalAppData%`.

Fix: added `"--scope", "machine"` to the install argv. Tools that support machine-scope (most of the catalog, including the MSI variants of MSIX-only Microsoft Store apps that winget will select when `--scope machine` is requested) now land in `Program Files`. Tools that genuinely cannot do machine-scope will surface their error explicitly via the existing graceful-failure path rather than silently falling back to user scope.

**Improvement PATH-DIAGNOSTIC-01.** When the system PATH is already over the Windows-safe threshold (which v0.4.7 detects and skips writing to), the framework now prints a comprehensive diagnostic to stdout (not just the log file): current PATH size, the threshold, total entries, count of duplicates, count of dead entries (point to non-existent dirs), proposed cleanup savings, and step-by-step instructions for cleanup via System Properties > Environment Variables. Up to 10 examples each of duplicates and dead entries are printed for direct user reference. The framework cannot self-clean other software's PATH entries safely, but it can identify them clearly so the user can act. Lesson L46: system-wide state changes accumulate across runs and must be self-cleaning OR self-monitoring.

**Section 22.2 expanded.** The Usage Guide now contains a comprehensive table for every tool that has no winget Package ID:

- libyal toolset (28 tools, source-only upstream from joachimmetz): vmdk*, vhdi*, qcow*, fsapfs*, fsntfs*, fsext*, fsfat*, fshfs*, fsxfs*, vshadow*, vslvm*, luksde*, smraw*, phdi* -- with notes on Windows substitutes where available (Hyper-V Mount-VHD for VHD, QEMU qemu-img for QCOW conversion, native Windows NTFS / FAT for those file systems, WSL Linux subsystem for ext / xfs / LVM / LUKS) and explicit acknowledgment that build-from-source requires Visual Studio C++, Python, and autotools.
- External SDK tools: `signtool` (Windows SDK), `apksigner` / `apktool` / `aapt2` (Android SDK).
- Tools with no canonical Windows distribution: `ent` (fourmilab.ch source), `file` (Git for Windows), `qemu-img` (qemu.weilnetz.de Windows builds).
- pip packages: `binwalk` (auto-installed when Python is available), `ssdeep` (PyPI build requires C compiler; community Windows binaries available).

Each row documents what the tool provides, where to obtain it, and notes about substitutes or build requirements.

**Documentation cleanup.** Removed version-pointer noise throughout the descriptive sections of both README and Usage Guide. Section headings no longer carry decorative version pills (`<span class="pill med">v0.4.X</span>` next to titles). Description paragraphs and CLI option discussions describe the framework's current factual state rather than narrating its evolution ("v0.3.0 added ... v0.3.1 added ... v0.3.2 added ..." replaced with present-tense functionality descriptions). The changelog retains version history (that is its purpose); everything else reads as present-tense fact.

**Lessons captured:**

- **L45**: backend / strategy classes need a shared contract enforced at definition time. Either via abstract base class with `@abstractmethod`, or via a base-class default that subclasses override only when behavior differs. The former fails at instantiation time; the latter has zero failure surface.
- **L46**: system-wide state changes accumulate across runs and must be self-cleaning OR self-monitoring. Tools that modify shared state (PATH, registry keys, startup entries, scheduled tasks) should monitor cumulative state, not just check pre-write conditions, and provide a diagnostic / cleanup path for the state they helped grow.

v0.4.0 architectural decisions and inventory unchanged.

### 0.4.7 -- Patch release (PATH overflow guard + plistutil probe fix)

Two bugs from v0.4.6 Windows 11 Pro field test (testrun510.txt, 599 lines, 4 invocations across 32 minutes). The v0.4.6 manual-install detection improvements are confirmed working: the field log shows `Manual install batch complete: 6 succeeded, 1 failed, 33 skipped` (lines 453-506) with all 6 succeeded tools (binwalk, ewfinfo, ewfexport, osslsigncode, pdfdetach, plistutil) detected post-install via the v0.4.6 Pass 0 well-known fallback at `C:\Program Files\re-unpacker\bin\`. Sigcheck displays its readable version "Sigcheck v2.91 - File version and signature viewer" (lines 265, 577), confirming the v0.4.6 byte-level BOM decoder works.

**Bug PATH-OVERFLOW-POPUP-01 (CRITICAL).** User reported: "Now generates a new pop-up Error message 'PATH env variable too big'."

Root cause: across multiple `--install` runs on the same machine, cumulative system PATH growth (winget per-package additions plus our re-unpacker bin dir plus accumulated entries from prior re-unpacker versions and any unrelated software) crossed the legacy 2047-char REG_SZ environment variable buffer limit. Windows' env-var change broadcast mechanism shows a modal "PATH env variable too big" dialog when a registry write would exceed this limit. v0.4.6's `_add_install_dir_to_system_path` had no length check before calling `winreg.SetValueEx`.

This isn't a code change in v0.4.6 (the PATH update logic is unchanged from v0.4.4); it's the cumulative effect of repeated installations across versions finally crossing the threshold during this run.

Fix: rewrote `_add_install_dir_to_system_path` to:

1. **Always update the current Python process's PATH first**, idempotently and process-locally (using `os.environ`). This can never trigger the Windows dialog because it doesn't touch the registry. It enables current-run tool discovery via the standard PATH mechanism for subprocesses Claude spawns within this Python invocation.
2. **Use `os.path.normpath`** for idempotency comparison instead of raw string comparison. Without normalization, `C:\Program Files\re-unpacker\bin\` and `C:\Program Files\re-unpacker\bin` are treated as different entries even though they're the same directory; case variation (`C:\PROGRAM FILES\...`) likewise.
3. **Length-check the proposed new PATH value before writing the registry**, with a safe threshold of 1900 chars (margin under 2047).
4. **Skip the registry write with a clear, actionable warning** if the threshold would be exceeded. The warning explains:
   - Current PATH size and what the appended size would be
   - Why we're skipping (Windows-safe threshold)
   - That re-unpacker tools remain discoverable via Pass 0 of `_windows_well_known_lookup` (so re-unpacker continues to work)
   - That external shells won't see these tools on PATH unless the user manually cleans up cumulative PATH bloat in System Properties > Environment Variables
5. **Continue gracefully** -- the install batch doesn't fail just because we skipped the registry update. Pass 0 (added in v0.4.6) is the always-on discovery mechanism for re-unpacker invocations; the registry update is the usability optimization for external shells.

**Bug PLISTUTIL-PROBE-STDIN-01 (cosmetic).** v0.4.6 testrun510.txt line 562:

```
Tool found: plistutil -> C:\Program Files\re-unpacker\bin\plistutil.exe
  (version: ERROR: reading from stdin is not supported on Windows)
```

Cause: tools.py probes plistutil with no args; plistutil with no args waits for stdin input; our `subprocess.DEVNULL` for stdin produces immediate EOF; tool emits the error string above to stderr; our probe captures stderr as the version field. plistutil from libimobiledevice doesn't have a `--version` or `--help` flag that exits cleanly with version info.

Fix: added `plistutil` to `_NO_EXEC_PROBE_TOOLS` in `tools.py`. This existing mechanism (used for `msiexec` since v0.4.2) marks tools that should be existence-checked only, no exec probe. Version field now reads "installed" instead of the misleading stderr capture. The tool's actual functionality is verified by the extractors that use it.

**Lesson L44:** modifying system-wide environment variables requires length validation, normalized idempotency checks, and a fallback discovery path that doesn't depend on the env var. The v0.4.6 Pass 0 well-known lookup is exactly that fallback path -- v0.4.7's PATH overflow guard relies on it.

**v0.4.0 architectural decisions and inventory unchanged.** v0.4.4 manual-install handler subsystem and v0.4.6 detection improvements are intact.

### 0.4.6 -- Patch release (manual-install detection + handler accuracy fixes)

Five bugs from the v0.4.5 Windows 11 Pro field test (testrun.txt, 491 lines, pid 8876 install + pid 6248 post-tools-check). The v0.4.4 manual-install handler subsystem itself was running correctly: 7 winget packages installed, 3 GitHub-release handlers extracted binaries successfully into `C:\Program Files\re-unpacker\bin\`. The bugs were in adjacent layers (detection, asset matching, output decoding) -- not the install pipeline.

**Bug DETECT-MANUAL-INSTALLS-01 (CRITICAL).** The user's log showed: line 311-317 ewftools extracted (5 .exe + 2 .dll), line 349-352 osslsigncode extracted (1 .exe + 3 .dll), line 358-384 pdfdetach extracted (1 .exe + 25 .dll) -- ALL into `C:\Program Files\re-unpacker\bin\` per the v0.4.4 design. Then line 408 starts a new Python process for the immediately-following `--tools-check`, and lines 419-420, 449, 450 report ewfexport, ewfinfo, osslsigncode, pdfdetach all MISSING. Root cause: Windows propagates HKLM PATH updates to new processes only after `WM_SETTINGCHANGE` broadcast, AND child processes of a still-running shell inherit the OLD PATH. The well-known directory probe in `_windows_well_known_lookup` didn't include the manual-install directory, so tools we installed couldn't be found unless the user opened a new shell.

Fix: added Pass 0 to `_windows_well_known_lookup` that probes `C:\Program Files\re-unpacker\bin\` directly via a new `_re_unpacker_install_dirs()` helper. This Pass runs FIRST in the lookup chain and catches every tool the framework auto-installs, regardless of PATH propagation state. Lesson L41 captures the pattern.

**Bug PLISTUTIL-WRONG-ASSET-01.** Line 389 of the v0.4.5 log: `Downloading https://github.com/libimobiledevice-win32/imobiledevice-net/releases/download/v1.3.17/libimobiledevice.1.2.1-r1122-osx-x64.zip`. The macOS asset! v0.4.4's plistutil handler used `asset_name_hint="x64"` which substring-matched `osx-x64` before reaching any `win-x64` asset. The handler downloaded a Mach-O archive, found no `plistutil.exe` inside, and reported failure -- a misleading symptom of a wrong-asset bug.

Fix: changed `asset_name_hint` from `"x64"` to `"win-x64"` to specifically match the Windows asset variant. Lesson L42 captures the pattern: substring asset hints must include a platform discriminator, never just an architecture.

**Bug BINWALK-NOT-DETECTED-01.** Line 304: `Running: C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe -m pip install --upgrade binwalk`. pip ran for ~5 seconds (line 305 starts the next dispatch). pip places entry-point scripts at `<python_install_root>\Scripts\<tool>.exe`, which is on PATH only if Python's installer registered it AND only if the user has restarted their shell since. The v0.4.5 well-known lookup didn't probe Python Scripts dirs, so binwalk was reported MISSING.

Fix: added Pass 6 to `_windows_well_known_lookup` via a new `_python_scripts_dirs()` helper that globs Python Scripts directories from BOTH system-wide locations (`%ProgramFiles%\Python*\Scripts\`) AND user-scope locations (`%LocalAppData%\Programs\Python\Python*\Scripts\`). Pass 6 handles every pip-installed CLI tool. Note: probing `%LocalAppData%\Programs\Python\` doesn't violate the user's "no AppData installs" rule from v0.4.4 Q1; we're not installing there, we're searching there for tools that pip's own infrastructure put there. Lesson L43 captures the pattern.

**Bug SIGCHECK-BOM-PERSISTS-01.** Line 273 and 468: `Tool found: sigcheck -> ... (version: ��)`. v0.4.4's BOM-stripping fix in `tools.py` was string-level, but subprocess output is decoded BEFORE my code runs -- with `errors='replace'`, raw `\xff\xfe` UTF-16 LE BOM bytes become `\ufffd\ufffd` (Unicode replacement characters), not `\ufeff`. The string-level strip looked for `\ufeff` and missed the replacement chars entirely.

Fix: moved BOM detection to the byte level in `subprocess_utils._decode_with_bom`. The new function inspects the leading bytes of subprocess output and:

- `\xff\xfe\x00\x00` -> decode as UTF-32 LE
- `\x00\x00\xfe\xff` -> decode as UTF-32 BE
- `\xff\xfe` -> decode as UTF-16 LE
- `\xfe\xff` -> decode as UTF-16 BE
- `\xef\xbb\xbf` -> decode as UTF-8 (BOM stripped)
- otherwise -> UTF-8 with errors='replace'

The string-level `\ufeff` strip in tools.py is kept as belt-and-suspenders, plus also strips leading `\ufffd` (replacement chars) defensively for any path that doesn't go through `_decode_with_bom`. Verified with synthetic inputs: `_decode_with_bom(b"\xff\xfeS\x00i\x00g\x00c\x00h\x00e\x00c\x00k\x00")` returns `"Sigcheck"` cleanly.

**Bug EWF-DOUBLE-DOWNLOAD-01 (efficiency).** Lines 306-317 (ewfexport handler) installed 7 ewf*.exe binaries from alpine-sec/ewf-tools-x64.zip; lines 318-329 (ewfinfo handler) downloaded and extracted the SAME 14MB zip again. Cause: dispatcher only marked the dispatched tool as `already_handled`, not all related-family names. Each iteration re-downloaded the full zip.

Fix: when libewf is dispatched (for either `ewfinfo` or `ewfexport`), the handler is now called with `["ewfinfo", "ewfexport"]` in one go and returns results for both names. The `already_handled` set then blocks the second iteration's redundant download. This is a common pattern for handlers that produce multiple binaries from one asset.

**Improvement: per-tool result logging (lesson L39 fulfillment).** v0.4.5's log showed only the `--- Manual install: X ---` headers; per-tool result (status + message) wasn't logged. Hard to diagnose remotely whether a handler succeeded, failed gracefully, or crashed. Now each result emits at INFO/WARNING/DEBUG depending on status: `[OK] <tool>: <message>` for success, `[FAIL] <tool>: <message>` for failure (with the actionable diagnostic), `[SKIP] <tool>: <message>` for upstream-unavailable / out-of-scope / not-yet-implemented. End-of-batch summary is now also written to the log file (was previously console-only via `print()`).

**Lessons captured:**

- **L41**: tools installed by the framework must be discoverable independently of system PATH. PATH is fragile across process trees, shells, and OS broadcast timing; direct probing of the install dir is deterministic.
- **L42**: substring asset-name hints must include a platform-discriminating substring (`"win-x64"`, not `"x64"`). Multi-platform releases are common and `"x64"` substring-matches them all.
- **L43**: Python entry-point scripts (pip-installed binaries) need explicit probe-path coverage. Whether Python Scripts is on PATH depends on installer choices and shell restart state; probing the dir directly removes both dependencies.

**v0.4.0 architectural decisions and inventory unchanged.** The v0.4.4 manual-install handler subsystem is intact: 8 working auto-installers, 28 honest-skip entries (libyal beyond ewf, ent, qemu-img, file), 3 out-of-scope entries (signtool, apksigner, apktool).

### 0.4.5 -- Patch release (UnboundLocalError scoping bug)

Field bug from v0.4.4 Windows 11 Pro test:

```
File "...\src\re_unpacker\cli.py", line 777, in _run_install
    registry = build_and_probe_registry(logger=logger)
UnboundLocalError: cannot access local variable 'build_and_probe_registry'
where it is not associated with a value
```

`re-unpacker --install --yes` crashed immediately, before any install work began.

**Root cause:** v0.4.4's manual-install integration in cli.py added a redundant function-local import at line ~822:

```python
if is_windows():
    from .manual_install_windows import install_missing_tools_windows
    from .tools import build_and_probe_registry  # <-- the bug
    post_winget_registry = build_and_probe_registry(logger=logger)
```

Python's static scope analysis is whole-function: if a name is bound (including via `from X import Y`) anywhere in a function, every reference to that name in the function is treated as a local variable. The earlier reference at line 777 -- which had been resolving against the module-level import at line 62 (`from .tools import build_and_probe_registry, format_tools_check_report`) -- became an UnboundLocalError because Python now saw `build_and_probe_registry` as function-local but it wasn't bound until line 822 (which was unreachable from the earlier line 777 reference).

**Fix:** dropped the redundant local import. The module-level import at line 62 covers all references throughout cli.py. Kept the Windows-only `from .manual_install_windows import install_missing_tools_windows` as a legitimate platform-gated lazy import (no prior reference to that name in the function; no shadowing).

**Verification:** added bytecode inspection to the test flow:

```python
import re_unpacker.cli as cli
local_names = set(cli._run_install.__code__.co_varnames)
assert 'build_and_probe_registry' not in local_names, (
    "BUG: build_and_probe_registry is function-local; will UnboundLocalError"
)
assert 'install_missing_tools_windows' in local_names, (
    "should still be a function-local (Windows-only platform-gated import)"
)
```

This catches the exact failure mode at compile time rather than waiting for a Windows runtime trace.

**Lesson L40:** local imports in Python shadow module-level bindings for the entire function. When adding a function-local import, scan the entire function body first for any prior reference to the same name. Default to module-level imports unless platform-gating requires lazy import.

**v0.4.4 manual-install handler subsystem is unchanged.** All 8 working auto-installers (binwalk, upx, ssdeep, osslsigncode, innoextract, ewfinfo+ewfexport, plistutil, pdfdetach), 28 honest-skip entries (libyal beyond ewf, ent, qemu-img, file), and 3 out-of-scope entries (signtool, apksigner, apktool) ship as designed in v0.4.4.

**New Usage Guide playbook:** 21.46 (UnboundLocalError on Windows --install).

### 0.4.4 -- Manual install handler subsystem (closes the v0.4.0/v0.4.x gap)

Implements per-tool auto-install handlers for the ~30 Windows tools that have no winget Package ID. Through v0.4.3, those tools were skipped entirely by `--install`, leaving the user with a partial install batch and a manual install task list. v0.4.4 closes that gap with the scope explicitly confirmed by the user before implementation began (per the project's hard-rule L28 against shipping partial solutions on ambiguous scope).

**User-confirmed scope (Q&A from v0.4.3 release):**

- **Q1 -- Install location:** `C:\Program Files\re-unpacker\bin\` (machine scope, admin required). NEVER `%LOCALAPPDATA%`. The user's stated reason: "%APPDATA% is not a proper or secure installation location by any standard, policy or practice."
- **Q2 -- Distribution:** auto-download at install time from each tool's canonical upstream release (no bundled binaries; tarball stays small at ~310KB; version is always current).
- **Q3 -- Coverage:** everything except `signtool` (user has Windows SDK already), `apksigner` / `apktool` / `aapt2` (Android SDK; user chose to skip).
- **Q4 -- Failure mode:** graceful continuation. Per-tool failures log with actionable diagnostic; batch continues with remaining tools; non-zero exit code at end-of-batch if any handler failed (signal to CI/automation).

**Working auto-install handlers (8 tools, full coverage):**

| Tool | Source | Mechanism |
|---|---|---|
| `binwalk` | PyPI | `python -m pip install --upgrade binwalk` |
| `upx` | upx/upx GitHub release | latest `upx-*-win64.zip` -> extract `upx.exe` |
| `ssdeep` | PyPI | `pip install ssdeep` (best-effort: provides Python bindings; ssdeep CLI may need separate install) |
| `osslsigncode` | mtrojnar/osslsigncode | latest Windows ZIP release |
| `innoextract` | dscharrer/innoextract | latest Windows ZIP release |
| `ewfinfo` + `ewfexport` | alpine-sec/ewf-tools | third-party Windows binary mirror of libyal/libewf (libyal upstream is source-only) |
| `plistutil` | libimobiledevice-win32/imobiledevice-net | latest x64 ZIP release |
| `pdfdetach` | oschwartz10612/poppler-windows | latest Release ZIP |

**Honest skips (upstream doesn't publish Windows binaries):**

The following 28 tools are skipped with explicit `"upstream publishes source-only releases; no pre-built Windows binaries available. Build from source (requires Visual Studio C++, Python, autotools) or skip this tool"` messages -- not silent failures:

- libyal toolset (joachimmetz GitHub) beyond libewf: `vmdkinfo`, `vmdkexport`, `vhdiinfo`, `vhdiexport`, `qcowinfo`, `qcowexport`, `fsapfsinfo`, `fsapfsexport`, `fsntfsinfo`, `fsntfsexport`, `fsextinfo`, `fsextexport`, `fsfatinfo`, `fsfatexport`, `fshfsinfo`, `fshfsexport`, `fsxfsinfo`, `fsxfsexport`, `vshadowinfo`, `vshadowexport`, `vslvminfo`, `vslvmexport`, `luksdeinfo`, `smrawinfo`, `smrawverify`, `phdiinfo`, `phdiexport`
- `ent`: no canonical Windows distribution from fourmilab.ch (source only)
- `qemu-img`: requires custom installer handler for qemu.weilnetz.de Windows builds (not yet implemented; clear pointer in skip message)
- `file`: ships with Git for Windows; pointer to `winget install Git.Git`

**Out-of-scope per Q3:** `signtool`, `apksigner`, `apktool`.

**Architecture (`src/re_unpacker/manual_install_windows.py`, ~600 lines):**

- `install_missing_tools_windows(tool_names, *, logger)` -- top-level entry point. Returns `ManualInstallSummary` with succeeded / failed / skipped lists.
- Pre-flight: `is_admin()` check (writes to `Program Files`), `_ensure_install_dir()` creates `C:\Program Files\re-unpacker\bin\`, `_add_install_dir_to_system_path()` updates HKLM PATH idempotently AND `os.environ['PATH']` for the current process.
- Helpers: `_http_get_json` (GitHub release API), `_http_download` (atomic via .part rename), `_extract_zip` (with zip-slip path-traversal protection), `_find_executables` (recursive walk filtered by name list).
- Per-tool dispatcher: `_dispatch_handler(tool_name)` routes to the right handler. Tools NOT in any registry are reported as "no auto-install handler registered" rather than crashing.
- `_OUT_OF_SCOPE` dict for the user-excluded tools; `_DEFERRED_NO_UPSTREAM` dict for the libyal source-only tools; both keyed for transparency.

**Integration (`src/re_unpacker/cli.py` `_run_install`):**

After the winget batch on Windows:

1. Re-probe the tool registry to identify what's STILL missing
2. Filter to tools with empty `package_hint` (i.e. not winget-installable; would have been skipped before v0.4.4)
3. Call `install_missing_tools_windows()` with those names
4. Print `summary.format_human()` to stdout
5. Return exit code `6` (PackageManagerError-equivalent) if any handler failed; `0` if all succeeded or were gracefully skipped

The Linux apt path is unchanged. Existing test fixtures (Linux regression: schema 1.1.0, tool 0.4.4, 0 errors) all pass.

**Bonus fix: sigcheck UTF-16 BOM mojibake.**

The v0.4.3 testruncmd.txt log showed `Tool found: sigcheck -> ... (version: ��)` -- sigcheck.exe writes a UTF-16 BOM at the start of its console output, which when decoded as UTF-8 produced mojibake characters. Fixed in `tools.py` probe: `lstrip("\ufeff")` removes the Unicode BOM character; defensive byte-level BOM stripping handles raw-byte cases too. Lesson L38 captures the pattern.

**Lessons captured (`tasks/lessons.md`):**

- **L37**: Verify upstream binary distribution before promising auto-install. libyal projects are the canonical case: source-only releases mean no automatic install path exists. Honest "no upstream Windows binaries" skip is better than a silent 404 failure.
- **L38**: Subprocess output decoding must handle Windows BOM. Tools like Sysinternals utilities emit BOM bytes; strip before parsing.
- **L39**: When implementing graceful-failure mode, the failure must produce actionable diagnostic output. "binwalk install failed: HTTP 403 from PyPI; check network proxy or run `pip install binwalk` manually" is actionable; "binwalk install failed" is not. End-of-batch summary distinguishes succeeded / skipped / failed for clarity.

### 0.4.3 -- CRITICAL fix release (Windows 11 Pro field bugs, third round)

Two field-reported bugs from a third Windows 11 Pro test run with v0.4.2. Lessons captured in `tasks/lessons.md` (L35 + L36). v0.4.0 architectural decisions and inventory unchanged.

**Bug WINGET-FLAG-01 (CRITICAL, blocking): `--accept-source-agreements` is invalid for `winget source update`.**

The user's v0.4.2 test produced a red error in the console:

```
Argument name was not recognized for the current command: '--accept-source-agreements'
```

Root cause: v0.4.1's `_refresh_source()` (added to fix the Fast Cache 0x80071130 issue) ran `winget source update --accept-source-agreements`. The `--accept-source-agreements` flag is documented as valid for `winget install`, `winget uninstall`, and `winget upgrade` -- but NOT for `winget source update`. winget rejected the entire invocation. The error was non-blocking (rc=non-zero, source update failed and proceeded with stale cache) but visible and user-confusing.

Fix: removed `--accept-source-agreements` from the `_refresh_source()` argv in `pkg_manager.py`. The new invocation is just `winget source update`, which is the documented correct form.

**Bug WELL-KNOWN-PATHS-INCOMPLETE-01: post-install detection still fails for portable winget packages.**

The user reported: "only approximately 7 tools install" -- but examining the actual final `--tools-check` output more carefully, the well-known fallback added in v0.4.2 worked for some tools (7-Zip found at `C:\Program Files\7-Zip\7z.exe`, GnuPG at `C:\Program Files\GnuPG\bin\gpg.exe`) and FAILED for: ExifTool, QPDF, Sigcheck, YARA, yarac. All five were installed successfully by winget but the well-known map didn't know where to find them.

Root cause: winget categorizes installer types and routes binaries accordingly. Traditional Inno/MSI installers use `%ProgramFiles%\<Vendor>\` (which v0.4.2 covered). But:

- **Portable / archive (zip) installers** (used by Sysinternals.Sigcheck, VirusTotal.YARA): files go to `%LOCALAPPDATA%\Microsoft\WinGet\Packages\<PackageId>_Microsoft.Winget.Source_8wekyb3d8bbwe\` (user scope) or `C:\Program Files\WinGet\Packages\<PackageId>_Microsoft.Winget.Source_8wekyb3d8bbwe\` (machine scope). winget creates shim links at `%LOCALAPPDATA%\Microsoft\WinGet\Links\` (or `C:\Program Files\WinGet\Links\`).
- **Inno installers in user scope** (ExifTool with `--silent` and no admin): files go to `%LocalAppData%\Programs\<Vendor>\`.
- **Version-stamped Inno installers** (QPDF): files go to `%ProgramFiles%\qpdf X.Y.Z\bin\qpdf.exe` -- versioned dir.

Fix: extended `_windows_well_known_lookup()` to a five-pass probe:

1. **Pass 1: WinGet Links directories.** Single rule covering ALL portable winget packages via shim links. `%LOCALAPPDATA%\Microsoft\WinGet\Links\<tool>.exe` and `C:\Program Files\WinGet\Links\<tool>.exe`. This catches Sigcheck, YARA, yarac, and any future portable winget package automatically.
2. **Pass 2: hardcoded per-tool paths under Program Files roots.** Keeps v0.4.2 behavior for traditional installs (7-Zip, GnuPG, etc.).
3. **Pass 3: glob-based fallback for version-stamped install dirs.** `%ProgramFiles%\qpdf*\bin\qpdf.exe` catches QPDF's versioned install directory.
4. **Pass 4: `%LocalAppData%\Programs\` for Inno user-scope.** Covers ExifTool when winget chooses user scope.
5. **Pass 5: WinGet Packages dirs per-package iteration.** Final fallback if a Links shim is missing or named differently from the binary; iterates `<PackageRoot>\<id>\<tool>.exe` and one level deeper.

Three new helper functions in `platform_compat.py`: `_winget_links_dirs()`, `_winget_packages_dirs()`, `_local_appdata_programs_dir()`.

**Important note: scope of the broader user complaint.**

The user's overall reaction -- "the script only installs approximately 7 tools (it would install 8 if powershell didn't already exist). This is unacceptable." -- accurately points to a larger gap. The Windows tool inventory has ~30 entries with empty install hints (`KNOWN_UNAVAILABLE_PACKAGES_WIN`) marking them as "manual install required":

- libyal toolset (16 binaries: ewf*, vmdk*, vhdi*, qcow*, fsapfs*, fsntfs*, fsext*, fsfat*, fshfs*, fsxfs*, vshadow*, vslvm*, luksde*, smraw*, phdi*) -- joachimmetz GitHub releases
- binwalk (pip install)
- upx, ssdeep, osslsigncode, innoextract (GitHub release ZIPs)
- qemu-img (qemu-w64-setup-*.exe)
- signtool (Windows SDK -- requires Microsoft installer)
- apksigner / apktool / aapt2 (Android SDK -- requires Google installer)
- file / plistutil / pdfdetach / ent (varying availability)

Implementing automatic installation for these requires a manual-install handler subsystem with HTTP downloads (urllib + ssl), ZIP extraction (zipfile), pip dispatch, GitHub release URL research per tool, version pinning, checksum verification, install location management (`%LOCALAPPDATA%\re-unpacker\bin\`), and per-tool verification. That's a substantial amount of new code (estimated 1500+ lines) with several scope decisions:

- Bundle binaries in the tarball (license complications) vs auto-download at install time (network requirement)?
- Pin versions vs always fetch latest?
- Where to install (user scope `%LOCALAPPDATA%\re-unpacker\bin\` vs machine scope `C:\Program Files\re-unpacker\bin\`)?
- How to handle SDK requirements (signtool, apksigner) that genuinely cannot be auto-installed?

Per the project's hard-rule L28 ("never assume; STOP and ask on ambiguous scope"), this is being explicitly scoped as v0.4.4 with user input rather than implemented partial in v0.4.3.

**New Usage Guide playbooks:** 21.43 (winget source update flag error), 21.44 (winget portable package detection paths).

### 0.4.2 -- Patch release (Windows 11 Pro field bugs, second round)

Four bugs from a second Windows 11 Pro test run, plus one UX refinement. Lessons captured in `tasks/lessons.md` (L32 + L33 + L34). v0.4.0 architectural decisions and inventory unchanged.

**Bug MSI-PROBE-01: msiexec /? probe opens Windows Installer GUI dialog AND crashes with `os.killpg` AttributeError.**

The user reported "At every test execution, the framework generates an Windows Installer pop-up panel." Two compounding root causes:

1. The Windows version probe for msiexec was `("/?",)`, but on Windows `msiexec /?` opens the Windows Installer help dialog (a GUI window), not a console version banner. The probe blocked for 15 seconds (the run_tool timeout) until the user dismissed the dialog manually.
2. `subprocess_utils.run_tool()` used POSIX-only `os.killpg(proc.pid, signal.SIGTERM)` in its timeout-cleanup path. On Windows, `os.killpg` doesn't exist; the cleanup crashed with `AttributeError: module 'os' has no attribute 'killpg'`.

Fix:

- New `_NO_EXEC_PROBE_TOOLS = frozenset({"msiexec"})` in `tools.py`. Tools in this set are detected by existence-on-PATH only; the version field shows the placeholder "installed". Eliminates the GUI popup at the source.
- New `subprocess_utils._terminate_proc_tree(proc, hard=False/True)` helper replaces all five `os.killpg` callsites. POSIX path keeps existing `os.killpg(proc.pid, sig)` group-kill semantics. Windows path uses `proc.terminate()` (calls TerminateProcess on the immediate child) or `proc.kill()` if `hard=True`.

**Bug POST-INSTALL-PATH-01: tools installed via winget not detected by subsequent --tools-check in the same process.**

The user's testrun.txt log showed: after `re-unpacker.ps1 --install --yes` ran 7 winget installs successfully (7-Zip, ExifTool, GnuPG, PowerShell 7+, QPDF, Sigcheck, YARA), the immediately-following `--tools-check` reported all 7 still missing. Two compounding root causes:

1. `os.environ['PATH']` is captured at Python process start; the winget `WM_SETTINGCHANGE` broadcast doesn't reach already-running Python processes.
2. Several common winget packages don't auto-add to system PATH at all: 7-Zip installs to `C:\Program Files\7-Zip\`, GnuPG to `C:\Program Files (x86)\GnuPG\bin\`, Sysinternals/Sigcheck to varying locations, YARA paths vary by installer.

Fix:

- `platform_compat.which_tool()` now falls back to well-known install directories on Windows when `shutil.which()` misses. Curated map covers 7-Zip (`C:\Program Files\7-Zip\7z.exe`), GnuPG (`...\GnuPG\bin\gpg.exe`), QPDF (`...\qpdf\bin\qpdf.exe`), Sysinternals/Sigcheck, ExifTool (OliverBetz packaging), YARA. Both `%ProgramFiles%` and `%ProgramFiles(x86)%` roots are probed.
- New `platform_compat.refresh_path_from_registry()` re-reads HKLM\\System\\...\\Environment\\Path and HKCU\\Environment\\Path into `os.environ['PATH']` after an install batch, picking up tools that DID add themselves to PATH but weren't visible to the current process. Called automatically from the `--install` flow on Windows.
- `tools.py` probe layer now uses `platform_compat.which_tool` instead of bare `shutil.which` so the well-known-directory fallback applies to every probe.
- `--install` completion message on Windows now includes "Note: if any tools still appear missing after this, restart your shell" guidance.

**Bug TOOLS-CHECK-FOOTER-01: --tools-check footer hardcoded for Kali / Debian.**

The user reported: "executing `.\re-unpacker.ps1 --tools-check ...` on a Windows 11 Pro system has this output at the end of console output: 'To install everything missing on Kali / Debian: sudo apt-get update && sudo apt-get install -y 7zip.7zip GnuPG.GnuPG ...'". The apt-get command was hardcoded; the package list was the WINGET identifiers (which apt would not resolve).

Fix:

- `tools.py` `format_tools_check_report()` footer is now platform-aware via `platform_compat.is_windows()`. On Linux: keeps existing `sudo apt-get update && sudo apt-get install -y ...` instruction with apt package names. On Windows: prints `To install the N missing winget-managed tool(s) on Windows: re-unpacker --install --yes` followed by the winget Package IDs as informational context. Built-in tools (empty hint) and manual-install tools redirect to ReUnpacker-Usage-Guide.html section 22.2.
- `--dry-run-install` mode similarly platform-aware: Linux still emits apt commands; Windows emits the `re-unpacker --install/--uninstall/--repair --yes` form.

**Bug UNKNOWN-PACKAGE-MSG-01: empty hints displayed as "unknown package".**

Empty-string entries in `TOOL_PACKAGE_HINTS_WINDOWS` (manual-install tools like libyal binaries, signtool, binwalk) showed in the `--tools-check` log as `(install hint: unknown package)`. Fix: `tools.py` probe formatter now emits `(install hint: manual install (see Usage Guide section 22.2))` for empty hints.

**UX: Microsoft.PowerShell wrongly recommended for install.**

The user pointed out that the v0.4.1 install footer recommended installing `Microsoft.PowerShell` even though Windows PowerShell 5.1 (built into Windows 10+) was already detected. PowerShellAuthenticodeVerifier uses the `powershell` (5.1) command, not `pwsh` (7+); they're functionally interchangeable for re-unpacker's needs.

Fix: new `_OPTIONAL_ALTERNATIVES` mapping in `tools.py`:

```python
_OPTIONAL_ALTERNATIVES = {
    "pwsh":  "powershell",   # PowerShell 7+ optional when 5.1 is present
    "7zz":   "7z",            # alternate name; same binary
    "yarac": "yara",          # part of yara package; redundant if yara is present
}
```

When a tool listed as a key has its alternative already detected, the tool is excluded from the install recommendation. The status table still shows it as MISSING (so the user can see the state), but the footer suppresses it from the "you should install these" list and adds a "Note: the following missing tools are OPTIONAL because their canonical alternative is already available" footnote.

**New Usage Guide playbooks:** 21.40 (Windows Installer popup at every run), 21.41 (winget-installed tools not detected), 21.42 (platform-aware tools-check footer).

### 0.4.1 -- Patch release (Windows 11 Pro field bugs)

Two bugs surfaced from a Windows 11 Pro field deployment of v0.4.0. Both fixed; lessons captured in `tasks/lessons.md` (L30 + L31). v0.4.0 architectural decisions and inventory unchanged; this is a patch-level release.

**Bug WIN-01: winget source not pre-initialized before install (rc=2147946800 / 0x80071130).**

The user's first `--install` attempt on a fresh Windows 11 Pro install failed with `0x80071130 : Fast Cache data not found` after attempting to install VirusTotal.YARA. Root cause: `WingetBackend.install_packages()` did not run `winget source update` before the install loop, even though the class defined a `refresh_index: bool = True` field documenting the intent. AptBackend correctly runs `apt-get update` when `refresh_index=True`; the winget analog was never wired up. On freshly-provisioned Windows systems, winget's source cache isn't populated and the first install fails before reaching the actual download step.

Fix:

- New `WingetBackend._refresh_source()` method calls `winget source update --accept-source-agreements`. Invoked from `install_packages()` when `refresh_index=True` (default). Defensive: source-update failure is logged-and-warned, not fatal -- the install attempt still runs against any pre-existing cached data.
- `WingetBackend._run_streaming()` now detects `rc=2147946800` (and the signed equivalent `-147020496`, both representations of `0x80071130`) explicitly and includes a `fix:` field in the raised `PackageManagerError`'s context dict, recommending: `winget source update --source winget`, `winget source reset --force`, OR reinstalling App Installer from the Microsoft Store.
- The existing `--no-refresh-index` flag works on Windows too (skips `winget source update`), useful on offline systems where the refresh can't run.

**Bug HELP-01: --help missing platform-aware concrete examples.**

The user reported "the help and instructional information does not provide indication of execution of the re-unpacker script against a target directory or file." Root cause: argparse `description` was one terse sentence; `_EPILOG` examples used `./re-unpacker sample.deb` (Linux bash invocation) only with no Windows equivalents; bare-invocation error gave no example at all.

Fix:

- argparse `description` now includes the explicit instruction "Pass a file or directory as the first argument; see Examples below for concrete invocations on each platform."
- `_EPILOG` now leads with a "Quick start" block showing all four invocation paths (Linux/macOS bash, Windows PowerShell, Windows cmd.exe, direct python). The Examples section now includes a Windows PowerShell example (`.\re-unpacker.ps1 C:\samples\firmware.bin -o C:\scratch\out`).
- Bare-invocation error now embeds a literal example: `Pass a file or directory as the first argument, e.g.:\n\n  ./re-unpacker sample.deb` (Linux) or `.\re-unpacker.ps1 sample.cab` (Windows). The example is platform-aware via `platform_compat.is_windows()`.

**New Usage Guide playbook 21.39: winget --install fails with 0x80071130 "Fast Cache data not found".** Walks through the symptom, the root cause, the v0.4.1 auto-refresh fix, and three manual remediation steps if the auto-refresh doesn't resolve the issue.

### 0.4.0 -- Windows-tandem release (cross-platform Python)

Significant feature release. Brings re-unpacker to Windows as a tandem platform alongside Linux, using a single cross-platform Python codebase with runtime platform detection. **Manifest schema unchanged at 1.1.0**: a Linux v0.3.2 manifest and a Windows v0.4.0 manifest are byte-interchangeable for downstream tooling.

**Architectural delta vs v0.3.2**

- New `re_unpacker/platform_compat.py` module: central abstraction for platform detection (`is_windows()`, `is_linux()`, `is_macos()`, `current_platform()`), filesystem layout (`cache_dir()`, `config_dir()` -- XDG paths on Linux, `%LOCALAPPDATA%` / `%APPDATA%` on Windows), admin detection (`is_admin()` -- wraps `os.geteuid() == 0` on Linux, `IsUserAnAdmin()` on Windows), file mode synthesis (`format_mode_string()` -- 4-char zero-padded octal on Linux, synthesized "0644" / "0444" / "0755" from Windows file attributes), tool resolution (`which_tool()`, `executable_suffix()`), YARA rule discovery paths (`default_yara_rule_dirs()`), and long-path handling (`long_path_supported()`, `normalize_long_path()`).
- `constants.py` split into `TOOL_PACKAGE_HINTS_LINUX` (93 tools, unchanged) + `TOOL_PACKAGE_HINTS_WINDOWS` (56 tools, new). Same pattern for `KNOWN_UNAVAILABLE_PACKAGES`. Both resolved at module-load time to a single `TOOL_PACKAGE_HINTS` symbol matching the running platform; existing call sites work unchanged.
- `tools.py` `_VERSION_PROBES` similarly split per-platform. Coverage check `set(_VERSION_PROBES) == set(TOOL_PACKAGE_HINTS)` passes on both platforms.

**Windows tool inventory (56 tools)**

Verified winget Package Identifiers against `microsoft/winget-pkgs`:

- **Built-in to Windows 10+** (no install): `tar`, `expand`, `msiexec`, `powershell`
- **winget-installable**: `7zip.7zip` (handles deb/rpm/cab/cpio/ar/vmdk/qcow2/vhd/vhdx/squashfs/iso natively), `OliverBetz.ExifTool`, `VirusTotal.YARA`, `GnuPG.GnuPG`, `QPDF.QPDF`, `Microsoft.Sysinternals.Sigcheck`, `Microsoft.PowerShell` (PowerShell 7+)
- **Manual install** (documented in `KNOWN_UNAVAILABLE_PACKAGES_WIN`): `binwalk` (pip), `upx`, `ssdeep`, `apksigner` (Android SDK), `osslsigncode`, `signtool` (Windows SDK), `file` (Git for Windows or python-magic-bin), `innoextract`, `qemu-img`, `apktool`, `plistutil`, `pdfdetach`, plus the libyal Windows binary set (`vmdkinfo`, `vmdkexport`, `vhdiinfo`, `vhdiexport`, `qcowinfo`, `qcowexport`, `vshadowinfo`, `vshadowexport`, `vslvminfo`, `vslvmexport`, `fsapfsinfo`, `fsapfsexport`, `fsextinfo`, `fsextexport`, `fshfsinfo`, `fshfsexport`, `fsxfsinfo`, `fsxfsexport`, `fsfatinfo`, `fsfatexport`, `fsntfsinfo`, `fsntfsexport`, `luksdeinfo`, `smrawinfo`, `smrawverify`, `phdiinfo`, `phdiexport`)

**Extractor adaptation (8 modules)**

Each of these gets a Windows code path while keeping the Linux path unchanged:

- `cab.py`: Linux `cabextract -d`; Windows `expand.exe -F:*` (built-in)
- `embedded_fs.py` (`MsCompressExtractor` for KWAJ/SZDD): Linux `msexpand`; Windows `expand.exe -R` (built-in handles KWAJ/SZDD natively)
- `cpio_ar.py`: Linux `cpio -idm` / `ar x`; Windows `7z x` (handles cpio + ar archive members)
- `deb.py`: Linux `dpkg-deb -R` (primary) and `ar x` + tar (fallback); Windows new `DebSevenZipExtractor` does three-stage 7-Zip extraction mirroring dpkg-deb's `dest/DEBIAN/` + `dest/<payload>` layout
- `rpm.py`: Linux `rpm2cpio | cpio` (primary) and `rpm2archive | tar` (fallback); Windows new `RpmSevenZipExtractor` uses 7-Zip's native RPM container support
- `msi.py`: Linux `msiextract`; Windows new `MsiExecExtractor` uses native `msiexec /a "<file>" /qn TARGETDIR=<dest>` administrative install
- `disk_image.py`: Linux libyal FUSE-mount path (existing); Windows new `WindowsSevenZipDiskExtractor` (priority 85) for VMDK/QCOW2/VHD/VHDX via 7-Zip's native disk-image support, plus `WindowsVmdkExportExtractor`/`WindowsQcowExportExtractor`/`WindowsVhdiExportExtractor` (priority 75) using libyal `*export -t <target> <source>` for users who installed the libyal Windows binary distributions
- `forensic_fs.py`: Linux libyal FUSE-mount path (existing); Windows new `WindowsSevenZipForensicFsExtractor` (priority 85) for NTFS/APFS/HFS+/EXT/FAT via 7-Zip's native filesystem support, plus `WindowsXfsExportExtractor`/`WindowsVssExportExtractor`/`WindowsLvm2ExportExtractor` (priority 75) for the niche kinds 7-Zip doesn't cover

The Linux-only extractors auto-filter on Windows because their `required_tools` (`dpkg-deb`, `rpm2cpio`, `msiextract`, `cabextract`, `mscompress`, `cpio`, `ar`, `vmdkmount`, `fusermount`, etc.) are absent from `TOOL_PACKAGE_HINTS_WINDOWS`. The Windows-only extractors override `is_supported()` to return False on Linux (where the canonical Linux path is preferred even when 7-Zip is available). No platform `if`/`else` chains in the extractor dispatch.

**Verifiers (NEW: +2 Windows-native)**

- `verifiers/windows_authenticode.py` (NEW): `PowerShellAuthenticodeVerifier` uses `Get-AuthenticodeSignature -FilePath '<path>'` (PowerShell 5.1 is built into every Windows 10+ install -- always available). `SigntoolVerifier` uses `signtool.exe verify /pa /v <path>` (optional; provides richer cert chain and timestamping info than the PowerShell cmdlet). Both apply to PE_*/MSI/CAB and produce the same `VerifierResult` shape as `OssLsignCodeVerifier`. Both auto-filter on Linux because their `required_tools` (`powershell`, `signtool`) are absent from `TOOL_PACKAGE_HINTS_LINUX`. Total verifier count goes 7 -> 9.
- Linux-only verifiers (`DebsigsVerifier`, `DpkgSigVerifier`, `RpmVerifier`) self-exclude on Windows by the same `required_tools` mechanism (no `is_windows()` check needed in `applies_to()`).

**Installer subsystem (winget alongside apt)**

- New `WingetBackend` class in `pkg_manager.py` mirrors the `AptBackend` interface (`install_packages`, `remove_packages`, `reinstall_packages`, `is_package_installed`). winget invocation pattern: `winget install --id <PackageId> --exact --silent --accept-source-agreements --accept-package-agreements`. winget has no atomic reinstall, so `reinstall_packages` does uninstall + install with the uninstall failure swallowed (so a partial earlier install doesn't block the install half).
- Top-level `detect_backend()` dispatches via `platform_compat.is_windows()`: returns `WingetBackend` on Windows, `AptBackend` on Linux. Existing CLI surface (`--install`, `--uninstall`, `--repair`) unchanged.
- `is_root()` now wraps `platform_compat.is_admin()` for cross-platform admin/elevation detection.

**Wrappers (3 shipped now)**

- `re-unpacker` (bash, existing) -- bumped to 0.4.0; now notes the Windows siblings exist
- `re-unpacker.ps1` (NEW) -- PowerShell wrapper with full comment-based help (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, `.NOTES`, `.LINK`); locates Python via Get-Command, prepends `src` to `PYTHONPATH`, splat-forwards arguments
- `re-unpacker.cmd` (NEW) -- minimal cmd.exe shim for users without PowerShell or with restrictive execution policy

**Output-layer parity (no exceptions)**

The fundamental contract: a Windows v0.4.0 manifest is interchangeable with a Linux v0.3.2 manifest. Same FileEntry shape (25 fields). Same RunStats counters (20). Same summary.txt sections. Same tree.txt format. Same manifest.json schema (1.1.0). Same CLI flags (28). Same exit codes. Same kinds extractable on both platforms. The MECHANISM differs (FUSE-mount on Linux vs 7-Zip / libyal `*export` on Windows; `osslsigncode` on Linux vs `signtool` / PowerShell on Windows), but the OUTPUT is identical.

**File operations**

- Mode field on Windows: synthesized as "0755" for directories, "0444" for read-only files, "0644" for regular read-write files. Heuristic; not an exact ACL translation, but produces stable strings that downstream consumers can read.
- Cache directory on Windows: `%LOCALAPPDATA%\re-unpacker\` (vs `~/.cache/re-unpacker/` on Linux).
- Long-path handling: detection via `LongPathsEnabled` registry value; per-operation `\\?\` prefix when path approaches MAX_PATH on Windows.

### 0.3.2 -- Subsystem B (verification) + Subsystem C (classification) + schema 1.1.0

Significant feature release. Adds per-file signature/integrity verification AND per-file classification enrichment. **First manifest schema bump since v0.1.0** (1.0.0 -> 1.1.0). Backward compat preserved: v0.3.1 and earlier manifests remain readable by v0.3.2 tooling, and downstream consumers using `dict.get()` patterns work transparently.

**Subsystem B: Signature verification.**

7 new verifier modules under `src/re_unpacker/verifiers/`. All verifiers run as always-on best-effort after extraction completes. Verifiers that don't apply silently record nothing; verifiers that ran record their result in `file_entry.verification`.

| Verifier | Tool | Applies to |
|---|---|---|
| `gpgv` | gpgv | Any file with sibling `.sig` / `.asc` companion |
| `debsigs` | debsigs | DEB |
| `dpkg-sig` | dpkg-sig | DEB |
| `debsums` | debsums | (DISABLED in v0.3.2 -- debsums fundamentally operates on installed packages, not .deb files at rest. Registered for tool-tracking only.) |
| `rpm-K` | rpm | RPM |
| `apksigner` | apksigner | APK |
| `osslsigncode` | osslsigncode | PE_EXECUTABLE / PE_NSIS / PE_INNOSETUP / PE_INSTALLSHIELD / PE_WIXBURN / MSI / CAB |

Each verifier honors `--enrich-timeout SEC` (default 30s). Timeouts record `error="timeout"`. There is NO opt-out flag for verification (always-on best-effort by design).

**Subsystem C: Classification enrichment.**

4 new classifier modules under `src/re_unpacker/classifiers/`. Each can be disabled individually via the new `--no-*` flags. All classifiers honor `--enrich-timeout` AND a hard 256 MiB size cap (`ENRICHMENT_SIZE_CAP_BYTES`). Files above the cap skip ALL classifiers with `enrichment_skipped="size_exceeds_cap"` recorded.

| Classifier | Tools | Field(s) populated |
|---|---|---|
| `entropy` | `ent` (with pure-Python fallback) | `entropy`, `encrypted`, `encryption_scheme` |
| `fuzzy_hash` | python3-tlsh + python3-ssdeep (preferred) or `ssdeep` CLI | `ssdeep`, `tlsh` |
| `exif` | `exiftool` | `exif_metadata` (nested dict, per-value 4096-char cap) |
| `yara` | python3-yara | `yara_matches` (list of dicts with rule_name / namespace / tags / meta) |

Pipeline order: entropy (cheap) -> fuzzy_hash -> exif -> yara (most expensive).

**YARA rule auto-discovery** (when `--yara-rules PATH` is NOT given): UNION of three default directories with namespacing.

| Default directory | Namespace prefix |
|---|---|
| `/etc/yara/` | `etc` |
| `~/.config/re-unpacker/yara/` | `user` |
| `/var/lib/yara-forge/packages/full/` | `forge` |

When `--yara-rules PATH` is given, only that path is loaded with namespace `custom`.

**Schema 1.1.0: 9 new optional FileEntry fields.**

```json
{
  "ssdeep": "768:abc...:xyz",
  "tlsh": "T1A2B3C4...",
  "entropy": 7.823,
  "encrypted": false,
  "encryption_scheme": null,
  "yara_matches": [
    {"rule_name": "Suspicious_Powershell", "namespace": "etc:0:rules",
     "tags": ["powershell", "obfuscated"], "meta": {"author": "..."}}
  ],
  "exif_metadata": { "FileType": "PE", "MachineType": "AMD64", ... },
  "enrichment_skipped": null,
  "verification": [
    { "verifier_name": "rpm-K", "performed": true, "applicable": true,
      "signed": true, "valid": true, "signer": null,
      "error": null, "duration_seconds": 0.123 }
  ]
}
```

All 9 fields are optional with sensible defaults; older manifest readers are unaffected.

**Schema 1.1.0: 8 new RunStats counters.**

`verifications_performed`, `verifications_signed_valid`, `verifications_signed_invalid`, `verifications_unsigned`, `yara_matches_total`, `files_yara_matched`, `enrichment_timeouts`, `enrichment_skipped_size`.

**summary.txt: two new sections.**

Per locked-in design decision, the human-readable summary now includes a full "Signature verification results" section AND a "Classification enrichment summary" section. The verification section has both a verifier-by-status rollup table and a per-file breakdown showing each verifier's outcome with duration and any signer/error info.

**6 new CLI flags.**

```
--no-yara              Skip YARA rule matching pass
--no-fuzzy-hash        Skip ssdeep + TLSH fuzzy hash computation
--no-exif              Skip exiftool metadata extraction
--no-entropy           Skip Shannon entropy computation
--yara-rules PATH      Bypass auto-discovery; load rules from PATH only
--enrich-timeout SEC   Per-pass per-file timeout (default: 30s)
```

**Tool registry expanded 82 -- 93 tools.** New entries: gpg, gpgv, debsigs, dpkg-sig, debsums, apksigner, osslsigncode, exiftool, ssdeep, yara, ent. Plus 3 new Python bindings tracked: python3-tlsh, python3-yara, python3-ssdeep.

**Bugs fixed during v0.3.2 development.**

- Wrong `RunResult` attribute names in 18 places across 7 verifier/classifier modules (`.stdout_bytes` / `.stderr_bytes` instead of `.stdout` / `.stderr`). Caught when entropy classifier silently no-op'd in smoke test.
- `debsums` doesn't verify .deb files at rest (it operates on installed packages). Resolution: DebsumsVerifier registered for completeness but `applies_to() -> False`.
- Unreadable dead-code conditional in rpm verifier; replaced with clean call.

**Verification: 17-test matrix, all passed.**

Including byte-identical regression on the canonical v0.1.x nested archive (22 files / 3 archives / 0 failed / 0 errors / depth 4), enrichment field population (22/22 entropy, 22/22 ssdeep, 10/22 tlsh, 7/22 exif), all 4 disable flags, size cap on 300MB synthetic file, custom YARA rule matching, missing-rule-path graceful no-op, and forward/backward schema compat.

### 0.3.1 -- production-rig fix release

Five issues caught during v0.3.0 deployment to a real Kali Linux rig (kernel 6.19.11-1kali1, 2026-04-09). All five fixes are scoped narrowly: no schema change, no functionality regressions, no new extractors. Subsystem B (verification) is rescoped to v0.3.2 to make room.

**ISS-001: Default file logging for non-extract modes.**

The five non-extract modes (`--tools-check`, `--install`, `--uninstall`, `--repair`, `--dry-run-install`) previously logged only to stderr. Output was lost as soon as the terminal scrolled. v0.3.1 adds a default per-invocation file log:

```
~/.cache/re-unpacker/logs/<mode>-<UTC_YYYYMMDD-HHMMSS>-<pid>.log
```

(or `$XDG_CACHE_HOME/re-unpacker/logs/...` when XDG_CACHE_HOME is set). The directory is created on first use with mode 0700. Each mode prints a one-line banner showing the resolved path. File logging is best-effort: an unwritable path falls back to console-only with a warning, never aborts the run.

**ISS-002: New `--log-file PATH` flag.**

Operators can now specify an explicit log file path. Behavior:

- Extract mode: `--log-file PATH` adds an additional handler on top of `<output>/extraction.log`. Both files receive output.
- Non-extract modes: `--log-file PATH` replaces the default cache-dir path.
- `--log-file -` disables file logging entirely.
- Parent directories are created with mode 0700 if missing.

**ISS-003: Wrong / missing package hints corrected.**

- `smrawinfo` hint dropped: `libsmraw-utils` does NOT ship `smrawinfo`. The package provides `smrawmount` and `smrawverify`. v0.3.1 tracks `smrawverify` as the correct companion to `smrawmount`.
- `libfsfat-utils` documented as a known-unavailable package via the new `KNOWN_UNAVAILABLE_PACKAGES` constant. The package is not currently shipped by Debian / Kali / Ubuntu stable. The `--install` path now logs an INFO-level message with the upstream-tracking link instead of failing the install batch with a generic warning.

**ISS-004: Expanded `_VERSION_PROBES` -- no more "(version: unknown)".**

The version-probe dictionary covered only 33 of 82 tracked tools, leaving the rest displaying "(version: unknown)" in `--tools-check` output. v0.3.1 expands the dictionary to 82 explicit entries (full coverage; libyal `*mount` / `*info` tools use `-V`, DOS-era / minimal tools probe with no args, etc.) and adds an "installed" sentinel fallback for any tool present on PATH but yielding no parseable version output. Result: zero tools display "(version: unknown)" on a fully-installed Kali rig.

**ISS-005: New `-v` / `-vv` / `-q` verbosity shortcuts.**

Conventional Unix-style verbosity flags. `-v` -> INFO (default), `-vv` -> DEBUG, `-q` / `--quiet` -> WARNING. `-v` and `-q` are mutually exclusive (argparse mutex group). `--log-level` overrides both with a clear warning logged.

**Verification:**

18-test verification matrix (10 issue-resolution + 4 regression + 4 dual-handler-on-extract). All passed including byte-for-byte regression on the canonical v0.1.x nested archive scenario (22 files / 3 archives / 0 failed / 0 errors / depth 4 -- identical to v0.1.1, v0.2.0, v0.3.0).

**Updated release calendar:**

- v0.3.0 -- Subsystem A (extraction depth)
- v0.3.1 (this release) -- Production-rig fixes
- v0.3.2 (planned) -- Subsystem B (verification) + Subsystem C (classification + schema bump to 1.1.0)

### 0.3.0 -- extraction-depth subsystem (Subsystem A)

Incrementally-shipped Subsystem A from the broader v0.3 plan. Subsystems B (verification) and C (classification + schema 1.1.0) are scoped for v0.3.1 and v0.3.2 respectively.

**New extractor modules (6 files, 18 new extractor classes):**

- `extractors/pdf.py` -- PdfAttachmentExtractor (`pdfdetach -saveall`), PdfStructureExtractor (`qpdf --qdf`)
- `extractors/android.py` -- ApktoolExtractor (`apktool d`); ZipExtractor extended to handle APK as priority-80 fallback when apktool is missing
- `extractors/disk_image.py` -- QemuImgExtractor (universal `qemu-img convert -O raw`, no-root path), VmdkExtractor / QcowExtractor / VhdiExtractor (libyal FUSE mounters, root-required)
- `extractors/forensic_fs.py` -- ApfsExtractor / NtfsExtractor / ExtFsExtractor / XfsExtractor / HfsplusExtractor / FatExtractor / VssExtractor / Lvm2Extractor (all libyal FUSE mounters, all root-required)
- `extractors/embedded_fs.py` -- FirmwareFsBinwalkExtractor (JFFS2 / UBI / MTD), MsCompressExtractor (KWAJ / SZDD), BplistConverter (secondary, runs alongside the original to produce sibling XML plist)
- `extractors/encrypted.py` -- documentary stub for future v0.4+ keyed extractors. v0.3.0 itself registers no encrypted-extractor; encrypted formats are terminal-classify only.

**New `requires_root` flag on `Extractor` base class:**

- The 11 libyal FUSE-mount-based extractors set `requires_root = True`.
- The orchestrator filters them at primary AND secondary dispatch sites when the current process is not root, with an INFO-level log message: "Skipping extractor X on Y -- requires root for FUSE mount; rerun with sudo to enable this extractor".
- Run does NOT abort -- the next extractor in the chain (e.g. `qemu-img` for VM disk images) gets a turn. Files for which no non-root extractor exists surface as "no available primary extractor for kind=..." in the manifest, consistent with v0.1.x behavior.

**FileKind expansion (56 -> 78):**

22 new entries: APK, BPLIST, VMDK, QCOW2, VHD, VHDX, RAW_DISK, APFS, NTFS, EXT_FS, XFS, HFSPLUS, FAT, VSS, LVM2, JFFS2, UBI, MTD, KWAJ, SZDD, LUKS_ENCRYPTED, ENCRYPTED_GENERIC. Three are explicitly TERMINAL (excluded from EXTRACTABLE_KINDS by design): LUKS_ENCRYPTED, ENCRYPTED_GENERIC, BPLIST.

**Detection refinement (v0.3.0 additions):**

- APK detection: triggers on `.apk` extension OR `file(1)` description "Android package" OR mime `application/vnd.android.package-archive`. Promoted from generic ZIP so apktool wins dispatch at priority 90.
- VMDK / QCOW2 / VHD / VHDX magic-byte detection at the start of the file.
- Filesystem images: NTFS (offset 3), ext (offset 1080), XFS (offset 0), APFS (offset 32), HFS+ (offset 1024), FAT (variable offset).
- LUKS detection (terminal-classify): `magic:LUKS` plus `terminal:encrypted` signal.
- BPLIST detection (terminal-classify): `magic:BPLIST` plus `terminal:bplist` signal.
- Embedded firmware: JFFS2 (BE / LE node magic), UBI (volume identifier).
- MS DOS-era: KWAJ, SZDD.

**Tool registry expansion (47 -> 82 tracked tools):**

New tools: apktool, qpdf, pdfdetach, qemu-img, vmdkmount, vmdkinfo, qcowmount, qcowinfo, vhdimount, vhdiinfo, smrawmount, smrawinfo, fsapfsmount, fsapfsinfo, fsntfsmount, fsntfsinfo, fsextmount, fsextinfo, fsfatmount, fsfatinfo, fshfsmount, fshfsinfo, fsxfsmount, fsxfsinfo, vshadowmount, vshadowinfo, vslvmmount, vslvminfo, luksdeinfo, mtdinfo, mscompress, mtools, mcopy, plistutil, fusermount.

**Defensive package-management improvements:**

- `AptBackend.is_package_available()` -- cheap `apt-cache show` probe for any package.
- `AptBackend.filter_available()` -- splits a package list into (available, unavailable), with a warning logged for each unavailable entry.
- `install_packages()` now filters against apt-cache BEFORE submitting to `apt-get install`, preventing a single bad TOOL_PACKAGE_HINTS entry from poisoning the entire install batch with rc=100. (Caught the v0.3.0 `libfsfat-utils` issue immediately; same root cause as v0.2.0's `rpm2archive` incident.)

**Bugs fixed during v0.3.0 verification:**

- Wrong `ExtractorNotApplicable` constructor signature (3 positional args when actual signature is 1 positional + 1 kwarg) -- fixed in pdf.py, embedded_fs.py, disk_image.py, forensic_fs.py.
- FUSE ENOSYS during `mountpoint.iterdir()` killed the run when FUSE userspace/module unavailable; now caught and surfaced as `ExtractorNotApplicable` so qemu-img gets a turn.
- `mime_type` reference where parameter is named `mime` -- caught at runtime, fixed.
- APK files were being classified as plain ZIP -- fixed by adding APK refinement to the ZIP-magic detection branch.

**Verification:**

10 verification tests, all passed including byte-for-byte regression on the canonical v0.1.x nested archive scenario (22 files / 3 archives / 0 failed / 0 errors / depth 4 -- identical to v0.1.1 and v0.2.0). Non-root-skip behavior verified by simulated non-root run: qcowmount filtered with clear log, qemu-img took over, run did not abort.

**Target environment note:**

The production target is Kali Linux. Full Kali installs ship the upstream libyal packages with the FUSE `*mount` binaries; minimal Ubuntu / Debian installs ship only the `*info` companions and will silently filter the FUSE-mount-based extractors as unavailable. `re-unpacker --tools-check` reports the gap clearly.

### 0.2.0 -- tool installer / uninstaller / repair subsystem + extended unpack toolset

**New CLI modes** (require root, exit 5 if non-root):

- `--install` (alias `--install-missing`) -- install all known unpack tools currently missing
- `--uninstall` -- remove every currently-present unpack tool from the system
- `--repair` -- reinstall every currently-present unpack tool (recovers from broken / half-installed state)
- `--dry-run-install` -- print exact apt commands the above modes would run, no execution, no root required
- `-y` / `--yes` -- skip the y/N confirmation prompt
- `--no-refresh-index` -- skip `apt-get update` before install / repair (faster on repeated runs)

**New exit codes:**

- 5 -- privilege required (install / uninstall / repair invoked without root)
- 6 -- package manager error (apt failed during install / remove / reinstall)

**Two-tier protection against bricking the system:**

- `PROTECTED_TOOLS` (apt-get, dpkg-query) -- tracked by registry for visibility, never targeted by install / uninstall / repair
- `PROTECTED_PACKAGES` (apt, dpkg) -- packages filtered at the package layer so a different tracked tool can't smuggle them through
- `Essential: yes` runtime filter -- `--uninstall` consults `dpkg-query -W -f='${Essential}'` and skips essentials (`tar`, `gzip`, `dpkg`, etc.) so the user gets a clean exit instead of apt rc=100. `--repair` does NOT skip essentials (apt allows reinstall of essentials, and a damaged tar / gzip is exactly the case repair exists to handle).

**Toolset expanded 32 → 47 tracked tools.** New tools and the formats they unlock:

- `arj` -- ARJ archives
- `lhasa` (provides `lha`) -- LHA / LZH archives
- `unar` (provides `unar`, `lsar`) -- broad-coverage Unarchiver: StuffIt SIT/SITX, ALZ, ACE, plus fallback for RAR / ZIP / NSIS / InnoSetup / LHA / ARJ
- `lzip` -- lzip single-stream (`.lz`) and `.tar.lz` pipeline
- `plzip` -- parallel lzip
- `pixz` -- parallel / indexed XZ
- `lrzip` -- high-ratio compression (`.lrz`)
- `zpaq` -- ZPAQ archives
- `nomarch` -- ARC / ARK MS-DOS archives
- `tnef` -- Microsoft TNEF (`winmail.dat`)
- `sharutils` -- shell archives (`.shar`) and uuencoded data (`.uu`, `.uue`)

**FileKind enum 42 → 56 entries**, **EXTRACTABLE_KINDS 35 → 50**, **primary kinds 38 → 51**, **registered extractors 29 → 40**, **secondary extractor count unchanged at 7**.

**New extractor modules:**

- `extractors/legacy.py` -- ArjExtractor, LhaExtractor, ArcExtractor, TnefExtractor, SharExtractor, UuencodedExtractor, UnarFallbackExtractor (broad-coverage fallback at priority 55)
- `extractors/lzip_family.py` -- LzipExtractor, TarLzipExtractor (lzip → tar pipeline), LrzipExtractor (operates on copy, like UpxExtractor), ZpaqExtractor

**Bugs fixed during v0.2.0 verification:**

- Wrong package hint for `rpm2archive` (ships in `rpm` package on Debian/Ubuntu, not its own package) -- fixed
- Wrong tool name `lunzip` (Ubuntu's lzip package provides `lzip`, not `lunzip`; decompression via `lzip -d -c`) -- fixed
- `.tar.lz` routed to LzipExtractor instead of TarLzipExtractor (missing entry in `_compound_ext` suffix list) -- fixed
- Three stale references to renamed `_ensure_root_or_exit` function -- fixed

### 0.1.1 -- post-verification fix release

- `_drain_parallel` busy-wait incorrectly marked still-running futures as "done" because `concurrent.futures.TimeoutError` inherits from `Exception`. Replaced with `wait(..., return_when=FIRST_COMPLETED)`.
- `ZipExtractor` ran `unzip` twice to handle non-fatal warnings (rc=1). Reduced to a single `check=False` call with explicit return-code interpretation.
- `pyproject.toml` added; `pip install -e .` works and registers a `re-unpacker` entry-point.
- Verified j=1 vs j=4 produces byte-identical extraction counts on a 20-archive batch.

### 0.1.0 -- initial release

- 24-module package with full dispatch chain across 29 extractor classes.
- Verified end-to-end on five test scenarios: 4-level nested archive, real `.deb`, UPX-packed ELF, path-traversal symlink defense, SHA-256 dedup.
- Mid-verification fixes: introduced `ExtractorNotApplicable` to distinguish "not the right job" from "tried and failed", made secondary extractors (PE resources, ELF sections) run independently of primary outcome, hardened `sanitize_name` against shell-special characters.
