# RE-Unpacker Setup Guide

This guide covers installing RE-Unpacker and provisioning the external
extraction tools on Linux and Windows. For day-to-day use see
[USAGE_GUIDE.md](USAGE_GUIDE.md); for problems see
[TROUBLESHOOTING_GUIDE.md](TROUBLESHOOTING_GUIDE.md).

RE-Unpacker has **no runtime Python dependencies**. It is pure standard-library
Python that drives external system binaries for the actual extraction. Setup
therefore has two parts: getting the tool itself runnable, and provisioning the
extraction binaries.

## Table of contents

1. [Requirements](#requirements)
2. [Get the tool](#get-the-tool)
3. [Linux tool provisioning](#linux-tool-provisioning)
4. [Windows tool provisioning](#windows-tool-provisioning)
5. [Verify the install](#verify-the-install)
6. [Optional Python bindings](#optional-python-bindings)
7. [YARA rules](#yara-rules)
8. [Uninstall and repair](#uninstall-and-repair)

## Requirements

- **Python 3.10 or newer** on PATH. The codebase uses PEP 604 union types and
  modern typing.
- A supported host:
  - Linux: Kali / Debian / Ubuntu (Kali is the primary target and ships the
    widest tool coverage).
  - Windows 10 1809+ or Windows 11, with the Windows Package Manager
    (`winget`), which ships as part of the App Installer component.

## Get the tool

No installer is required. Clone the repository and run the bundled wrapper.

### Linux / macOS

```bash
git clone https://github.com/Sandler73/RE-Unpacker.git
cd re-unpacker
chmod +x re-unpacker
./re-unpacker --version
```

The `re-unpacker` wrapper prepends the bundled `src/` to `PYTHONPATH` and runs
`python3 -m re_unpacker`. To put it on your PATH, symlink it into
`~/.local/bin/`, or install the package:

```bash
pip install -e . # editable install; adds a 're-unpacker' console script
re-unpacker --version
```

### Windows

Same source tree, two launchers:

```powershell
# PowerShell wrapper (preferred):
.\re-unpacker.ps1 --version

# Cmd.exe shim (for restricted-execution-policy environments):
re-unpacker.cmd --version
```

If Python is not found, install it with `winget install Python.Python.3.12`
(or any equivalent) and reopen the shell.

## Linux tool provisioning

Let RE-Unpacker tell you exactly what is missing:

```bash
re-unpacker --tools-check
```

Then either install everything it flags in one shot, or let RE-Unpacker do it:

```bash
# RE-Unpacker drives apt for you (requires root):
sudo re-unpacker --install --yes
```

The full manual package set on a fresh Kali / Debian / Ubuntu box:

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

Notes:

- On full Kali installs, the libyal `lib*-utils` packages ship the FUSE
  `*mount` binaries needed by the forensic-filesystem extractors. On Ubuntu and
  minimal Debian, only the `*info` companions ship, so the FUSE-mount extractors
  are silently filtered as unavailable. Run `--tools-check` to see the gap.
- `libfsfat-utils` is not currently packaged for Debian / Kali / Ubuntu stable.
  RE-Unpacker knows this and drops it cleanly from an install batch with an
  informative message; `mtools` provides a partial FAT fallback.
- The `apt` and `dpkg` packages are protected: `--uninstall` and `--repair`
  will never remove them.

## Windows tool provisioning

The same `--install` mode dispatches to winget instead of apt, and additionally
runs per-tool manual-install handlers for tools that have no winget package.

```powershell
# Run from an elevated (Administrator) shell:
.\re-unpacker.ps1 --install --yes
```

This provisions tools in three tiers:

1. **Built into Windows 10+** (no install): `expand.exe`, `msiexec.exe`,
   `tar.exe`, Windows PowerShell 5.1.
2. **winget-managed** (verified Package IDs): `7zip.7zip`,
   `OliverBetz.ExifTool`, `VirusTotal.YARA`, `GnuPG.GnuPG`, `QPDF.QPDF`,
   `Microsoft.Sysinternals.Sigcheck`, `Microsoft.PowerShell`. Machine-scope
   installs land in `Program Files`.
3. **Manual-install handlers** for tools with no winget package. Working
   auto-installers cover binwalk (pip), upx, ssdeep, osslsigncode, innoextract,
   ewfinfo + ewfexport, plistutil, and pdfdetach, downloading from each tool's
   canonical upstream release into `C:\Program Files\re-unpacker\bin\`.

Some tools have no pre-built Windows distribution and are honestly skipped with
guidance rather than silently failing: most of the libyal toolset beyond libewf
(upstream is source-only), plus SDK tools like `signtool` (Windows SDK) and
`apksigner` / `apktool` (Android SDK). Run `--tools-check` to see per-tool
status and manual-install hints.

Because 7-Zip on Windows covers many formats that need separate tools on Linux
(deb, rpm, cab, cpio, ar, KWAJ/SZDD, and several disk-image formats), the
Windows tool set is smaller than the Linux one while preserving output parity:
every kind extractable on Linux is extractable on Windows, with identical
manifest schema.

### A note on PATH on Windows

RE-Unpacker installs its manual-install tools to
`C:\Program Files\re-unpacker\bin\` and adds that directory to the system PATH,
but only if doing so keeps PATH under the Windows-safe length threshold. If your
system PATH is already near the legacy 2047-character limit, RE-Unpacker skips
the registry write (to avoid the modal "PATH env variable too big" dialog) and
prints a diagnostic with cleanup guidance. RE-Unpacker still finds its own
tools regardless, because it probes its install directory directly. See the
[Troubleshooting Guide](TROUBLESHOOTING_GUIDE.md) for the cleanup procedure.

## Verify the install

```bash
# Version and schema.
re-unpacker --version

# Tool inventory: present, missing, and how to install the missing ones.
re-unpacker --tools-check

# Smoke test: classify a directory without extracting.
re-unpacker --dry-run ./some-samples
```

A healthy `--tools-check` on Linux shows the full 93-tool inventory with paths
and versions; on Windows it shows the 56-tool inventory. Missing tools are not
fatal: the orchestrator filters unavailable extractors and continues, so you can
run RE-Unpacker with a partial toolset and still extract everything your
installed tools support.

## Optional Python bindings

Three classifier passes prefer a Python binding over the CLI tool when present,
because subprocess overhead dominates per-file enrichment cost:

| Binding | apt package | Used by |
|---------|-------------|---------|
| `tlsh` | `python3-tlsh` | fuzzy-hash classifier |
| `yara` | `python3-yara` | YARA match classifier |
| `ssdeep` | `python3-ssdeep` | fuzzy-hash classifier |

These are optional. When absent, the CLI tools are used instead; when both are
absent, the pass records that it was not performed.

## YARA rules

When you do not pass `--yara-rules PATH`, RE-Unpacker auto-discovers rules from
its default directories as a namespaced union. On Linux these are the system
YARA directory, the per-user RE-Unpacker config directory, and the YARA Forge
default location; on Windows the equivalents under `%PROGRAMDATA%` and
`%APPDATA%`. Drop `.yar` / `.yara` files into any of them, or point at a
specific file or directory with `--yara-rules`.

## Uninstall and repair

```bash
# Preview what uninstall/repair would run, no changes, no root.
re-unpacker --dry-run-install

# Reinstall the currently-present toolset (recover from a broken state).
sudo re-unpacker --repair

# Remove every currently-present unpack tool (protected packages are spared).
sudo re-unpacker --uninstall
```

`--repair` is the right tool after a partial package-manager failure leaves
tools half-installed. `--uninstall` removes the unpack toolset but never the
protected `apt` / `dpkg` packages.
