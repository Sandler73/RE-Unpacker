# re-unpacker Frequently Asked Questions

Conceptual and scope questions. For usage see [USAGE_GUIDE.md](USAGE_GUIDE.md);
for install see [SETUP_GUIDE.md](SETUP_GUIDE.md); for problems see
[TROUBLESHOOTING_GUIDE.md](TROUBLESHOOTING_GUIDE.md).

## General

### What is re-unpacker?

A recursive extractor for reverse-engineering triage. You hand it a file or a
directory of files, and it pulls apart every package, installer, archive,
filesystem image, compressed stream, and packed binary it recognizes,
recursively, until it reaches content it cannot unpack further. It writes a
structured tree of the extracted content plus a machine-readable manifest
describing everything it found.

### Who is it for?

Reverse engineers, malware analysts, incident responders, digital-forensics
practitioners, and anyone inspecting a software supply chain. It is built for
the triage step: get everything out of a container quickly and safely so you can
start analyzing.

### What platforms does it run on?

Linux (Kali / Debian / Ubuntu, with Kali as the primary target) and Windows
(10 1809+ or 11). The same source tree runs on both; the manifest schema is
byte-compatible across platforms.

### What is the current version?

0.4.9. The manifest schema is 1.1.0. See [CHANGELOG.md](../CHANGELOG.md) for the
full history.

## Scope and formats

### What formats can it unpack?

Linux and Windows packages (deb, rpm, msi, cab), PE installers (NSIS,
InnoSetup, InstallShield, WiX Burn), filesystem images (ISO, DMG, xar/pkg,
SquashFS, snap, AppImage), traditional archives (tar and its compressed
variants, zip and zip-based formats like jar/apk/whl/docx, 7z, rar, ar, cpio),
single-stream compression (gz, bz2, xz, zst, lzma, lz4, lzo, lzip, lrzip,
zpaq), legacy formats (arj, lha, arc, tnef, shar, uuencoded, StuffIt, ALZ,
ACE), PDFs (attachments and structure), Android APKs, VM disk images (vmdk,
qcow2, vhd, vhdx, raw), forensic filesystems (NTFS, ext, XFS, APFS, HFS+, FAT,
VSS, LVM2), embedded firmware filesystems (JFFS2, UBI, MTD), Microsoft DOS-era
compressed formats (KWAJ, SZDD), UPX-packed binaries, and PE resource / ELF
section extraction. See the README supported-formats table for the exact
tool-per-format mapping.

### What does it deliberately not do?

Two things are out of scope by design:

- **Password recovery** for password-protected archives. Encrypted content is
  detected and classified (as `LUKS_ENCRYPTED` or `ENCRYPTED_GENERIC`) but not
  cracked. Decrypt out of band and re-run.
- **OS-kernel-level mounting** such as loop-mounting ISOs with `mount -o loop`.
  The risk outweighs the value for triage. Extraction is done through userspace
  tools instead.

### Does it execute the samples it unpacks?

No, not with the analyst's privileges. Extraction runs the external extraction
tools against the sample, not the sample itself. Installer and AppImage handling
specifically avoid executing the payload with install privileges wherever
possible (for example AppImage is extracted from its SquashFS tail rather than
run). Extracted artifacts may themselves be malicious; treat them accordingly.

## Dependencies and tools

### What does it depend on?

re-unpacker has **no runtime Python dependencies**. It is pure standard-library
Python. All extraction is performed by external system binaries (dpkg-deb,
7-Zip, cabextract, binwalk, qpdf, yara, exiftool, gpg, the libyal toolset, and
others), which are installed and licensed separately.

### Do I need every tool installed?

No. Missing tools are not fatal. `--tools-check` shows what is present and what
is missing, and the orchestrator filters out extractors whose tools are absent
and continues with the rest. Install only the tools for the formats you care
about, or run `--install` to provision everything.

### Why is the Windows tool set smaller than the Linux one?

7-Zip on Windows handles many formats that need separate dedicated tools on
Linux (deb, rpm, cab, cpio, ar, KWAJ/SZDD, and several disk-image formats). So
the Windows inventory is smaller (56 tools) than the Linux one (93) while
preserving output parity: every kind extractable on Linux is extractable on
Windows, with an identical manifest.

## Safety

### Is it safe to run on malware?

re-unpacker is designed for exactly that, and implements strong defensive
controls: argv-only subprocess execution (never a shell), per-extractor
timeouts, bounded output capture, path-traversal auditing with quarantine, and
byte / file-count quotas. That said, no tool can guarantee complete safety when
handling adversarial input. Run it in an isolated analysis environment (a
disposable VM or container without access to sensitive networks or data) and
treat extracted artifacts as potentially malicious.

### What happens if an archive tries a path-traversal attack?

After every extraction, re-unpacker resolves each extracted symlink against the
output root. Escaping symlinks are replaced with a placeholder that records the
original target (so you can see what the archive attempted), and escaping
regular files are moved into a `_quarantine/` directory. The counts are surfaced
in the run statistics.

### What is a "decompression bomb" and how is it handled?

An archive crafted to expand to an enormous size or file count. re-unpacker
defends against it in two layers. On POSIX, every extraction child runs under an
`RLIMIT_FSIZE` output-size cap sized to `--max-extracted-size`, so a single-file
bomb (a tiny input that would expand to hundreds of GB) is stopped by the kernel
mid-write rather than after it fills the disk. In addition, after each extraction
step the produced byte count and file count are checked against the per-archive
and run-wide ceilings (`--max-extracted-size`, `--max-total-size`,
`--max-files`); tripping any of them raises `SafetyLimitExceeded`, exits with
code 2, and preserves the partial output. The measured-after-the-step check is
the primary guard on Windows, where `RLIMIT_FSIZE` is not available.

## Output

### What does a run produce?

A consolidated `manifest.json`, a streaming `manifest.jsonl` (line-buffered and
crash-resilient), an `extraction.log` (full DEBUG), an `errors.log` (warnings
and above), a `tree.txt` listing, a `summary.txt`, and an `extracted/` tree
where every re-unpacker-produced directory carries a `.unpacked` suffix.

### How do I query the manifest?

`manifest.jsonl` is one JSON record per line, friendly to `jq` and `grep`. Each
record has a `record_type` of `header`, `file`, `error`, or `footer`. See the
[Usage Guide](USAGE_GUIDE.md#reading-the-output) for example queries.

### Why does a run report errors but still exit 0?

Exit 0 means the run itself completed. Individual extractor failures on specific
files are recorded in the manifest `errors` list and `errors.log`, but they do
not fail the whole run. This lets you triage a large directory where a few files
fail without losing the results for everything that succeeded. The distinction
between "this extractor is not applicable" (silent, not an error) and "this
extractor tried and failed" (recorded as an error) is intentional.

## Contributing and support

### How do I add support for a new format?

Add the kind to the `FileKind` enum, add its magic signature (verified against
the format spec), and write an extractor class that registers itself. See
[CONTRIBUTING.md](../CONTRIBUTING.md) for the full pattern, including the
dispatch-chain contract and the required-tools filtering that lets
platform-specific extractors coexist.

### How do I report a bug or a security issue?

Bugs: open a GitHub issue with the bug-report template and include version,
command, logs, and a reproducer. Security vulnerabilities: do not open a public
issue; follow [SECURITY.md](../SECURITY.md) for private reporting.

### Where is the full documentation?

In `docs/` (Usage, Setup, Troubleshooting, FAQ), in the mirrored
[project wiki](https://github.com/Sandler73/RE-Unpacker/wiki), and in the
HTML companions in `docs/`. The README is the top-level overview.
