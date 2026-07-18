"""
.. module:: re_unpacker.constants
    :synopsis: Central project constants, defaults, and version information.

Description
-----------
Single source of truth for version numbers, default limits, tool package
hints, and well-known file magic byte sequences used across the re-unpacker
package. Kept dependency-free (pure Python stdlib types) so this module can
be imported anywhere in the package without causing import cycles.

Notes
-----
- Magic byte values were verified against authoritative sources (format
  specifications, upstream project source, and `file(1)` magic database
  references). See detection.py for usage.
- Default limits err on the side of "large enough for legitimate RE
  artifacts, small enough to catch pathological archives". Override via CLI.

Version
-------
Part of re-unpacker 0.4.10. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

from .platform_compat import is_windows

# -----------------------------------------------------------------------------
# Project identity
# -----------------------------------------------------------------------------
PROJECT_NAME: str = "re-unpacker"
VERSION: str = "0.4.10"
SCHEMA_VERSION: str = "1.1.0"

# -----------------------------------------------------------------------------
# Default runtime limits
# -----------------------------------------------------------------------------
DEFAULT_MAX_DEPTH: int = 10
DEFAULT_JOBS: int = 1  # sequential by default (user opt-in to parallel via -j)
DEFAULT_MAX_EXTRACTED_SIZE: int = 50 * 1024 * 1024 * 1024  # 50 GiB per archive
DEFAULT_MAX_TOTAL_SIZE: int = 500 * 1024 * 1024 * 1024  # 500 GiB run-wide
DEFAULT_MAX_FILES_PER_ARCHIVE: int = 1_000_000
DEFAULT_TIMEOUT_SECONDS: int = 1800  # 30 minutes
DEFAULT_READ_CHUNK_SIZE: int = 1024 * 1024  # 1 MiB for hashing/streaming reads

# -----------------------------------------------------------------------------
# Output layout constants
# -----------------------------------------------------------------------------
MANIFEST_FILENAME: str = "manifest.json"
MANIFEST_JSONL_FILENAME: str = "manifest.jsonl"
TREE_FILENAME: str = "tree.txt"
SUMMARY_FILENAME: str = "summary.txt"
EXTRACTION_LOG_FILENAME: str = "extraction.log"
ERRORS_LOG_FILENAME: str = "errors.log"
EXTRACTED_DIRNAME: str = "extracted"
QUARANTINE_DIRNAME: str = "_quarantine"
UNPACKED_SUFFIX: str = ".unpacked"

# -----------------------------------------------------------------------------
# Tool -> Linux package name map (used in --tools-check install hints on Linux)
# Verified against Debian/Kali package repositories.
# -----------------------------------------------------------------------------
TOOL_PACKAGE_HINTS_LINUX: dict[str, str] = {
    "file": "file",
    "7z": "p7zip-full",
    "unzip": "unzip",
    "tar": "tar",
    "gzip": "gzip",
    "gunzip": "gzip",
    "bzip2": "bzip2",
    "bunzip2": "bzip2",
    "xz": "xz-utils",
    "unxz": "xz-utils",
    "zstd": "zstd",
    "lz4": "lz4",
    "lzop": "lzop",
    "unlzma": "xz-utils",
    "dpkg-deb": "dpkg",
    "ar": "binutils",
    "rpm2cpio": "rpm2cpio",
    "rpm2archive": "rpm",        # rpm2archive ships as part of the rpm package on Debian/Ubuntu, not its own package
    "cpio": "cpio",
    "msiextract": "msitools",
    "cabextract": "cabextract",
    "innoextract": "innoextract",
    "unshield": "unshield",
    "unsquashfs": "squashfs-tools",
    "bsdtar": "libarchive-tools",
    "binwalk": "binwalk",
    "upx": "upx-ucl",
    "unrar": "unrar",
    "wrestool": "icoutils",
    "icotool": "icoutils",
    "objcopy": "binutils",
    "readelf": "binutils",
    # ---- Extended unpack toolset ----
    "arj": "arj",                     # ARJ archives (.arj)
    "lha": "lhasa",                   # LHA / LZH archives (lhasa provides the lha binary)
    "unar": "unar",                   # The Unarchiver: very wide format coverage (StuffIt, ALZ, ACE, RAR4/5, NSIS variants, ...)
    "lsar": "unar",                   # The Unarchiver listing helper, ships with unar
    "lrzip": "lrzip",                 # high-ratio compression (.lrz)
    "lzip": "lzip",                   # lzip (.lz). On Debian/Ubuntu the lzip package
                                      # provides /usr/bin/lzip; we use 'lzip -d -c'
                                      # for decompression.
    "plzip": "plzip",                 # parallel lzip
    "pixz": "pixz",                   # parallel/indexed XZ
    "nomarch": "nomarch",             # ARC / ARK MS-DOS archives
    "tnef": "tnef",                   # Microsoft TNEF (winmail.dat)
    "unshar": "sharutils",            # shell archives (.shar)
    "uudecode": "sharutils",          # uuencoded data
    "zpaq": "zpaq",                   # ZPAQ format
    # Package-manager helpers (used by --install/--uninstall/--repair).
    # These are nearly always present on Debian/Kali; we still probe them so
    # `--tools-check` flags an environment that's missing them outright.
    "apt-get": "apt",
    "dpkg-query": "dpkg",
    # ---- additions: extraction-depth subsystem (Subsystem A) ----
    # PDF
    "qpdf": "qpdf",                   # PDF reorganization (--qdf produces extractable form)
    "pdfdetach": "poppler-utils",     # Extract attached files / embedded files from PDFs
    # Android
    "apktool": "apktool",             # APK resource decoding (binary XML, smali). Kali-specific.
    # macOS / Apple
    "plistutil": "libplist-utils",    # Binary plist -> XML
    # Disk-image conversion (universal bridge)
    "qemu-img": "qemu-utils",         # Convert any VM disk image to raw
    # FUSE userspace (required by all libyal *mount tools).
    # Note: on minimal Ubuntu/Kali builds 'fusermount' may not be present
    # even though the kernel module is loaded. fuse3 provides fusermount3,
    # fuse2 provides fusermount.
    "fusermount": "fuse",
    # libyal: VM disk image readers
    "vmdkmount": "libvmdk-utils",     # VMware VMDK (FUSE)
    "vmdkinfo": "libvmdk-utils",      # VMDK metadata
    "qcowmount": "libqcow-utils",     # QCOW/QCOW2 (FUSE)
    "qcowinfo": "libqcow-utils",
    "vhdimount": "libvhdi-utils",     # Microsoft VHD/VHDX (FUSE)
    "vhdiinfo": "libvhdi-utils",
    "smrawmount": "libsmraw-utils",   # Split raw images (FUSE)
    # NOTE: libsmraw-utils does NOT ship 'smrawinfo'. The package provides
    # smrawmount and smrawverify only. We track smrawverify (useful for
    # integrity checks on raw image splits) and drop the smrawinfo hint
    # that had wrong.
    "smrawverify": "libsmraw-utils",
    # libyal: filesystem readers (all FUSE-based; require root)
    "fsapfsmount": "libfsapfs-utils", # macOS APFS (FUSE)
    "fsapfsinfo": "libfsapfs-utils",
    "fsntfsmount": "libfsntfs-utils", # Windows NTFS (FUSE)
    "fsntfsinfo": "libfsntfs-utils",
    "fsextmount": "libfsext-utils",   # Linux ext{2,3,4} (FUSE)
    "fsextinfo": "libfsext-utils",
    # libfsfat-utils is NOT currently packaged for Debian / Kali stable as of
    # this release. The hint is kept here as documentation: --tools-check will
    # report fsfatmount/fsfatinfo as MISSING (because the binaries aren't on
    # PATH), but the apt-cache filter in --install will drop the package
    # cleanly with an informative log message rather than failing the whole
    # install batch. mtools (also tracked) provides partial-coverage FAT
    # disk-image inspection as a fallback.
    "fsfatmount": "libfsfat-utils",
    "fsfatinfo": "libfsfat-utils",
    "fshfsmount": "libfshfs-utils",   # macOS HFS+ (FUSE)
    "fshfsinfo": "libfshfs-utils",
    "fsxfsmount": "libfsxfs-utils",   # Linux XFS (FUSE)
    "fsxfsinfo": "libfsxfs-utils",
    "vshadowmount": "libvshadow-utils",  # Windows VSS (FUSE)
    "vshadowinfo": "libvshadow-utils",
    "vslvmmount": "libvslvm-utils",   # Linux LVM2 (FUSE)
    "vslvminfo": "libvslvm-utils",
    # libyal: encryption detection (terminal-classify only)
    "luksdeinfo": "libluksde-utils",  # LUKS detection
    # Embedded firmware filesystems
    "mtdinfo": "mtd-utils",           # MTD / NAND flash images
    # Microsoft compressed file formats (KWAJ/SZDD, DOS-era)
    "mscompress": "mscompress",
    # Auxiliary unpack tools (broaden coverage on already-supported kinds)
    "mtools": "mtools",               # FAT disk-image alternative (mcopy)
    "mcopy": "mtools",
    # =========================================================================
    # Subsystem B (verification) tools
    # =========================================================================
    # Per-file signature/integrity verification. All verifiers run as
    # always-on best-effort after extraction succeeds. Verifiers that don't
    # apply to a kind silently record performed=false; verifiers that ran
    # and found no signature record signed=false.
    "gpg": "gnupg",                   # Detached signatures (.sig / .asc)
    "gpgv": "gpgv",                   # Lightweight detached-signature verification
    "debsigs": "debsigs",             # Embedded signatures in .deb files
    "dpkg-sig": "dpkg-sig",           # Alternative deb signature scheme
    "debsums": "debsums",             # md5sum-based deb integrity check
    "apksigner": "apksigner",         # APK v1/v2/v3 signature verification
    "osslsigncode": "osslsigncode",   # PE/MSI/CAT Authenticode signatures
    # rpm itself (already tracked above as part of v0.1.x) provides "rpm -K"
    # for RPM signature/integrity verification; no new entry needed here.
    # =========================================================================
    # Subsystem C (classification) tools
    # =========================================================================
    # Per-file enrichment passes. Each can be disabled via --no-* flags. All
    # honor --enrich-timeout and the 256MB ENRICHMENT_SIZE_CAP_BYTES.
    "exiftool": "libimage-exiftool-perl",  # Format-aware metadata extraction
    "ssdeep": "ssdeep",                    # Context-Triggered Piecewise Hashing
    "yara": "yara",                        # YARA rule matching engine (CLI)
    "ent": "ent",                          # Shannon entropy + chi-square + serial correlation
    # python3-tlsh and python3-yara are Python bindings tracked separately
    # below in PYTHON_BINDINGS for runtime detection (not available via apt
    # --install path; required as Python module imports). Python bindings
    # are preferred over CLI tools for performance: subprocess overhead
    # dominates per-file enrichment cost in CLI-tool mode.
}

# -----------------------------------------------------------------------------
# Tool -> Windows winget Package Identifier map
# -----------------------------------------------------------------------------
# Each entry maps a tool's binary name (case-insensitive on Windows; canonical
# form here is lowercase, no .exe suffix) to a winget Package Identifier
# verified against the microsoft/winget-pkgs manifest repository.
#
# Three value conventions:
# - Non-empty winget Package ID: tool is winget-installable; --install
# calls `winget install --id <value> --silent --accept-source-agreements
# --accept-package-agreements`.
# - Empty string "": tool is either built-in to Windows (e.g. expand.exe,
# msiexec.exe, tar.exe on Windows 10+) OR has no winget package and
# requires manual install (e.g. libyal binaries from joachimmetz GitHub
# releases). Manual-install tools are documented in
# KNOWN_UNAVAILABLE_PACKAGES_WINDOWS below.
#
# Tools that are Linux-specific (debsigs, debsums, dpkg-sig, mtdinfo,
# fusermount, losetup, cryptsetup, the libyal *mount FUSE binaries, etc.)
# are deliberately ABSENT from this dict. Their Windows counterparts use
# different mechanisms: 7-Zip handles deb/rpm/cab/cpio/ar extraction;
# libyal *info + *export tools handle disk-image/forensic-FS extraction
# without requiring FUSE.
#
# Verified winget Package Identifiers (as of 2026-05-07):
# - 7zip.7zip (7-Zip; handles 35+ archive formats)
# - OliverBetz.ExifTool (Phil Harvey's ExifTool for Windows)
# - VirusTotal.YARA (YARA pattern-matching engine)
# - GnuPG.GnuPG (GnuPG; provides gpg + gpgv)
# - QPDF.QPDF (PDF transformation toolkit)
# - Microsoft.Sysinternals.Sigcheck (Sysinternals sigcheck.exe; Authenticode + VirusTotal lookup)
# - Microsoft.PowerShell (PowerShell 7+; cross-platform)
TOOL_PACKAGE_HINTS_WINDOWS: dict[str, str] = {
    # -------- Built-in to Windows 10+ (no install needed) --------
    "tar":          "",                      # bsdtar.exe; in System32 since Win10 1803
    "expand":       "",                      # cab/KWAJ/SZDD extractor; since DOS era
    "msiexec":      "",                      # MSI engine; always present
    "powershell":   "",                      # Windows PowerShell 5.1; always present on Win10+
    # -------- winget-installable (verified Package IDs) --------
    "7z":           "7zip.7zip",             # archive-extraction backbone on Windows
    "7zz":          "7zip.7zip",             # alternative entry-point name
    "exiftool":     "OliverBetz.ExifTool",   # Subsystem C: format-aware metadata
    "yara":         "VirusTotal.YARA",       # Subsystem C: rule matching
    "yarac":        "VirusTotal.YARA",       # YARA rule compiler (ships with yara)
    "gpg":          "GnuPG.GnuPG",           # detached signature verification
    "gpgv":         "GnuPG.GnuPG",           # lightweight GPG verifier
    "qpdf":         "QPDF.QPDF",             # PDF transformation (Subsystem A)
    "sigcheck":     "Microsoft.Sysinternals.Sigcheck",  # Authenticode (alternative path)
    "pwsh":         "Microsoft.PowerShell",  # PowerShell 7 (cross-platform)
    # -------- Manual install required (no winget package) --------
    # See KNOWN_UNAVAILABLE_PACKAGES_WINDOWS for guidance text.
    "binwalk":      "",                      # pip install binwalk
    "upx":          "",                      # GitHub releases (upx/upx)
    "ssdeep":       "",                      # GitHub releases (ssdeep-project/ssdeep)
    "ent":          "",                      # GitHub or fourmilab.ch; pure-Python fallback in entropy.py
    "apksigner":    "",                      # Android SDK Build-Tools (manual)
    "osslsigncode": "",                      # GitHub releases (mtrojnar/osslsigncode); MSYS2 alternative
    "signtool":     "",                      # Windows SDK; bundled with Visual Studio Build Tools
    "file":         "",                      # via Git for Windows (libmagic) OR python-magic-bin pip
    "innoextract":  "",                      # GitHub releases (dscharrer/innoextract)
    "qemu-img":     "",                      # via QEMU Windows binaries (qemu.org)
    "apktool":      "",                      # GitHub releases (iBotPeaches/Apktool)
    "plistutil":    "",                      # part of libplist; manual or pip plistlib alternative
    "pdfdetach":    "",                      # poppler-utils via XpdfReader or manual
    # -------- libyal Windows binary distributions --------
    # All from GitHub releases (one ZIP per library; user extracts and adds
    # to PATH or copies binaries into a common bin dir). No winget packages.
    # On Windows we use the offline `*info` + `*export` workflow rather than
    # the FUSE-mount workflow used on Linux; the *mount tools are NOT tracked
    # for Windows since they require kernel FUSE which only WinFsp provides
    # (and the offline export path is preferred).
    "ewfinfo":      "",                      # libewf
    "ewfexport":    "",                      # libewf
    "vmdkinfo":     "",                      # libvmdk
    "vmdkexport":   "",                      # libvmdk (NOTE: may require manual build; mountable image alternative)
    "vhdiinfo":     "",                      # libvhdi
    "vhdiexport":   "",                      # libvhdi
    "qcowinfo":     "",                      # libqcow
    "qcowexport":   "",                      # libqcow
    "vshadowinfo":  "",                      # libvshadow
    "vshadowexport":"",                      # libvshadow
    "vslvminfo":    "",                      # libvslvm
    "vslvmexport":  "",                      # libvslvm
    "fsapfsinfo":   "",                      # libfsapfs (macOS APFS)
    "fsapfsexport": "",                      # libfsapfs
    "fsextinfo":    "",                      # libfsext (Linux ext{2,3,4})
    "fsextexport":  "",                      # libfsext
    "fshfsinfo":    "",                      # libfshfs (macOS HFS+)
    "fshfsexport":  "",                      # libfshfs
    "fsxfsinfo":    "",                      # libfsxfs (Linux XFS)
    "fsxfsexport":  "",                      # libfsxfs
    "fsfatinfo":    "",                      # libfsfat (FAT)
    "fsfatexport":  "",                      # libfsfat
    "fsntfsinfo":   "",                      # libfsntfs (Windows NTFS)
    "fsntfsexport": "",                      # libfsntfs
    "luksdeinfo":   "",                      # libluksde (encryption detection)
    "smrawinfo":    "",                      # libsmraw (split raw images)
    "smrawverify":  "",                      # libsmraw (integrity check)
    "phdiinfo":     "",                      # libphdi (Parallels PHDI)
    "phdiexport":   "",                      # libphdi
}

# -----------------------------------------------------------------------------
# Platform-resolved alias
# -----------------------------------------------------------------------------
# At module-load time this resolves to the platform-appropriate dict.
# Existing call sites that import TOOL_PACKAGE_HINTS continue to work
# unchanged; they get the right inventory automatically. Platform doesn't
# change during a process lifetime, so caching the result here is safe.
TOOL_PACKAGE_HINTS: dict[str, str] = (
    TOOL_PACKAGE_HINTS_WINDOWS if is_windows() else TOOL_PACKAGE_HINTS_LINUX
)

# Tools that are infrastructure-level: they are tracked by the registry so
# --tools-check can flag their absence, but --install/--uninstall/--repair
# will never act on them. Removing apt or dpkg would brick the system; the
# safety has to live in the policy layer because the registry itself is just
# a probe table.
PROTECTED_TOOLS: frozenset[str] = frozenset({
    "apt-get",
    "dpkg-query",
})

# Packages that --uninstall and --repair must never touch even if a different
# unpack tool happens to be provided by the same package. Removing 'dpkg'
# would orphan apt; removing 'apt' would orphan the entire package manager.
# Listed independently of PROTECTED_TOOLS so the package-level protection
# is robust against a single package providing multiple tracked tools.
PROTECTED_PACKAGES: frozenset[str] = frozenset({
    "apt",
    "dpkg",
})

# -----------------------------------------------------------------------------
# Subsystem C (classification) constants
# -----------------------------------------------------------------------------

# Hard size cap for per-file enrichment passes (entropy / fuzzy-hash / exiftool
# / yara). Files larger than this skip ALL enrichment passes with
# enrichment_skipped="size_exceeds_cap" recorded in the FileEntry. Verifiers
# are NOT subject to this cap -- signature verification on multi-GB ISOs and
# disk images is exactly the use case we want to support, and the underlying
# tools handle large files efficiently.
ENRICHMENT_SIZE_CAP_BYTES: int = 256 * 1024 * 1024  # 256 MiB

# Default per-pass per-file timeout for enrichment + verification. Exposed
# via --enrich-timeout SEC. A timeout records error="timeout" in the
# corresponding result entry and the pass moves on.
ENRICH_TIMEOUT_DEFAULT_SECONDS: int = 30

# Python bindings tracked separately from apt-installable CLI tools. Each
# entry is (importable_module_name, apt_package_for_install_hint). Detection
# runs at registry-build time via importlib.util.find_spec(). When a binding
# is present, the corresponding classifier prefers it over the CLI tool for
# performance (subprocess overhead dominates per-file enrichment cost).
PYTHON_BINDINGS: dict[str, str] = {
    "tlsh": "python3-tlsh",     # TLSH (Trend Locality Sensitive Hash) Python binding
    "yara": "python3-yara",     # YARA Python binding (libyara wrapper)
    "ssdeep": "python3-ssdeep", # CTPH Python binding (optional; CLI tool is mandatory)
}

# YARA rule auto-discovery default directories. When --yara-rules PATH is NOT
# given, all three are scanned (UNION semantics per locked-in design decision)
# and rules are loaded with namespacing so cross-directory rule-name collisions
# resolve cleanly. The order here matters only for log output: rules from
# earlier dirs are loaded first.
#
# now resolved via platform_compat.default_yara_rule_dirs() so the
# Windows variant uses %PROGRAMDATA%\\yara, %APPDATA%\\re-unpacker\\yara, and
# %PROGRAMDATA%\\yara-forge\\packages\\full at runtime.
from .platform_compat import default_yara_rule_dirs as _default_yara_rule_dirs
YARA_DEFAULT_RULE_DIRS: list[tuple[str, str]] = _default_yara_rule_dirs()


# -----------------------------------------------------------------------------
# Maps package name -> human-readable explanation. When the apt-cache
# availability filter in pkg_manager.py drops one of these from an install
# batch, it logs an informative INFO-level message including the explanation
# (rather than just a generic warning). This makes it clear to the user that
# the missing package is a known constraint, not a misconfiguration.
#
# Entries should be REMOVED from this dict as upstream packaging fixes the
# coverage gap on Debian/Kali/Ubuntu.
KNOWN_UNAVAILABLE_PACKAGES_LINUX: dict[str, str] = {
    "libfsfat-utils": (
        "libfsfat-utils is not currently packaged for Debian / Kali / Ubuntu "
        "stable. The fsfatmount and fsfatinfo extractors will be filtered as "
        "unavailable. mtools (already tracked) provides partial-coverage FAT "
        "disk-image inspection as a fallback. Track libyal upstream packaging "
        "status at https://github.com/libyal/libfsfat for resolution."
    ),
}

# -----------------------------------------------------------------------------
# Manual-install instructions for Windows tools
# -----------------------------------------------------------------------------
# Tools that have no winget Package Identifier and require manual install
# from external sources. Format mirrors KNOWN_UNAVAILABLE_PACKAGES_LINUX
# but the values are install instructions rather than gap explanations.
#
# When --install runs on Windows and encounters a missing tool whose hint
# is empty AND it appears in this dict, the user is shown the install
# instruction instead of a generic "no package" error.
#
# Format: human-readable instruction string. May reference specific URLs,
# pip package names, or installer suite names. Multi-line strings allowed.
KNOWN_UNAVAILABLE_PACKAGES_WINDOWS: dict[str, str] = {
    "binwalk": (
        "binwalk has no winget package. Install via pip: "
        "`python -m pip install binwalk`. binwalk's Python module is "
        "self-contained but provides the binwalk CLI as a console script."
    ),
    "upx": (
        "upx has no winget package. Download the Windows binary from "
        "https://github.com/upx/upx/releases (upx-N.NN.N-win64.zip) and "
        "place upx.exe somewhere on PATH."
    ),
    "ssdeep": (
        "ssdeep has no winget package. Download from "
        "https://github.com/ssdeep-project/ssdeep/releases (ssdeep-N.NN-win32-binary.zip) "
        "and place ssdeep.exe on PATH. Alternatively, the python-ssdeep "
        "binding (pip install ssdeep) provides equivalent functionality "
        "from the FuzzyHashClassifier."
    ),
    "ent": (
        "ent has no Windows distribution. The EntropyClassifier already "
        "ships a pure-Python fallback that produces equivalent results "
        "(Shannon entropy of file contents); no install is necessary "
        "unless you specifically want the CLI tool."
    ),
    "apksigner": (
        "apksigner ships with the Android SDK Build-Tools. Install via "
        "the Android SDK Manager (cmdline-tools), then add "
        "$ANDROID_HOME\\build-tools\\<version>\\ to PATH. The Android Studio "
        "winget package (Google.AndroidStudio) bundles the SDK but is heavy; "
        "the standalone Command-line Tools download is lighter."
    ),
    "osslsigncode": (
        "osslsigncode has no winget package. Download Windows binaries "
        "from https://github.com/mtrojnar/osslsigncode/releases or install "
        "via MSYS2 (`pacman -S mingw-w64-x86_64-osslsigncode`). The "
        "PowerShellAuthenticodeVerifier and SigntoolVerifier are "
        "Windows-native alternatives that don't require "
        "osslsigncode."
    ),
    "signtool": (
        "signtool ships with the Windows SDK. Install Visual Studio Build "
        "Tools (winget install Microsoft.VisualStudio.2022.BuildTools) and "
        "select the 'Windows 10/11 SDK' workload, OR install the Windows "
        "SDK standalone from "
        "https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/. "
        "signtool.exe is at "
        "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\<sdk-version>\\<arch>\\signtool.exe."
    ),
    "file": (
        "file (libmagic) has no winget package. Two paths: "
        "(1) Install Git for Windows (winget install Git.Git) which "
        "includes file.exe under usr\\bin; "
        "(2) pip install python-magic-bin (bundles libmagic.dll for Windows; "
        "re-unpacker uses python-magic as fallback when file.exe is absent)."
    ),
    "innoextract": (
        "innoextract has no winget package. Download from "
        "https://github.com/dscharrer/innoextract/releases (innoextract-N.N.N-windows.zip) "
        "and place innoextract.exe on PATH. 7-Zip handles many InnoSetup "
        "installers as a fallback."
    ),
    "qemu-img": (
        "qemu-img is not in winget. Install QEMU for Windows from "
        "https://www.qemu.org/download/#windows; qemu-img.exe will be in "
        "C:\\Program Files\\qemu\\."
    ),
    "apktool": (
        "apktool has no winget package. Download apktool_N.N.N.jar from "
        "https://github.com/iBotPeaches/Apktool/releases and the launcher "
        "wrapper script (apktool.bat) from https://ibotpeaches.github.io/Apktool/install/. "
        "Place both on PATH; apktool.bat invokes the JAR via java."
    ),
    "plistutil": (
        "plistutil has no winget package. The libplist binary distribution "
        "exists for Windows; alternatively, Python's built-in plistlib "
        "module handles binary and XML plists natively."
    ),
    "pdfdetach": (
        "pdfdetach (poppler-utils) has no standalone winget package. "
        "Download the Xpdf command-line tools "
        "(https://www.xpdfreader.com/download.html) which include pdfdetach, "
        "or install MSYS2 and `pacman -S mingw-w64-x86_64-poppler`."
    ),
    # libyal binaries (one bullet covers all 16 entries below):
    "libyal_binaries": (
        "libyal toolset Windows binaries (vmdkinfo, vhdiinfo, qcowinfo, "
        "vshadowinfo, vslvminfo, fsapfsinfo, fsextinfo, fshfsinfo, "
        "fsxfsinfo, fsfatinfo, fsntfsinfo, luksdeinfo, smrawinfo, ewfinfo, "
        "phdiinfo, and matching *export tools) are not in winget. "
        "Download per-library Windows ZIPs from the libyal toolset releases: "
        "https://github.com/libyal/<library-name>/releases. Each ZIP contains "
        "a single set of *info.exe and *export.exe binaries. Extract to a "
        "common bin directory and add to PATH. On Windows we use the "
        "offline export workflow (*info + *export); the Linux *mount tools "
        "require FUSE which is not available without WinFsp, and the "
        "offline path produces identical FileEntry output."
    ),
}

# Platform-resolved alias for KNOWN_UNAVAILABLE_PACKAGES.
# Matches the same pattern as TOOL_PACKAGE_HINTS above.
KNOWN_UNAVAILABLE_PACKAGES: dict[str, str] = (
    KNOWN_UNAVAILABLE_PACKAGES_WINDOWS if is_windows()
    else KNOWN_UNAVAILABLE_PACKAGES_LINUX
)

# -----------------------------------------------------------------------------
# File magic byte signatures
# Each entry: (magic_bytes, offset_from_start)
# Multiple entries per format supported where appropriate (e.g. RAR v4 vs v5).
# -----------------------------------------------------------------------------
MAGIC_SIGNATURES: dict[str, list[tuple[bytes, int]]] = {
    # Compression (single-file)
    "GZIP":       [(b"\x1f\x8b", 0)],
    "BZIP2":      [(b"BZh", 0)],
    "XZ":         [(b"\xfd7zXZ\x00", 0)],
    "ZSTD":       [(b"\x28\xb5\x2f\xfd", 0)],
    "LZ4":        [(b"\x04\x22\x4d\x18", 0)],
    "LZOP":       [(b"\x89LZO\x00\r\n\x1a\n", 0)],
    "LZMA":       [(b"\x5d\x00\x00", 0)],  # heuristic; LZMA alone has no fixed magic
    # Archives
    "ZIP":        [(b"PK\x03\x04", 0), (b"PK\x05\x06", 0), (b"PK\x07\x08", 0)],
    "SEVENZ":     [(b"7z\xbc\xaf\x27\x1c", 0)],
    "RAR4":       [(b"Rar!\x1a\x07\x00", 0)],
    "RAR5":       [(b"Rar!\x1a\x07\x01\x00", 0)],
    "TAR":        [(b"ustar\x00", 257), (b"ustar  \x00", 257)],
    "AR":         [(b"!<arch>\n", 0)],
    "CPIO_NEWC":  [(b"070701", 0)],
    "CPIO_CRC":   [(b"070702", 0)],
    "CPIO_ODC":   [(b"070707", 0)],
    "XAR":        [(b"xar!", 0)],
    # Package formats
    "RPM":        [(b"\xed\xab\xee\xdb", 0)],
    "DEB":        [(b"!<arch>\ndebian-binary", 0)],  # ar with debian-binary member first
    "OLE2":       [(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0)],  # MSI, DOC, XLS, etc.
    # Filesystem / image containers
    "ISO9660":    [(b"CD001", 32769), (b"CD001", 34817), (b"CD001", 36865)],
    "SQUASHFS":   [(b"hsqs", 0), (b"sqsh", 0), (b"shsq", 0), (b"qshs", 0)],
    "CAB":        [(b"MSCF", 0)],
    "DMG_KOLY":   [(b"koly", -512)],  # UDIF trailer at EOF - 512
    # Executables
    "ELF":        [(b"\x7fELF", 0)],
    "MACHO_LE32": [(b"\xce\xfa\xed\xfe", 0)],
    "MACHO_LE64": [(b"\xcf\xfa\xed\xfe", 0)],
    "MACHO_BE32": [(b"\xfe\xed\xfa\xce", 0)],
    "MACHO_BE64": [(b"\xfe\xed\xfa\xcf", 0)],
    "MACHO_UNIV": [(b"\xca\xfe\xba\xbe", 0), (b"\xbe\xba\xfe\xca", 0)],
    "PE":         [(b"MZ", 0)],
    # Documents / misc
    "PDF":        [(b"%PDF-", 0)],
    "DEX":        [(b"dex\n", 0)],
    # Java / Android
    "CLASS":      [(b"\xca\xfe\xba\xbe", 0)],  # JVM .class (note: collides with macho univ)
    # ---- Extended unpack format magic ----
    # ARJ archives: 0x60 0xEA at offset 0 (header magic per ARJ spec).
    "ARJ":        [(b"\x60\xea", 0)],
    # LHA / LZH: signature is at offset 2 ("-lh" or "-lz" then a digit, 'd', or '-' then "-").
    # Common method-IDs: -lh0-, -lh5-, -lh6-, -lh7-, -lhd-, -lz4-, -lz5-, -lzs-.
    # We register the most common eight; libmagic's description fills in the rest.
    "LHA":        [(b"-lh0-", 2), (b"-lh1-", 2), (b"-lh4-", 2),
                   (b"-lh5-", 2), (b"-lh6-", 2), (b"-lh7-", 2),
                   (b"-lhd-", 2), (b"-lzs-", 2)],
    # lzip (.lz) -- distinct from LZMA. Magic: "LZIP" at offset 0.
    "LZIP":       [(b"LZIP", 0)],
    # lrzip -- "LRZI" at offset 0.
    "LRZIP":      [(b"LRZI", 0)],
    # ZPAQ -- block magic per format spec: 0x37 0x6b 0x53 0x74 0xa0 0x31 0x83 0xd3 0x8c 0xb2 0x28 0xb0 0xd3 (13 bytes).
    "ZPAQ":       [(b"7kSt\xa0\x31\x83\xd3\x8c\xb2\x28\xb0\xd3", 0)],
    # ARC (System Enhancement Associates / DOS): signature is 0x1a then a method byte (0x00 - 0x09 or 0x80+).
    # We accept the leading 0x1a as the trigger; libmagic confirms in layer 2.
    "ARC":        [(b"\x1a\x08", 0), (b"\x1a\x09", 0), (b"\x1a\x02", 0)],
    # TNEF (winmail.dat): "TNEF" not literal -- the magic is a 4-byte LE int 0x223e9f78.
    "TNEF":       [(b"\x78\x9f\x3e\x22", 0)],
    # shell archive (shar): heuristic only -- starts with "#!/bin/sh" plus "# This is a shell archive".
    # We do NOT register a binary magic for shar; layer 2 (file(1)) is the right detector.

    # ---- additions: extraction-depth subsystem ----
    # VM disk images
    # VMDK: "KDMV" at offset 0 (sparse extent header) or text COW header.
    "VMDK":       [(b"KDMV", 0), (b"# Disk DescriptorFile", 0)],
    # QCOW2 / QCOW: "QFI\xfb" at offset 0.
    "QCOW2":      [(b"QFI\xfb", 0)],
    # VHD (legacy): "conectix" footer (last 512 bytes); we still register a head-style match
    # for the dynamic-disk header which appears at offset 0 in some variants.
    "VHD":        [(b"conectix", 0)],
    # VHDX: "vhdxfile" file-type identifier at offset 0.
    "VHDX":       [(b"vhdxfile", 0)],
    # Filesystem images (in-the-blob detection)
    # NTFS boot sector: "NTFS " at offset 3.
    "NTFS":       [(b"NTFS    ", 3)],
    # ext2/3/4 superblock magic 0xEF53 at offset 1080 (0x438) of the partition.
    # We detect via the magic at that offset.
    "EXT_FS":     [(b"\x53\xef", 1080)],
    # XFS superblock magic "XFSB" at offset 0.
    "XFS":        [(b"XFSB", 0)],
    # APFS container superblock: NXSB magic at offset 0x20 of block 0 (most cases).
    "APFS":       [(b"NXSB", 32)],
    # HFS+ wrapper / volume header: "H+" at offset 0x400 of block 0 (1024 bytes).
    "HFSPLUS":    [(b"H+\x00\x04", 1024), (b"HX\x00\x05", 1024)],
    # FAT boot sector: "FAT12 ", "FAT16 ", "FAT32 " in OEM area at offset 0x36 (FAT12/16) or 0x52 (FAT32).
    # These are not 100% reliable (modern formatters may omit), so detection mostly defers to libmagic.
    "FAT":        [(b"FAT12   ", 54), (b"FAT16   ", 54), (b"FAT32   ", 82)],
    # LUKS: "LUKS\xba\xbe" at offset 0 (LUKS1) or "LUKS\xba\xbe" + version 2 (LUKS2 same magic, different version field at offset 6).
    "LUKS":       [(b"LUKS\xba\xbe", 0)],
    # JFFS2: 0x1985 0x2003 (BE) or 0x8519 0x0320 (LE) at start of node.
    "JFFS2":      [(b"\x19\x85", 0), (b"\x85\x19", 0)],
    # UBI: "UBI#" at offset 0 (volume identifier header).
    "UBI":        [(b"UBI#", 0)],
    # Apple binary plist: "bplist00" at offset 0.
    "BPLIST":     [(b"bplist00", 0), (b"bplist01", 0)],
    # MS KWAJ: "KWAJ" at offset 0.
    "KWAJ":       [(b"KWAJ", 0)],
    # MS SZDD: "SZDD\x88\xf0\x27\x33" at offset 0.
    "SZDD":       [(b"SZDD\x88\xf0\x27\x33", 0)],
}

# -----------------------------------------------------------------------------
# Extensions that imply known kinds (used as a tertiary tiebreaker only)
# -----------------------------------------------------------------------------
EXTENSION_HINTS: dict[str, str] = {
    ".deb": "DEB",
    ".udeb": "DEB",
    ".rpm": "RPM",
    ".msi": "MSI",
    ".msp": "MSI",
    ".cab": "CAB",
    ".exe": "PE_EXECUTABLE",
    ".dll": "PE_EXECUTABLE",
    ".sys": "PE_EXECUTABLE",
    ".iso": "ISO",
    # ".img" is defined once, below, with its refined RAW_DISK value.
    ".dmg": "DMG",
    ".appimage": "APPIMAGE",
    ".snap": "SNAP",
    ".squashfs": "SQUASHFS",
    ".sfs": "SQUASHFS",
    ".cpio": "CPIO",
    ".a": "AR",
    ".ar": "AR",
    ".zip": "ZIP",
    ".jar": "ZIP",
    ".war": "ZIP",
    ".ear": "ZIP",
    # ".apk" is defined once, below, with its refined APK value.
    ".ipa": "ZIP",
    ".xpi": "ZIP",
    ".crx": "ZIP",
    ".nupkg": "ZIP",
    ".whl": "ZIP",
    ".egg": "ZIP",
    ".docx": "ZIP",
    ".xlsx": "ZIP",
    ".pptx": "ZIP",
    ".odt": "ZIP",
    ".ods": "ZIP",
    ".odp": "ZIP",
    ".epub": "ZIP",
    ".7z": "SEVENZ",
    ".rar": "RAR",
    ".tar": "TAR",
    ".gz": "GZIP",
    ".tgz": "TAR_GZ",
    ".bz2": "BZIP2",
    ".tbz2": "TAR_BZ2",
    ".tbz": "TAR_BZ2",
    ".xz": "XZ",
    ".txz": "TAR_XZ",
    ".zst": "ZSTD",
    ".tzst": "TAR_ZST",
    ".lz4": "LZ4",
    ".lzma": "LZMA",
    ".lzo": "LZOP",
    ".xar": "XAR",
    ".pkg": "XAR",  # macOS pkg are typically xar archives
    ".pdf": "PDF",
    ".dex": "DEX",
    ".class": "JAVA_CLASS",
    ".elf": "ELF",
    ".so": "ELF",
    ".o": "ELF",
    ".ko": "ELF",
    ".dylib": "MACHO",
    ".macho": "MACHO",
    # ---- Extended format support ----
    ".arj": "ARJ",
    ".lha": "LHA",
    ".lzh": "LHA",
    ".lz": "LZIP",
    ".tlz": "TAR_LZIP",        # tar wrapped in lzip; treated as a composite kind
    ".tar.lz": "TAR_LZIP",
    ".lrz": "LRZIP",
    ".zpaq": "ZPAQ",
    ".arc": "ARC",
    ".ark": "ARC",
    ".tnef": "TNEF",
    ".shar": "SHAR",
    ".uue": "UUENCODED",
    ".uu": "UUENCODED",
    ".sit": "STUFFIT",         # StuffIt classic; handled via unar
    ".sitx": "STUFFIT",        # StuffIt X; handled via unar
    ".alz": "ALZ",             # Korean ALZ format; handled via unar
    ".ace": "ACE",             # ACE; handled via unar (unace is non-free)
    # ---- Extended format support ----
    # Android
    ".apk": "APK",             # Android package -- ZIP underneath but apktool decodes resources
    # PDF (already detected by magic; just hint presence)
    # VM disk images
    ".vmdk": "VMDK",
    ".qcow2": "QCOW2",
    ".qcow": "QCOW2",
    ".vhd": "VHD",
    ".vhdx": "VHDX",
    ".raw": "RAW_DISK",        # Raw disk image
    ".img": "RAW_DISK",        # Generic disk image (often raw or one of the above)
    ".dd": "RAW_DISK",         # dd-style raw image
    # Filesystem images
    ".ntfs": "NTFS",
    ".ext2": "EXT_FS",
    ".ext3": "EXT_FS",
    ".ext4": "EXT_FS",
    ".xfs": "XFS",
    ".apfs": "APFS",
    ".hfs": "HFSPLUS",
    ".hfsx": "HFSPLUS",
    ".luks": "LUKS",
    # Embedded firmware filesystems
    ".jffs2": "JFFS2",
    ".ubi": "UBI",
    ".ubifs": "UBI",
    ".mtd": "MTD",
    # macOS
    ".plist": "BPLIST",        # Will refine in detection layer 2: text plists are NOT bplist
    # Microsoft compressed
    ".kwaj": "KWAJ",
    ".szdd": "SZDD",
}
