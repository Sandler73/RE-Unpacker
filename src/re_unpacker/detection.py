"""
.. module:: re_unpacker.detection
    :synopsis: Multi-layer file-type detection (magic bytes + file(1) + ext).

Description
-----------
Given a path, return a canonical :class:`FileKind` that the extractor
registry can dispatch on. Detection is layered from most-reliable to
least:

1. **Magic bytes** read directly from the file (offset-aware; checks up
   to the first 64 KiB for formats like ISO9660 whose magic sits at
   offset 32769).
2. **`file(1)`** via the ``file`` binary (libmagic). More descriptive
   for PE sub-types (NSIS vs InnoSetup) and for formats our magic table
   doesn't cover.
3. **Extension hint**, used only to disambiguate when the first two agree
   on a generic kind (e.g. a ZIP could be ``.jar`` / ``.apk`` / ``.whl``;
   a generic archive from 7z could be any of several).

The final :class:`DetectedFile` carries everything downstream code might
need: kind, raw magic description, mime type, and hash of the first
header bytes.

Notes
-----
- We never trust the extension alone. A file called ``foo.zip`` that
  starts with ``\\x7fELF`` is an ELF.
- `file` is on every Kali by default; if for some reason it's missing,
  detection falls back to magic bytes + extension.

Version
-------
Part of RE-Unpacker 0.5.0. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import enum
import logging
import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from .constants import EXTENSION_HINTS, MAGIC_SIGNATURES
from .subprocess_utils import run_tool
from .tools import ToolRegistry


# =============================================================================
# FileKind enum -- canonical dispatch keys
# =============================================================================

class FileKind(str, enum.Enum):
    # Package formats
    DEB = "DEB"
    RPM = "RPM"
    MSI = "MSI"
    CAB = "CAB"

    # Windows PE and its installer sub-types
    PE_NSIS = "PE_NSIS"
    PE_INNOSETUP = "PE_INNOSETUP"
    PE_INSTALLSHIELD = "PE_INSTALLSHIELD"
    PE_WIXBURN = "PE_WIXBURN"
    PE_EXECUTABLE = "PE_EXECUTABLE"  # generic PE (EXE/DLL/etc.)

    # Unix executables
    ELF = "ELF"
    MACHO = "MACHO"

    # Filesystem/image containers
    ISO = "ISO"
    DMG = "DMG"
    APPIMAGE = "APPIMAGE"
    SNAP = "SNAP"
    SQUASHFS = "SQUASHFS"

    # Traditional archives
    TAR = "TAR"
    TAR_GZ = "TAR_GZ"
    TAR_BZ2 = "TAR_BZ2"
    TAR_XZ = "TAR_XZ"
    TAR_ZST = "TAR_ZST"
    TAR_LZMA = "TAR_LZMA"
    ZIP = "ZIP"
    SEVENZ = "SEVENZ"
    RAR = "RAR"
    AR = "AR"
    CPIO = "CPIO"
    XAR = "XAR"

    # Single-file compression streams
    GZIP = "GZIP"
    BZIP2 = "BZIP2"
    XZ = "XZ"
    ZSTD = "ZSTD"
    LZMA = "LZMA"
    LZ4 = "LZ4"
    LZOP = "LZOP"

    # Documents / other structured formats (kept for manifest; mostly not recursed)
    PDF = "PDF"
    OLE2 = "OLE2"   # Legacy Office compound doc (doc/xls/ppt/msi share)
    OOXML = "OOXML" # zip-based Office (docx/xlsx/pptx) -- dispatches as ZIP

    # Misc
    DEX = "DEX"
    JAVA_CLASS = "JAVA_CLASS"
    UNKNOWN_BINARY = "UNKNOWN_BINARY"
    UNKNOWN_TEXT = "UNKNOWN_TEXT"
    EMPTY = "EMPTY"

    # ---- Extended unpack formats ----
    ARJ = "ARJ"             # ARJ archives
    LHA = "LHA"             # LHA / LZH archives (handled by lha / lhasa)
    LZIP = "LZIP"           # lzip (.lz); distinct from .lzma / .xz
    TAR_LZIP = "TAR_LZIP"   # tar wrapped in lzip (.tar.lz)
    LRZIP = "LRZIP"         # lrzip (high-ratio compression)
    ZPAQ = "ZPAQ"           # ZPAQ archive
    ARC = "ARC"             # System Enhancement Associates ARC (DOS-era)
    TNEF = "TNEF"           # Microsoft TNEF (winmail.dat)
    SHAR = "SHAR"           # shell archive (POSIX)
    UUENCODED = "UUENCODED" # uuencoded data (.uu / .uue)
    STUFFIT = "STUFFIT"     # Apple StuffIt classic / X
    ALZ = "ALZ"             # ALZip Korean format
    ACE = "ACE"             # ACE archives (handled by unar; unace is non-free)

    # ---- additions: extraction-depth subsystem ----
    # PDF (refined: existing PDF kind reused; subkinds via signals)
    APK = "APK"                 # Android package -- ZIP outside, apktool-decodable
    BPLIST = "BPLIST"           # Apple binary plist (terminal -- classify only)
    # VM disk images
    VMDK = "VMDK"               # VMware VMDK
    QCOW2 = "QCOW2"             # QEMU QCOW/QCOW2
    VHD = "VHD"                 # Microsoft VHD (legacy)
    VHDX = "VHDX"               # Microsoft VHDX
    RAW_DISK = "RAW_DISK"       # Raw / dd-style disk image
    # Forensic filesystems
    APFS = "APFS"               # macOS APFS
    NTFS = "NTFS"               # Windows NTFS
    EXT_FS = "EXT_FS"           # Linux ext{2,3,4}
    XFS = "XFS"                 # Linux XFS
    HFSPLUS = "HFSPLUS"         # macOS HFS+
    FAT = "FAT"                 # FAT12/16/32/exFAT
    VSS = "VSS"                 # Windows VSS shadow copies
    LVM2 = "LVM2"               # Linux LVM2
    # Embedded firmware
    JFFS2 = "JFFS2"             # JFFS2 flash filesystem
    UBI = "UBI"                 # UBI / UBIFS
    MTD = "MTD"                 # MTD / NAND flash dump
    # Microsoft compressed (legacy)
    KWAJ = "KWAJ"               # MS KWAJ compressed
    SZDD = "SZDD"               # MS SZDD compressed
    # Encrypted (terminal-classify -- never recursed)
    LUKS_ENCRYPTED = "LUKS_ENCRYPTED"
    ENCRYPTED_GENERIC = "ENCRYPTED_GENERIC"


# Kinds that an extractor can still open -- used by orchestrator to decide
# whether to recurse into a just-extracted file.
EXTRACTABLE_KINDS: frozenset[FileKind] = frozenset({
    FileKind.DEB, FileKind.RPM, FileKind.MSI, FileKind.CAB,
    FileKind.PE_NSIS, FileKind.PE_INNOSETUP, FileKind.PE_INSTALLSHIELD,
    FileKind.PE_WIXBURN, FileKind.PE_EXECUTABLE,
    FileKind.ISO, FileKind.DMG, FileKind.APPIMAGE, FileKind.SNAP,
    FileKind.SQUASHFS,
    FileKind.TAR, FileKind.TAR_GZ, FileKind.TAR_BZ2, FileKind.TAR_XZ,
    FileKind.TAR_ZST, FileKind.TAR_LZMA,
    FileKind.ZIP, FileKind.SEVENZ, FileKind.RAR, FileKind.AR,
    FileKind.CPIO, FileKind.XAR,
    FileKind.GZIP, FileKind.BZIP2, FileKind.XZ, FileKind.ZSTD,
    FileKind.LZMA, FileKind.LZ4, FileKind.LZOP,
    # ELF/MACHO are "extractable" only when caller wants resource extraction.
    FileKind.ELF, FileKind.MACHO,
    FileKind.OOXML, FileKind.OLE2,
    # ---- Extended format support ----
    FileKind.ARJ, FileKind.LHA, FileKind.LZIP, FileKind.TAR_LZIP,
    FileKind.LRZIP, FileKind.ZPAQ, FileKind.ARC, FileKind.TNEF,
    FileKind.SHAR, FileKind.UUENCODED, FileKind.STUFFIT,
    FileKind.ALZ, FileKind.ACE,
    # ---- additions: extraction-depth (extractable only) ----
    # APK is extractable via apktool (and as a ZIP).
    FileKind.APK,
    # PDF is now extractable (qpdf for structure, pdfdetach for attachments).
    # We add it here because introduces a real extractor for it.
    FileKind.PDF,
    # VM disk images: extractable via qemu-img convert -> recurse into raw
    FileKind.VMDK, FileKind.QCOW2, FileKind.VHD, FileKind.VHDX,
    FileKind.RAW_DISK,
    # Forensic filesystems: libyal FUSE mount -> file copy out
    FileKind.APFS, FileKind.NTFS, FileKind.EXT_FS, FileKind.XFS,
    FileKind.HFSPLUS, FileKind.FAT, FileKind.VSS, FileKind.LVM2,
    # Embedded firmware filesystems
    FileKind.JFFS2, FileKind.UBI, FileKind.MTD,
    # Microsoft compressed (DOS-era)
    FileKind.KWAJ, FileKind.SZDD,
    # NOTE: BPLIST, LUKS_ENCRYPTED, ENCRYPTED_GENERIC are TERMINAL --
    # not in EXTRACTABLE_KINDS by design.
})


# =============================================================================
# Detection result
# =============================================================================

@dataclass
class DetectedFile:
    """Outcome of type detection."""
    path: Path
    size: int
    kind: FileKind
    magic_description: str = ""   # raw `file --brief` output
    mime_type: str = ""           # `file --mime-type --brief` output
    header_hex: str = ""          # first 32 bytes, hex-encoded (for manifest)
    extension_hint: str | None = None
    signals: list[str] = field(default_factory=list)  # debugging breadcrumb


# =============================================================================
# Magic-byte layer
# =============================================================================

_HEADER_BYTES_MAX: int = 65536  # enough for ISO9660 at offset 32769 + CD001

def _read_header(path: Path, max_bytes: int = _HEADER_BYTES_MAX) -> bytes:
    """Read up to ``max_bytes`` from the head of the file."""
    with open(path, "rb") as f:
        return f.read(max_bytes)


def _read_trailer(path: Path, size: int, trailer_bytes: int = 1024) -> bytes:
    """Read last ``trailer_bytes`` of the file (for DMG koly block)."""
    if size < trailer_bytes:
        return b""
    with open(path, "rb") as f:
        f.seek(size - trailer_bytes)
        return f.read(trailer_bytes)


def _check_magic(header: bytes, trailer: bytes, size: int) -> list[str]:
    """Return the list of MAGIC_SIGNATURES keys that match this data."""
    matches: list[str] = []
    for kind_key, sigs in MAGIC_SIGNATURES.items():
        for magic, offset in sigs:
            if offset >= 0:
                # Position in header buffer.
                if offset + len(magic) <= len(header):
                    if header[offset:offset + len(magic)] == magic:
                        matches.append(kind_key)
                        break
            else:
                # Negative offset: from EOF. Used for DMG koly trailer.
                if len(trailer) >= abs(offset):
                    start = len(trailer) + offset  # offset is negative
                    if 0 <= start and start + len(magic) <= len(trailer):
                        if trailer[start:start + len(magic)] == magic:
                            matches.append(kind_key)
                            break
    return matches


# Heuristic refinement: disambiguate magic-bytes collisions that need context.
def _refine_magic(
    matches: list[str], header: bytes, size: int, ext: str
) -> tuple[FileKind | None, list[str]]:
    """Map matched magic keys to a FileKind when possible.

    Returns ``(kind_or_None, signals)``.
    """
    signals: list[str] = [f"magic:{m}" for m in matches]

    # AR-family first (DEB is AR with "debian-binary" as first member).
    if "DEB" in matches:
        return FileKind.DEB, signals

    # Mach-O universal header and Java .class share 0xCAFEBABE. Disambiguate
    # by checking the "nfat_arch" field (position 4, big-endian u32). If
    # 0 < value < 30, treat as Mach-O universal; else class.
    if "MACHO_UNIV" in matches or "CLASS" in matches:
        if len(header) >= 8:
            nfat = struct.unpack(">I", header[4:8])[0]
            if 0 < nfat < 30:
                return FileKind.MACHO, signals + ["refine:macho_univ"]
            if ext in (".class", ".jar"):
                return FileKind.JAVA_CLASS, signals + ["refine:class_by_ext"]
            # Default to JAVA_CLASS since naked .class without ext is rare
            return FileKind.JAVA_CLASS, signals + ["refine:class_fallback"]

    # Executables
    if "ELF" in matches:
        return FileKind.ELF, signals
    if "PE" in matches:
        # PE needs to be confirmed: check for "PE\x00\x00" at e_lfanew.
        if len(header) >= 0x40:
            e_lfanew = struct.unpack("<I", header[0x3C:0x40])[0]
            if 0 < e_lfanew < len(header) - 4:
                if header[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
                    return FileKind.PE_EXECUTABLE, signals + ["refine:pe_confirmed"]
        # MZ without PE header → DOS exe -- still treat as PE_EXECUTABLE so
        # 7z can try to dig into it.
        return FileKind.PE_EXECUTABLE, signals + ["refine:mz_only"]

    if "MACHO_LE32" in matches or "MACHO_LE64" in matches \
            or "MACHO_BE32" in matches or "MACHO_BE64" in matches:
        return FileKind.MACHO, signals

    # Filesystem containers
    if "SQUASHFS" in matches:
        return FileKind.SQUASHFS, signals
    if "ISO9660" in matches:
        return FileKind.ISO, signals
    if "DMG_KOLY" in matches:
        return FileKind.DMG, signals
    if "CAB" in matches:
        return FileKind.CAB, signals

    # OLE2 is shared by MSI, DOC, XLS, PPT -- differentiate via extension.
    if "OLE2" in matches:
        if ext in (".msi", ".msp"):
            return FileKind.MSI, signals + ["refine:ole2_msi_by_ext"]
        # Treat other OLE2 as an extractable container; 7z can dig in.
        return FileKind.OLE2, signals + ["refine:ole2_generic"]

    # RPM
    if "RPM" in matches:
        return FileKind.RPM, signals

    # AR without debian-binary
    if "AR" in matches:
        return FileKind.AR, signals

    # CPIO variants
    if "CPIO_NEWC" in matches or "CPIO_CRC" in matches or "CPIO_ODC" in matches:
        return FileKind.CPIO, signals

    # XAR
    if "XAR" in matches:
        return FileKind.XAR, signals

    # Archive formats
    if "ZIP" in matches:
        return FileKind.ZIP, signals
    if "SEVENZ" in matches:
        return FileKind.SEVENZ, signals
    if "RAR4" in matches or "RAR5" in matches:
        return FileKind.RAR, signals
    if "TAR" in matches:
        return FileKind.TAR, signals

    # Compression streams
    if "GZIP" in matches:
        return FileKind.GZIP, signals
    if "BZIP2" in matches:
        return FileKind.BZIP2, signals
    if "XZ" in matches:
        return FileKind.XZ, signals
    if "ZSTD" in matches:
        return FileKind.ZSTD, signals
    if "LZ4" in matches:
        return FileKind.LZ4, signals
    if "LZOP" in matches:
        return FileKind.LZOP, signals
    if "LZMA" in matches:
        return FileKind.LZMA, signals

    if "PDF" in matches:
        return FileKind.PDF, signals
    if "DEX" in matches:
        return FileKind.DEX, signals

    # ---- Extended format support ----
    if "ARJ" in matches:
        return FileKind.ARJ, signals
    if "LHA" in matches:
        return FileKind.LHA, signals
    if "LZIP" in matches:
        # `.tar.lz` -- detect the tar wrapper via extension since the lzip
        # stream by itself doesn't expose its contents until decompressed.
        if ext in (".tlz", ".tar.lz"):
            return FileKind.TAR_LZIP, signals + ["refine:tar_lzip_by_ext"]
        return FileKind.LZIP, signals
    if "LRZIP" in matches:
        return FileKind.LRZIP, signals
    if "ZPAQ" in matches:
        return FileKind.ZPAQ, signals
    if "ARC" in matches:
        return FileKind.ARC, signals
    if "TNEF" in matches:
        return FileKind.TNEF, signals

    # ---- additions: extraction-depth subsystem ----
    # VM disk images
    if "VMDK" in matches:
        return FileKind.VMDK, signals
    if "QCOW2" in matches:
        return FileKind.QCOW2, signals
    if "VHDX" in matches:
        return FileKind.VHDX, signals
    if "VHD" in matches:
        return FileKind.VHD, signals
    # Filesystem images
    if "APFS" in matches:
        return FileKind.APFS, signals
    if "NTFS" in matches:
        return FileKind.NTFS, signals
    if "EXT_FS" in matches:
        return FileKind.EXT_FS, signals
    if "XFS" in matches:
        return FileKind.XFS, signals
    if "HFSPLUS" in matches:
        return FileKind.HFSPLUS, signals
    if "FAT" in matches:
        return FileKind.FAT, signals
    # Encrypted (terminal-classify -- the orchestrator must not recurse)
    if "LUKS" in matches:
        return FileKind.LUKS_ENCRYPTED, signals + ["terminal:encrypted"]
    # Embedded firmware
    if "JFFS2" in matches:
        return FileKind.JFFS2, signals
    if "UBI" in matches:
        return FileKind.UBI, signals
    # macOS bplist (terminal-classify; useful metadata for analyst but no recursion)
    if "BPLIST" in matches:
        return FileKind.BPLIST, signals + ["terminal:bplist"]
    # Microsoft compressed (DOS-era)
    if "KWAJ" in matches:
        return FileKind.KWAJ, signals
    if "SZDD" in matches:
        return FileKind.SZDD, signals

    return None, signals


# =============================================================================
# file(1) layer
# =============================================================================

def _run_file(path: Path, registry: ToolRegistry, logger: logging.Logger | None) \
        -> tuple[str, str]:
    """Return ``(brief_description, mime_type)`` from file(1). Empty on absence."""
    if not registry.have("file"):
        return "", ""
    file_bin = registry.path_of("file")
    try:
        brief = run_tool(
            [file_bin, "--brief", "--keep-going", str(path)],
            tool_name="file",
            timeout=30,
            check=False,
            logger=logger,
        )
        mime = run_tool(
            [file_bin, "--brief", "--mime-type", "--keep-going", str(path)],
            tool_name="file",
            timeout=30,
            check=False,
            logger=logger,
        )
    except Exception:
        return "", ""
    return brief.stdout_text.strip(), mime.stdout_text.strip()


# file(1) descriptions that indicate an installer sub-type. These strings
# are what upstream libmagic produces and are stable across recent Kali
# versions; checked against the `file-5.45` / `file-5.46` shipped magic.
_NSIS_MARKERS: Sequence[str] = ("Nullsoft Installer",)
_INNO_MARKERS: Sequence[str] = ("InnoSetup", "Inno Setup")
_INSTALLSHIELD_MARKERS: Sequence[str] = ("InstallShield",)
_WIXBURN_MARKERS: Sequence[str] = ("WiX Burn", "Burn container")
_APPIMAGE_MARKERS: Sequence[str] = ("AppImage",)
_SNAP_MARKERS: Sequence[str] = ("Snap package",)


def _refine_with_file_description(
    base_kind: FileKind | None,
    description: str,
    mime: str,
    ext: str,
    size: int,
) -> tuple[FileKind, list[str]]:
    """Combine base_kind (from magic) with file(1) description to refine."""
    desc_lower = description.lower()
    signals: list[str] = [f"file_desc:{description[:80]}"] if description else []
    if mime:
        signals.append(f"mime:{mime}")

    # PE sub-typing
    if base_kind in (FileKind.PE_EXECUTABLE, FileKind.PE_WIXBURN, None) and description:
        if any(m.lower() in desc_lower for m in _NSIS_MARKERS):
            return FileKind.PE_NSIS, signals + ["refine:nsis"]
        if any(m.lower() in desc_lower for m in _INNO_MARKERS):
            return FileKind.PE_INNOSETUP, signals + ["refine:inno"]
        if any(m.lower() in desc_lower for m in _INSTALLSHIELD_MARKERS):
            return FileKind.PE_INSTALLSHIELD, signals + ["refine:installshield"]
        if any(m.lower() in desc_lower for m in _WIXBURN_MARKERS):
            return FileKind.PE_WIXBURN, signals + ["refine:wixburn"]
        if base_kind == FileKind.PE_EXECUTABLE:
            return FileKind.PE_EXECUTABLE, signals

    # AppImage detection (it's an ELF with a signature)
    if base_kind == FileKind.ELF and description:
        if any(m.lower() in desc_lower for m in _APPIMAGE_MARKERS) \
                or ext == ".appimage":
            return FileKind.APPIMAGE, signals + ["refine:appimage"]
        return FileKind.ELF, signals

    # Snap
    if base_kind == FileKind.SQUASHFS and ext == ".snap":
        return FileKind.SNAP, signals + ["refine:snap"]
    if description and any(m.lower() in desc_lower for m in _SNAP_MARKERS):
        return FileKind.SNAP, signals + ["refine:snap_by_desc"]

    # OOXML vs ZIP: libmagic reports "Microsoft OOXML" for these.
    if base_kind == FileKind.ZIP:
        # APK detection: Android package archives are ZIP files at
        # the byte level but warrant the dedicated apktool extractor at
        # priority 90 (above plain unzip at 80). Trigger on any of:
        # - extension is .apk
        # - file(1) description mentions "Android package"
        # - mime type is application/vnd.android.package-archive
        # Whichever signal fires first wins; multiple signals strengthen the
        # classification but don't change the result.
        if (ext == ".apk"
                or "android package" in desc_lower
                or "android.package-archive" in (mime or "").lower()):
            return FileKind.APK, signals + ["refine:apk"]
        if "ooxml" in desc_lower or "microsoft word" in desc_lower \
                or "microsoft excel" in desc_lower \
                or "microsoft powerpoint" in desc_lower:
            return FileKind.OOXML, signals + ["refine:ooxml"]

    # TAR compression composites
    if base_kind in (FileKind.GZIP, FileKind.BZIP2, FileKind.XZ,
                     FileKind.ZSTD, FileKind.LZMA):
        # Extension hints commonly reveal the inner tar.
        ext_map = {
            ".tgz": FileKind.TAR_GZ, ".tar.gz": FileKind.TAR_GZ,
            ".tbz2": FileKind.TAR_BZ2, ".tbz": FileKind.TAR_BZ2,
            ".tar.bz2": FileKind.TAR_BZ2,
            ".txz": FileKind.TAR_XZ, ".tar.xz": FileKind.TAR_XZ,
            ".tzst": FileKind.TAR_ZST, ".tar.zst": FileKind.TAR_ZST,
            ".tar.lzma": FileKind.TAR_LZMA,
        }
        # Check compound extensions first.
        name_lower = ext.lower()
        for suffix, kind in ext_map.items():
            if name_lower.endswith(suffix) or ext == suffix:
                return kind, signals + [f"refine:tar_composite:{suffix}"]
        # file(1) reports "POSIX tar archive" even inside compression for many formats.
        if "tar archive" in desc_lower:
            map_to = {
                FileKind.GZIP: FileKind.TAR_GZ,
                FileKind.BZIP2: FileKind.TAR_BZ2,
                FileKind.XZ: FileKind.TAR_XZ,
                FileKind.ZSTD: FileKind.TAR_ZST,
                FileKind.LZMA: FileKind.TAR_LZMA,
            }
            return map_to[base_kind], signals + ["refine:tar_from_desc"]

    # ZIP subtype by extension hint (jar/apk/ipa/whl/docx...) -- dispatch
    # still goes via the ZIP extractor, but signal is recorded.
    if base_kind == FileKind.ZIP:
        return FileKind.ZIP, signals

    if base_kind is not None:
        return base_kind, signals

    # Nothing definitive from magic; try description heuristics.
    if description:
        if "elf" in desc_lower:
            return FileKind.ELF, signals + ["desc:elf"]
        if "pe32" in desc_lower or "ms-dos" in desc_lower:
            return FileKind.PE_EXECUTABLE, signals + ["desc:pe"]
        if "mach-o" in desc_lower:
            return FileKind.MACHO, signals + ["desc:macho"]
        if mime.startswith("text/") or "ascii text" in desc_lower \
                or "utf-8 unicode text" in desc_lower:
            return FileKind.UNKNOWN_TEXT, signals + ["desc:text"]

    # Default: size==0 → EMPTY; else binary unknown.
    if size == 0:
        return FileKind.EMPTY, signals + ["size:0"]
    return FileKind.UNKNOWN_BINARY, signals + ["fallback:unknown_binary"]


# =============================================================================
# Extension layer
# =============================================================================

def _compound_ext(path: Path) -> str:
    """Return a compound extension for names like ``foo.tar.gz`` (lowercase).

    Falls back to the single trailing extension (also lowercase).
    """
    name = path.name.lower()
    for suffix in (
        ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".tar.lzma",
        ".tar.lz4", ".tar.lzo",
        ".tar.lz",  # lzip-wrapped tar
    ):
        if name.endswith(suffix):
            return suffix
    return path.suffix.lower()


# =============================================================================
# Public entry points
# =============================================================================

def detect_file(
    path: Path,
    registry: ToolRegistry,
    *,
    logger: logging.Logger | None = None,
) -> DetectedFile:
    """Detect the kind of a single file.

    Parameters
    ----------
    path
        File path. Must be a regular file (caller screens directories).
    registry
        Populated tool registry (for the `file` probe).
    logger
        Optional logger for DEBUG trace.

    Returns
    -------
    DetectedFile
    """
    try:
        size = path.stat().st_size
    except OSError:
        size = 0

    if size == 0:
        return DetectedFile(
            path=path, size=0, kind=FileKind.EMPTY,
            signals=["size:0"],
        )

    header = b""
    trailer = b""
    try:
        header = _read_header(path)
        trailer = _read_trailer(path, size)
    except OSError as e:
        if logger is not None:
            logger.debug("Header read failed for %s: %s", path, e)

    header_hex = header[:32].hex() if header else ""
    ext = _compound_ext(path)

    # Layer 1: magic bytes
    magic_matches = _check_magic(header, trailer, size)
    magic_kind, magic_signals = _refine_magic(magic_matches, header, size, ext)

    # Layer 2: file(1)
    brief, mime = _run_file(path, registry, logger)

    # Layer 3: extension hint (only if the first two are inconclusive or ambiguous)
    ext_hint_kind_name = EXTENSION_HINTS.get(ext)

    # Combine layers
    combined_kind, file_signals = _refine_with_file_description(
        magic_kind, brief, mime, ext, size,
    )

    # If magic says one thing and file(1) says another, magic usually wins.
    # But for PE sub-types, file(1) is our only source, so let it upgrade.
    final_kind = combined_kind

    # If we still have UNKNOWN_BINARY and the extension hint maps, use it.
    if final_kind in (FileKind.UNKNOWN_BINARY, FileKind.UNKNOWN_TEXT) \
            and ext_hint_kind_name:
        try:
            final_kind = FileKind[ext_hint_kind_name]
            file_signals.append(f"ext_hint:{ext}")
        except KeyError:
            pass

    signals = magic_signals + file_signals
    if ext:
        signals.append(f"ext:{ext}")

    result = DetectedFile(
        path=path,
        size=size,
        kind=final_kind,
        magic_description=brief,
        mime_type=mime,
        header_hex=header_hex,
        extension_hint=ext_hint_kind_name,
        signals=signals,
    )
    if logger is not None:
        logger.debug(
            "detect: %s -> %s (size=%d, signals=%s)",
            path, final_kind.value, size, ",".join(signals),
        )
    return result
