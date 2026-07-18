"""
.. module:: re_unpacker.extractors.base
    :synopsis: Abstract Extractor base class and dispatch registry.

Description
-----------
Every format-specific extractor implements :class:`Extractor`. The
:class:`ExtractorRegistry` resolves a :class:`~re_unpacker.detection.FileKind`
to the ordered list of extractors the orchestrator should try (primary,
then fallback, then last-resort). The orchestrator walks the list in
order, catches :class:`~re_unpacker.exceptions.ExtractionError` from each
attempt, and records the outcome.

Notes
-----
- An extractor is "applicable" for a kind if it declares that kind in
  :attr:`Extractor.handles_kinds`. The orchestrator does not assume any
  1:1 mapping -- multiple extractors may handle the same kind (primary
  + fallback chain).
- An extractor is "available" on this host if every name in
  :attr:`Extractor.required_tools` is present in the
  :class:`ToolRegistry`. Unavailable extractors are silently skipped in
  dispatch (the orchestrator logs why).
- :meth:`Extractor.extract` must return an :class:`ExtractionResult`
  describing what was produced; it must not raise on expected "nothing
  useful to extract" outcomes (return empty result instead). Raise
  :class:`ExtractionError` only for true failures.

Version
-------
Part of re-unpacker 0.4.10. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ..detection import FileKind
from ..tools import ToolRegistry


@dataclass
class ExtractionContext:
    """Everything an extractor needs to do its job.

    Passed by the orchestrator so extractors don't need to know about
    quota tracking or manifests directly -- they just produce files
    into ``dest_dir`` and the orchestrator takes it from there.
    """
    source_path: Path           # input archive / package / binary
    source_sha256: str          # pre-computed hash of source (for manifest)
    dest_dir: Path              # where to put extracted output
    depth: int                  # recursion depth
    output_root: Path           # run-wide output root (for path safety audit)
    timeout_seconds: int
    logger: logging.Logger
    tools: ToolRegistry


@dataclass
class ExtractionResult:
    """What an extractor produced."""
    extractor_name: str
    success: bool
    dest_dir: Path
    files_produced: int = 0
    bytes_produced: int = 0
    notes: list[str] = field(default_factory=list)


class Extractor(abc.ABC):
    """Base class for all extractors."""

    # Human-readable name used in manifest / logs (override in subclass).
    name: str = "abstract"

    # Kinds this extractor handles (override in subclass).
    handles_kinds: frozenset[FileKind] = frozenset()

    # System tools this extractor needs (override in subclass).
    required_tools: tuple[str, ...] = ()

    # Priority among extractors for the same kind: higher = tried first.
    priority: int = 0

    # Whether the outputs of this extractor should be re-scanned for
    # further extractables. True for every container/archive extractor.
    produces_extractable_content: bool = True

    # Secondary extractors run *in addition to* the successful primary
    # extractor (not as alternatives). Used for PE resource / ELF section
    # dumping where we want both the installer unpack AND the resources.
    is_secondary: bool = False

    # New : whether this extractor needs root privileges to operate.
    # Currently used by libyal FUSE-mount-based filesystem extractors.
    # When True and the current process is non-root, the orchestrator skips
    # the extractor with a clear log message; the run does NOT abort, the
    # next extractor in the chain (if any) gets a turn.
    requires_root: bool = False

    def is_available(self, tools: ToolRegistry) -> bool:
        """True iff every required tool is present in the registry."""
        return all(tools.have(t) for t in self.required_tools)

    def missing_tools(self, tools: ToolRegistry) -> list[str]:
        """Names of required tools that are missing."""
        return [t for t in self.required_tools if not tools.have(t)]

    @abc.abstractmethod
    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        """Perform the extraction. Raise ``ExtractionError`` on failure."""

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"<{type(self).__name__} name={self.name!r} prio={self.priority}>"


class ExtractorRegistry:
    """Maps :class:`FileKind` → ordered list of :class:`Extractor` instances.

    Splits into *primary* extractors (orchestrator tries in priority order
    until one succeeds) and *secondary* extractors (orchestrator runs all
    of them in addition to the successful primary).
    """

    def __init__(self) -> None:
        self._primary_by_kind: dict[FileKind, list[Extractor]] = {}
        self._secondary_by_kind: dict[FileKind, list[Extractor]] = {}
        self._all: list[Extractor] = []

    def register(self, extractor: Extractor) -> None:
        """Add an extractor. Kinds it handles may overlap with others."""
        self._all.append(extractor)
        bucket_map = (
            self._secondary_by_kind if extractor.is_secondary
            else self._primary_by_kind
        )
        for kind in extractor.handles_kinds:
            bucket = bucket_map.setdefault(kind, [])
            bucket.append(extractor)
            # Keep each bucket sorted by descending priority.
            bucket.sort(key=lambda e: e.priority, reverse=True)

    def primary_for_kind(self, kind: FileKind) -> list[Extractor]:
        """Ordered list of primary extractors (empty if unknown)."""
        return list(self._primary_by_kind.get(kind, ()))

    def secondary_for_kind(self, kind: FileKind) -> list[Extractor]:
        """Ordered list of secondary extractors (empty if unknown)."""
        return list(self._secondary_by_kind.get(kind, ()))

    # Backwards-compatibility alias some callers may expect.
    def for_kind(self, kind: FileKind) -> list[Extractor]:
        return self.primary_for_kind(kind)

    def all(self) -> Iterable[Extractor]:
        return tuple(self._all)

    def known_kinds(self) -> frozenset[FileKind]:
        return frozenset(
            list(self._primary_by_kind.keys())
            + list(self._secondary_by_kind.keys())
        )


def build_default_registry() -> ExtractorRegistry:
    """Instantiate every concrete extractor and build the dispatch registry.

    Kept here (not in ``__init__`` of the extractors subpackage) to avoid
    import-order fragility.
    """
    # Import here to avoid circular imports at module load time.
    from .archive import (
        TarExtractor, ZipExtractor, SevenZipExtractor, RarExtractor,
        SingleStreamExtractor,
    )
    from .deb import DebExtractor, DebArFallbackExtractor, DebSevenZipExtractor
    from .rpm import RpmExtractor, RpmArchiveExtractor, RpmSevenZipExtractor
    from .msi import MsiExtractor, MsiExecExtractor
    from .cab import CabExtractor
    from .pe_installer import (
        NsisExtractor, InnoSetupExtractor, InnoSetupSevenZipExtractor,
        InstallShieldExtractor, GenericPeExtractor,
    )
    from .iso import IsoExtractor, IsoBsdtarExtractor, DmgExtractor, XarExtractor
    from .squashfs import SquashfsExtractor, SnapExtractor, AppImageExtractor
    from .cpio_ar import CpioExtractor, ArExtractor
    from .binwalk import BinwalkExtractor
    from .upx import UpxExtractor
    from .resources import PeResourceExtractor, ElfSectionExtractor
    # ---- Extended format support ----
    from .legacy import (
        ArjExtractor, LhaExtractor, ArcExtractor, TnefExtractor,
        SharExtractor, UuencodedExtractor, UnarFallbackExtractor,
    )
    from .lzip_family import (
        LzipExtractor, TarLzipExtractor, LrzipExtractor, ZpaqExtractor,
    )
    # ---- Extended format support ----
    from .pdf import PdfAttachmentExtractor, PdfStructureExtractor
    from .android import ApktoolExtractor
    from .disk_image import (
        QemuImgExtractor, VmdkExtractor, QcowExtractor, VhdiExtractor,
        WindowsSevenZipDiskExtractor,
        WindowsVmdkExportExtractor, WindowsQcowExportExtractor,
        WindowsVhdiExportExtractor,
    )
    from .forensic_fs import (
        ApfsExtractor, NtfsExtractor, ExtFsExtractor, XfsExtractor,
        HfsplusExtractor, FatExtractor, VssExtractor, Lvm2Extractor,
        WindowsSevenZipForensicFsExtractor,
        WindowsXfsExportExtractor, WindowsVssExportExtractor,
        WindowsLvm2ExportExtractor,
    )
    from .embedded_fs import (
        FirmwareFsBinwalkExtractor, MsCompressExtractor, BplistConverter,
    )

    reg = ExtractorRegistry()

    primary_extractors: tuple[Extractor, ...] = (
        # Package formats (primary + fallback)
        DebExtractor(), DebArFallbackExtractor(), DebSevenZipExtractor(),
        RpmExtractor(), RpmArchiveExtractor(), RpmSevenZipExtractor(),
        MsiExtractor(), MsiExecExtractor(), CabExtractor(),
        # PE installers (specific, then generic fallback)
        NsisExtractor(),
        InnoSetupExtractor(), InnoSetupSevenZipExtractor(),
        InstallShieldExtractor(),
        GenericPeExtractor(),
        # Filesystem containers
        IsoExtractor(), IsoBsdtarExtractor(),
        DmgExtractor(), XarExtractor(),
        SquashfsExtractor(), SnapExtractor(), AppImageExtractor(),
        # Traditional archives
        TarExtractor(), ZipExtractor(), SevenZipExtractor(), RarExtractor(),
        ArExtractor(), CpioExtractor(),
        # Single streams
        SingleStreamExtractor(),
        # Packer unpacker (primary for UPX'd binaries; orchestrator
        # tries it before the generic PE extractor for PE_EXECUTABLE kind).
        UpxExtractor(),
        # ---- Extended unpack toolset ----
        # Legacy / niche formats
        ArjExtractor(), LhaExtractor(), ArcExtractor(),
        TnefExtractor(), SharExtractor(), UuencodedExtractor(),
        # Lzip family + ZPAQ
        LzipExtractor(), TarLzipExtractor(),
        LrzipExtractor(), ZpaqExtractor(),
        # Broad-coverage fallback (StuffIt/ALZ/ACE primary; RAR/ZIP/etc. fallback)
        UnarFallbackExtractor(),
        # ---- additions: extraction-depth subsystem ----
        # PDF
        PdfAttachmentExtractor(), PdfStructureExtractor(),
        # Android
        ApktoolExtractor(),
        # VM disk images: libyal mounters (Linux, root-required) at priority 90,
        # qemu-img conversion (cross-platform, no-root) at priority 70.
        # Windows path: 7-Zip (priority 85) + libyal *export (priority 75).
        VmdkExtractor(), QcowExtractor(), VhdiExtractor(),
        QemuImgExtractor(),
        WindowsSevenZipDiskExtractor(),
        WindowsVmdkExportExtractor(),
        WindowsQcowExportExtractor(),
        WindowsVhdiExportExtractor(),
        # Forensic filesystems: libyal FUSE on Linux (root-required).
        # Windows path: 7-Zip for NTFS/APFS/HFS+/EXT/FAT (priority 85),
        # libyal *export for XFS/VSS/LVM2 (priority 75; manual install).
        ApfsExtractor(), NtfsExtractor(), ExtFsExtractor(),
        XfsExtractor(), HfsplusExtractor(), FatExtractor(),
        VssExtractor(), Lvm2Extractor(),
        WindowsSevenZipForensicFsExtractor(),
        WindowsXfsExportExtractor(),
        WindowsVssExportExtractor(),
        WindowsLvm2ExportExtractor(),
        # Embedded firmware filesystems
        FirmwareFsBinwalkExtractor(),
        # Microsoft DOS-era compressed
        MsCompressExtractor(),
        # Last resort
        BinwalkExtractor(),
    )

    secondary_extractors: tuple[Extractor, ...] = (
        PeResourceExtractor(),
        ElfSectionExtractor(),
        # ----: macOS bplist -> XML alongside the original ----
        BplistConverter(),
    )

    for ex in primary_extractors:
        reg.register(ex)
    for ex in secondary_extractors:
        reg.register(ex)
    return reg
