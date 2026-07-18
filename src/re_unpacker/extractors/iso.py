"""
.. module:: re_unpacker.extractors.iso
    :synopsis: Extractors for ISO-9660, DMG, and XAR container formats.

Description
-----------
- :class:`IsoExtractor` -- ISO-9660 / UDF disc images. 7z is primary; if
  absent, ``bsdtar`` (from libarchive-tools) works on most ISOs and is a
  solid backup.
- :class:`DmgExtractor` -- Apple Disk Image. 7z supports UDIF/UDRW
  out-of-the-box on Linux. Truly encrypted DMGs aren't unpackable
  without keys -- that's out of scope here.
- :class:`XarExtractor` -- Apple/FreeBSD XAR (``.pkg`` on macOS is xar).
  Prefer the dedicated ``xar`` binary if installed; otherwise 7z.

Notes
-----
- Mount-based extraction (``mount -o loop``) is avoided on purpose. It
  requires root, can trigger kernel-side code on hostile images, and is
  unnecessary when userspace tools already understand the formats.

Version
-------
Part of re-unpacker 0.4.10. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

from ..detection import FileKind
from ..subprocess_utils import run_tool
from .base import Extractor, ExtractionContext, ExtractionResult


class IsoExtractor(Extractor):
    """ISO-9660 / UDF extractor.

    ``7z`` (p7zip-full) is the primary extractor; it handles ISO-9660,
    Joliet, Rock Ridge, UDF, and hybrid images.
    """

    name = "7z (ISO)"
    handles_kinds = frozenset({FileKind.ISO})
    required_tools = ("7z",)
    priority = 85  # higher than the default 7z (60) for ISO kinds

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            ctx.tools.path_of("7z"), "x", "-y",
            f"-o{ctx.dest_dir}",
            "-bd", "-aoa",
            str(ctx.source_path),
        ]
        run_tool(
            argv, tool_name=self.name,
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )


class IsoBsdtarExtractor(Extractor):
    """Fallback ISO extractor using ``bsdtar`` (libarchive-tools)."""

    name = "bsdtar (ISO)"
    handles_kinds = frozenset({FileKind.ISO})
    required_tools = ("bsdtar",)
    priority = 50

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            ctx.tools.path_of("bsdtar"),
            "-xf", str(ctx.source_path),
            "-C", str(ctx.dest_dir),
        ]
        run_tool(
            argv, tool_name=self.name,
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )


class DmgExtractor(Extractor):
    """Apple Disk Image extractor using 7z."""

    name = "7z (DMG)"
    handles_kinds = frozenset({FileKind.DMG})
    required_tools = ("7z",)
    priority = 85

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            ctx.tools.path_of("7z"), "x", "-y",
            f"-o{ctx.dest_dir}",
            "-bd", "-aoa",
            str(ctx.source_path),
        ]
        run_tool(
            argv, tool_name=self.name,
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )


class XarExtractor(Extractor):
    """XAR / Apple .pkg extractor.

    Uses 7z (widely available on Kali) which understands the XAR container.
    A dedicated ``xar`` binary, when installed, offers better round-tripping
    but isn't needed here for read/extract.
    """

    name = "7z (XAR)"
    handles_kinds = frozenset({FileKind.XAR})
    required_tools = ("7z",)
    priority = 85

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            ctx.tools.path_of("7z"), "x", "-y",
            f"-o{ctx.dest_dir}",
            "-bd", "-aoa",
            str(ctx.source_path),
        ]
        run_tool(
            argv, tool_name=self.name,
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )
