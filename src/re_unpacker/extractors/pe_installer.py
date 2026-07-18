"""
.. module:: re_unpacker.extractors.pe_installer
    :synopsis: Extractors for Windows PE-based installers.

Description
-----------
Covers the common installer families whose payloads are wrapped in a
PE executable:

- :class:`NsisExtractor` -- Nullsoft Scriptable Install System. ``7z``
  extracts both the NSIS script and the packed files.
- :class:`InnoSetupExtractor` -- InnoSetup installers (``innoextract``).
- :class:`InstallShieldExtractor` -- InstallShield (``unshield`` for the
  classic data1.cab format; ``7z`` for newer MSI-based variants).
- :class:`GenericPeExtractor` -- fallback for any PE we still want to
  try to crack open (bundle installers, WiX burn, unknown self-extractors).
  Uses ``7z`` which handles most of them, and ``binwalk`` as a last resort
  if the dedicated :class:`BinwalkExtractor` is also run.

Notes
-----
- InstallShield ``.cab`` files live alongside ``setup.exe`` in cabinet
  sets. When we see a ``setup.exe`` that ``file`` identifies as
  InstallShield, we check for sibling ``data1.cab``/``data2.cab`` files
  and point ``unshield`` at them. If there's no sibling cab, we fall
  back to ``7z x``.

Version
-------
See :data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

from pathlib import Path

from ..detection import FileKind
from ..subprocess_utils import run_tool
from .base import Extractor, ExtractionContext, ExtractionResult


# =============================================================================
# NSIS
# =============================================================================

class NsisExtractor(Extractor):
    """NSIS installer extractor via 7z.

    7z understands the NSIS container and pulls out the install script
    and every packed file.
    """

    name = "7z (NSIS)"
    handles_kinds = frozenset({FileKind.PE_NSIS})
    required_tools = ("7z",)
    priority = 100

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


# =============================================================================
# InnoSetup
# =============================================================================

class InnoSetupExtractor(Extractor):
    """InnoSetup installer extractor via ``innoextract``."""

    name = "innoextract"
    handles_kinds = frozenset({FileKind.PE_INNOSETUP})
    required_tools = ("innoextract",)
    priority = 100

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        # -s: silent, -d: target directory, --extract: default action
        argv = [
            ctx.tools.path_of("innoextract"),
            "--silent",
            "--extract",
            "--output-dir", str(ctx.dest_dir),
            str(ctx.source_path),
        ]
        run_tool(
            argv, tool_name="innoextract",
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )


class InnoSetupSevenZipExtractor(Extractor):
    """Fallback for Inno when innoextract isn't installed."""

    name = "7z (InnoSetup fallback)"
    handles_kinds = frozenset({FileKind.PE_INNOSETUP})
    required_tools = ("7z",)
    priority = 50

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


# =============================================================================
# InstallShield
# =============================================================================

class InstallShieldExtractor(Extractor):
    """InstallShield extractor.

    Classic InstallShield places the payload in sibling ``data1.cab``
    files next to ``setup.exe``. We detect and prefer those. For modern
    InstallShield (MSI-based), this path will fail and the registry
    falls through to :class:`GenericPeExtractor`.
    """

    name = "unshield"
    handles_kinds = frozenset({FileKind.PE_INSTALLSHIELD})
    required_tools = ("unshield",)
    priority = 100

    def _find_data_cab(self, source: Path) -> Path | None:
        """Locate data1.cab next to the setup.exe, or the .exe itself."""
        parent = source.parent
        for candidate in ("data1.cab", "DATA1.CAB", "Data1.cab"):
            p = parent / candidate
            if p.is_file():
                return p
        # Some InstallShield variants package data1.cab inside the .exe.
        # In that case unshield can't read the .exe directly -- the fallback
        # (generic PE / 7z) will have to handle it.
        return None

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        data_cab = self._find_data_cab(ctx.source_path)
        target = data_cab if data_cab is not None else ctx.source_path
        argv = [
            ctx.tools.path_of("unshield"),
            "-d", str(ctx.dest_dir),
            "x",
            str(target),
        ]
        run_tool(
            argv, tool_name="unshield",
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        notes = []
        if data_cab is not None:
            notes.append(f"used sibling cab: {data_cab.name}")
        return ExtractionResult(
            extractor_name=self.name, success=True,
            dest_dir=ctx.dest_dir, notes=notes,
        )


# =============================================================================
# Generic PE fallback
# =============================================================================

class GenericPeExtractor(Extractor):
    """Generic fallback for PE executables of unknown installer family.

    Uses ``7z x`` which handles WiX burn bundles, SFX archives, and many
    other installer types generically. Fails gracefully when 7z doesn't
    know the format -- the orchestrator then drops through to
    :class:`BinwalkExtractor` if ``--binwalk`` is enabled (on by default).
    """

    name = "7z (generic PE)"
    handles_kinds = frozenset({
        FileKind.PE_EXECUTABLE, FileKind.PE_WIXBURN,
    })
    required_tools = ("7z",)
    priority = 50

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
