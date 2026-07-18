"""
.. module:: re_unpacker.extractors.rpm
    :synopsis: RPM package extractor (cross-platform).

Description
-----------
An ``.rpm`` is a lead + signature + header + compressed CPIO payload.

Cross-platform extractor strategy
---------------------------------
- **Linux**: Two extractor classes registered in priority order:
    1. ``RpmExtractor`` (priority 100): ``rpm2cpio | cpio -idm`` -- the
       canonical recipe.
    2. ``RpmArchiveExtractor`` (priority 90): ``rpm2archive | tar`` --
       handles modern zstd-compressed RPM payloads that older
       rpm2cpio+cpio may choke on.
- **Windows**: ``RpmSevenZipExtractor`` (priority 90; new in v0.4.0):
  uses 7-Zip's native RPM support. The 7-Zip manifest's FileExtensions
  list explicitly includes ``rpm`` (verified against
  microsoft/winget-pkgs/manifests/7/7zip/7zip). 7-Zip understands the
  RPM container and the inner CPIO payload, so a single ``7z x``
  produces the same payload tree as rpm2cpio+cpio on Linux.

The Linux-only RpmExtractor and RpmArchiveExtractor naturally
self-exclude on Windows because their required tools (rpm2cpio, cpio,
rpm2archive) are absent from TOOL_PACKAGE_HINTS_WINDOWS.

Notes
-----
- ``--no-absolute-filenames`` prevents cpio from writing outside
  ``dest_dir`` via absolute paths in the archive.
- cpio reports a summary line on stderr even on success; we don't treat
  non-empty stderr as failure -- only non-zero returncode.
- 7-Zip's RPM extraction may produce intermediate ``.cpio`` and ``.tar``
  files in the dest tree; the BFS orchestrator extracts them in
  subsequent passes naturally.

Version
-------
See :data:`re_unpacker.constants.VERSION`. Cross-platform support added
in v0.4.0.
"""

from __future__ import annotations

from pathlib import Path

from ..detection import FileKind
from ..platform_compat import is_windows
from ..subprocess_utils import run_pipeline, run_tool
from .base import Extractor, ExtractionContext, ExtractionResult


class RpmExtractor(Extractor):
    """Primary RPM extractor using ``rpm2cpio | cpio`` (Linux only).

    Filtered out on Windows because rpm2cpio and cpio are absent from
    TOOL_PACKAGE_HINTS_WINDOWS.
    """

    name = "rpm2cpio+cpio"
    handles_kinds = frozenset({FileKind.RPM})
    required_tools = ("rpm2cpio", "cpio")
    priority = 100

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        rpm2cpio = ctx.tools.path_of("rpm2cpio")
        cpio = ctx.tools.path_of("cpio")

        # cpio reads the stream from stdin. We run the pipeline.
        run_pipeline(
            stages=[
                [rpm2cpio, str(ctx.source_path)],
                [cpio, "-idm", "--no-absolute-filenames",
                 "-D", str(ctx.dest_dir)],
            ],
            tool_name=self.name,
            timeout=ctx.timeout_seconds,
            logger=ctx.logger,
            source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )


class RpmArchiveExtractor(Extractor):
    """Alternate RPM extractor using ``rpm2archive`` (Linux only).

    ``rpm2archive`` handles modern zstd-compressed RPM payloads that older
    rpm2cpio + cpio may choke on. Filtered out on Windows because
    rpm2archive is Linux-specific.
    """

    name = "rpm2archive"
    handles_kinds = frozenset({FileKind.RPM})
    required_tools = ("rpm2archive", "tar")
    priority = 90  # slightly below rpm2cpio+cpio default

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        # rpm2archive writes <rpm>.tgz next to the rpm by default; use -
        # to stream to stdout, then feed to tar.
        rpm2archive = ctx.tools.path_of("rpm2archive")
        tar = ctx.tools.path_of("tar")
        run_pipeline(
            stages=[
                [rpm2archive, "-n", "-o", "-", str(ctx.source_path)],
                # -n: no decompression of the tar wrapper; we let tar auto-detect
                # -o -: write to stdout
                [tar, "-xf", "-", "-C", str(ctx.dest_dir),
                 "--no-same-owner", "--no-same-permissions"],
            ],
            tool_name=self.name,
            timeout=ctx.timeout_seconds,
            logger=ctx.logger,
            source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )


class RpmSevenZipExtractor(Extractor):
    """Windows-only RPM extractor using 7-Zip.

    7-Zip understands the RPM container natively (per its FileExtensions
    manifest). A single ``7z x`` produces the payload files plus an
    intermediate CPIO archive that the BFS orchestrator extracts in the
    next pass automatically. Output is equivalent to rpm2cpio+cpio.
    """

    name = "7z (rpm, windows)"
    handles_kinds = frozenset({FileKind.RPM})
    required_tools = ("7z",)
    priority = 90  # below RpmExtractor(100) for cross-platform priority parity

    def is_available(self, tools) -> bool:
        # Windows-only: on Linux the canonical rpm2cpio+cpio path is
        # preferred even when 7z is available, because rpm2cpio handles
        # weird edge cases (zstd, lzip-compressed payloads) more robustly.
        if not is_windows():
            return False
        return super().is_available(tools)

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        sevenz = ctx.tools.path_of("7z")
        # 7-Zip extracts the RPM container; the inner CPIO and any
        # compressed payload layers are extracted by the BFS orchestrator
        # in subsequent passes.
        run_tool(
            [sevenz, "x", "-y", f"-o{ctx.dest_dir}", str(ctx.source_path)],
            tool_name="7z",
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )
