"""
.. module:: re_unpacker.extractors.upx
    :synopsis: UPX-packed binary unpacker.

Description
-----------
Detects UPX-packed ELF / PE / Mach-O binaries and unpacks them to
``dest_dir/<stem>.upx-unpacked`` using ``upx -d``. The original source
file is NEVER modified -- we copy it first and operate on the copy.

Detection strategy:

1. Fast path: scan the first few MiB of the file for the ``UPX!`` magic
   string. UPX writes this in several stub locations, and its presence
   is a reliable positive signal.
2. Confirmation: run ``upx -t <copy>`` which validates the UPX structure.
   If it returns zero the file really is UPX-packed.

Notes
-----
- ``upx -d`` requires write access to the file it's decompressing; we
  therefore always work on a copy.
- This extractor is "applicable" to any ELF / PE / Mach-O. It checks
  quickly whether the file is packed and returns a benign
  :class:`ExtractionResult` with ``success=False`` if not -- the
  orchestrator then lets the next extractor in the chain try.

Version
-------
See :data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from ..detection import FileKind
from ..exceptions import ExtractorFailure, ExtractorNotApplicable
from ..subprocess_utils import run_tool
from .base import Extractor, ExtractionContext, ExtractionResult


_UPX_MAGIC = b"UPX!"
_SCAN_BYTES = 8 * 1024 * 1024  # 8 MiB is enough for the stub region


class UpxExtractor(Extractor):
    """Detect and unpack UPX-packed binaries."""

    name = "upx"
    handles_kinds = frozenset({
        FileKind.ELF, FileKind.PE_EXECUTABLE, FileKind.MACHO,
    })
    required_tools = ("upx",)
    # Higher than format-generic (binwalk=20) but below format-specific
    # installers/archives. This way UPX runs alongside -- not instead of --
    # installer extraction, via separate orchestrator dispatch.
    priority = 70

    # UPX produces a single binary, not an archive. The unpacked binary can
    # itself be interesting for recursion (resource extraction, further
    # binwalk), so yes, mark it extractable.
    produces_extractable_content = True

    def _looks_upx(self, path: Path) -> bool:
        """Quick magic scan. Returns True if ``UPX!`` appears in the head."""
        try:
            with open(path, "rb") as f:
                head = f.read(_SCAN_BYTES)
            return _UPX_MAGIC in head
        except OSError:
            return False

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        if not self._looks_upx(ctx.source_path):
            # Not a UPX file; signal "not applicable" so the dispatch
            # chain continues silently (no error entry recorded).
            raise ExtractorNotApplicable(
                f"{self.name}: no UPX magic in {ctx.source_path.name}",
                context={"reason": "no_upx_magic"},
            )

        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        upx = ctx.tools.path_of("upx")

        # Always operate on a copy; never mutate the source.
        copy = ctx.dest_dir / (ctx.source_path.name + ".upx-copy")
        shutil.copy2(ctx.source_path, copy)

        # Confirm with `upx -t`.
        try:
            run_tool(
                [upx, "-t", str(copy)],
                tool_name="upx -t",
                timeout=min(ctx.timeout_seconds, 120),
                check=True, logger=ctx.logger,
                source_for_error=str(ctx.source_path),
            )
        except ExtractorFailure as e:
            # Magic was a coincidence (e.g. "UPX!" as a string inside the
            # binary); not actually UPX-packed. Not an error condition.
            try:
                copy.unlink()
            except OSError:
                pass
            raise ExtractorNotApplicable(
                f"{self.name}: upx -t rejected {ctx.source_path.name}",
                context={"reason": "upx_rejected"},
            ) from e

        # Unpack.
        outfile = ctx.dest_dir / (ctx.source_path.stem + ".upx-unpacked")
        argv = [upx, "-d", "-o", str(outfile), str(copy)]
        try:
            run_tool(
                argv, tool_name="upx -d",
                timeout=ctx.timeout_seconds, check=True,
                logger=ctx.logger, source_for_error=str(ctx.source_path),
            )
        finally:
            # Whether we succeeded or failed, remove the working copy.
            try:
                copy.unlink()
            except OSError:
                pass

        return ExtractionResult(
            extractor_name=self.name, success=True,
            dest_dir=ctx.dest_dir,
            notes=[f"upx -d produced: {outfile.name}"],
        )
