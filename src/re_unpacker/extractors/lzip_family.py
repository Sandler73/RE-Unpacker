"""
.. module:: re_unpacker.extractors.lzip_family
    :synopsis: Extractors for lzip / plzip / lrzip / pixz / zpaq formats.

Description
-----------
Modern compression formats added :

- :class:`LzipExtractor` -- ``.lz`` (lzip): LZMA-based but distinct
  format from ``.xz`` and ``.lzma``. Decompresses to ``<stem>``.
- :class:`TarLzipExtractor` -- ``.tar.lz`` / ``.tlz``: tar wrapped in
  lzip. Pipeline: ``lzip -c <file> | tar -xf -``.
- :class:`LrzipExtractor` -- ``.lrz`` (lrzip): high-ratio compression
  using rzip + LZMA. Decompresses in-place via ``lrzip -d``.
- :class:`ZpaqExtractor` -- ``.zpaq`` archives. Uses ``zpaq x``.

Notes
-----
- ``lzip`` is the standalone lzip decompressor (from the ``lzip`` apt
  package). We prefer it over ``plzip`` because plzip is parallel-only
  and its CLI varies between versions.
- ``lrzip`` decompresses in place by default; we make a copy first so
  the source is never mutated, then move the result to the destination.
  This is the same pattern :class:`UpxExtractor` uses.
- ``zpaq`` requires a ``-key`` flag for encrypted archives; if the
  archive is encrypted and no key is available, the extractor surfaces
  the failure without ever guessing keys.

Execution parameters
--------------------
- All extractors honor ``ctx.timeout_seconds``.

Examples
--------
::

    RE-Unpacker payload.tar.lz -o /scratch/lz/
    RE-Unpacker bigblob.lrz -o /scratch/lrz/
    RE-Unpacker firmware.zpaq -o /scratch/zpaq/

Version
-------
Part of RE-Unpacker 0.5.0. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from ..detection import FileKind
from ..exceptions import ExtractorFailure, ExtractorTimeout
from ..subprocess_utils import run_pipeline, run_tool
from .base import Extractor, ExtractionContext, ExtractionResult


# =============================================================================
# Plain lzip (.lz, single-stream)
# =============================================================================

class LzipExtractor(Extractor):
    """lzip single-stream decompressor producing ``<stem>`` in dest_dir."""

    name = "lzip"
    handles_kinds = frozenset({FileKind.LZIP})
    required_tools = ("lzip",)
    priority = 100

    def _derive_outfile(self, source: Path, dest_dir: Path) -> Path:
        name = source.name
        if name.lower().endswith(".lz"):
            base = name[:-3]
        else:
            base = name + ".out"
        if not base:
            base = "decompressed.out"
        return dest_dir / base

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        outfile = self._derive_outfile(ctx.source_path, ctx.dest_dir)
        # lzip -c writes to stdout; we redirect to the outfile.
        argv = [ctx.tools.path_of("lzip"), "-d", "-c", str(ctx.source_path)]
        ctx.logger.debug("lzip decompress: %r -> %s", argv, outfile)
        try:
            with open(outfile, "wb") as fout:
                proc = subprocess.Popen(
                    argv,
                    stdout=fout,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                )
                try:
                    _, stderr = proc.communicate(timeout=ctx.timeout_seconds)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(proc.pid, 15)
                    except ProcessLookupError:
                        pass
                    raise ExtractorTimeout(
                        self.name, str(ctx.source_path), ctx.timeout_seconds,
                    )
            if proc.returncode != 0:
                raise ExtractorFailure(
                    extractor=self.name, source=str(ctx.source_path),
                    returncode=proc.returncode,
                    stderr=(stderr.decode("utf-8", errors="replace")[:2000]
                            if stderr else ""),
                )
        except OSError as e:
            raise ExtractorFailure(
                self.name, str(ctx.source_path),
                returncode=None, stderr=str(e),
            ) from e
        return ExtractionResult(
            extractor_name=self.name, success=True,
            dest_dir=ctx.dest_dir, files_produced=1,
        )


# =============================================================================
# tar.lz / .tlz
# =============================================================================

class TarLzipExtractor(Extractor):
    """``.tar.lz`` / ``.tlz`` extractor: lzip stream piped into tar."""

    name = "lzip+tar"
    handles_kinds = frozenset({FileKind.TAR_LZIP})
    required_tools = ("lzip", "tar")
    priority = 100

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        run_pipeline(
            stages=[
                [ctx.tools.path_of("lzip"), "-d", "-c", str(ctx.source_path)],
                [ctx.tools.path_of("tar"), "-xf", "-",
                 "-C", str(ctx.dest_dir),
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


# =============================================================================
# lrzip
# =============================================================================

class LrzipExtractor(Extractor):
    """lrzip (.lrz) extractor.

    lrzip mutates its input by default; we operate on a copy so the source
    is never modified. Pattern matches :class:`UpxExtractor`.
    """

    name = "lrzip"
    handles_kinds = frozenset({FileKind.LRZIP})
    required_tools = ("lrzip",)
    priority = 100

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)

        # Work on a copy.
        copy = ctx.dest_dir / ctx.source_path.name
        shutil.copy2(ctx.source_path, copy)

        # lrzip -d <file> writes the decompressed result alongside, dropping
        # the .lrz suffix. Use -o to control the output filename explicitly.
        if copy.name.lower().endswith(".lrz"):
            outname = copy.name[:-4]
        else:
            outname = copy.name + ".out"
        outpath = ctx.dest_dir / outname

        argv = [
            ctx.tools.path_of("lrzip"),
            "-d",
            "-o", str(outpath),
            str(copy),
        ]
        try:
            run_tool(
                argv, tool_name="lrzip",
                timeout=ctx.timeout_seconds, check=True,
                logger=ctx.logger, source_for_error=str(ctx.source_path),
            )
        finally:
            # Always remove the working copy regardless of success / failure.
            try:
                copy.unlink()
            except OSError:
                pass
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
            notes=[f"lrzip -d produced: {outname}"],
        )


# =============================================================================
# zpaq
# =============================================================================

class ZpaqExtractor(Extractor):
    """ZPAQ archive extractor.

    zpaq's CLI is positional: ``zpaq x <archive> -to <outdir>``.
    """

    name = "zpaq"
    handles_kinds = frozenset({FileKind.ZPAQ})
    required_tools = ("zpaq",)
    priority = 100

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            ctx.tools.path_of("zpaq"), "x",
            str(ctx.source_path),
            "-to", str(ctx.dest_dir),
        ]
        run_tool(
            argv, tool_name="zpaq",
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )
