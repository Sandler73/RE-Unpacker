"""
.. module:: re_unpacker.extractors.squashfs
    :synopsis: Extractors for SquashFS images, Snap packages, and AppImages.

Description
-----------
- :class:`SquashfsExtractor` -- raw SquashFS images. ``unsquashfs``.
- :class:`SnapExtractor` -- ``.snap`` files are SquashFS images; same tool.
- :class:`AppImageExtractor` -- AppImages are ELF binaries whose tail is
  a SquashFS filesystem. The official extraction method is
  ``<appimage> --appimage-extract`` which requires the image to be
  executable AND writes output to ``squashfs-root/`` in the current
  working directory. We invoke it with a copy in a sandbox temp dir
  (never execute the user's file in-place) and then move
  ``squashfs-root`` into ``dest_dir``.

Notes
-----
- AppImage self-extract runs arbitrary code from the AppImage? No --
  ``--appimage-extract`` is handled by the AppImage runtime stub and
  only does decompression. Still, we never run the user's file directly;
  we make a read-only copy first so the original source is never
  modified, and we invoke it from a scratch directory so any side
  effects land there.
- If ``unsquashfs`` is available we additionally use it as a fallback
  for AppImages -- we can seek past the ELF header to the SquashFS
  offset and extract directly, which avoids running any part of the
  binary.

Version
-------
See :data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import os
import shutil
import stat
import struct
import tempfile
from pathlib import Path

from ..detection import FileKind
from ..exceptions import ExtractorFailure
from ..subprocess_utils import run_tool
from .base import Extractor, ExtractionContext, ExtractionResult


class SquashfsExtractor(Extractor):
    """Raw SquashFS image extractor via ``unsquashfs``."""

    name = "unsquashfs"
    handles_kinds = frozenset({FileKind.SQUASHFS})
    required_tools = ("unsquashfs",)
    priority = 100

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        # unsquashfs -d requires the destination NOT to exist (it creates it).
        # So we point at dest_dir/_sqfs and the orchestrator copies upward.
        # Actually unsquashfs accepts an existing empty dir via -f. Simpler:
        # create a subdir to guarantee newness.
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        target = ctx.dest_dir / "squashfs-root"
        # If a previous run left it behind, remove it.
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        argv = [
            ctx.tools.path_of("unsquashfs"),
            "-d", str(target),
            "-no-progress",
            "-no-xattrs",
            str(ctx.source_path),
        ]
        run_tool(
            argv, tool_name="unsquashfs",
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )


class SnapExtractor(Extractor):
    """``.snap`` extractor (identical mechanism to SquashFS)."""

    name = "unsquashfs (snap)"
    handles_kinds = frozenset({FileKind.SNAP})
    required_tools = ("unsquashfs",)
    priority = 100

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        target = ctx.dest_dir / "snap-root"
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        argv = [
            ctx.tools.path_of("unsquashfs"),
            "-d", str(target),
            "-no-progress",
            "-no-xattrs",
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


class AppImageExtractor(Extractor):
    """AppImage extractor.

    Tries, in order:

    1. ``unsquashfs -o <offset>`` if we can locate the SquashFS offset
       inside the ELF. This never executes the AppImage.
    2. ``<copy> --appimage-extract`` as a fallback. The copy is made
       world-readable + user-executable in a scratch directory so the
       original file is never mutated.
    """

    name = "appimage"
    handles_kinds = frozenset({FileKind.APPIMAGE})
    # unsquashfs preferred; if absent, chmod+run is attempted.
    required_tools = ("unsquashfs",)
    priority = 90

    def _find_squashfs_offset(self, path: Path) -> int | None:
        """Scan for the SquashFS magic inside the file and return its offset."""
        # Read in 1 MiB chunks, look for 'hsqs' or 'sqsh' magic.
        MAGICS = (b"hsqs", b"sqsh", b"shsq", b"qshs")
        CHUNK = 1024 * 1024
        pos = 0
        try:
            with open(path, "rb") as f:
                while True:
                    buf = f.read(CHUNK)
                    if not buf:
                        return None
                    for m in MAGICS:
                        idx = buf.find(m)
                        if idx != -1:
                            return pos + idx
                    # Overlap handling: rewind slightly in case magic spans boundary
                    if len(buf) < CHUNK:
                        return None
                    f.seek(f.tell() - (len(m) - 1))
                    pos = f.tell()
        except OSError:
            return None

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        # Strategy 1: unsquashfs with computed offset.
        if ctx.tools.have("unsquashfs"):
            offset = self._find_squashfs_offset(ctx.source_path)
            if offset is not None and offset > 0:
                target = ctx.dest_dir / "squashfs-root"
                if target.exists():
                    shutil.rmtree(target, ignore_errors=True)
                argv = [
                    ctx.tools.path_of("unsquashfs"),
                    "-d", str(target),
                    "-no-progress",
                    "-no-xattrs",
                    "-o", str(offset),
                    str(ctx.source_path),
                ]
                try:
                    run_tool(
                        argv, tool_name="unsquashfs (appimage offset)",
                        timeout=ctx.timeout_seconds, check=True,
                        logger=ctx.logger, source_for_error=str(ctx.source_path),
                    )
                    return ExtractionResult(
                        extractor_name=self.name, success=True,
                        dest_dir=ctx.dest_dir,
                        notes=[f"unsquashfs at offset {offset}"],
                    )
                except ExtractorFailure as e:
                    ctx.logger.debug(
                        "unsquashfs offset extract failed (will try fallback): %s",
                        e,
                    )

        # Strategy 2: copy + --appimage-extract (must be executable).
        with tempfile.TemporaryDirectory(prefix="reunp_appimg_") as td:
            td_path = Path(td)
            copy = td_path / ctx.source_path.name
            shutil.copy2(ctx.source_path, copy)
            # Make copy executable (we only set bits we need).
            st = copy.stat()
            copy.chmod(st.st_mode | stat.S_IXUSR | stat.S_IRUSR)
            argv = [str(copy), "--appimage-extract"]
            # Running the AppImage needs FUSE *unless* --appimage-extract is
            # used, which is served entirely by the runtime stub. Safe.
            run_tool(
                argv, tool_name="appimage --appimage-extract",
                cwd=td_path,
                timeout=ctx.timeout_seconds, check=True,
                logger=ctx.logger, source_for_error=str(ctx.source_path),
            )
            produced = td_path / "squashfs-root"
            if not produced.is_dir():
                raise ExtractorFailure(
                    extractor=self.name, source=str(ctx.source_path),
                    returncode=0,
                    stderr="--appimage-extract produced no squashfs-root directory",
                )
            target = ctx.dest_dir / "squashfs-root"
            if target.exists():
                shutil.rmtree(target, ignore_errors=True)
            shutil.move(str(produced), str(target))
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
            notes=["used --appimage-extract fallback"],
        )
