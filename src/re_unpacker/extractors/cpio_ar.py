"""
.. module:: re_unpacker.extractors.cpio_ar
    :synopsis: CPIO and AR archive extractors (cross-platform).

Description
-----------
CPIO is common inside RPMs and some initramfs images. AR is common as a
static-library container (``.a``) and is also used by ``.deb`` (handled
separately in :mod:`~re_unpacker.extractors.deb`).

Cross-platform behavior
-----------------------
- **Linux**: native ``cpio`` and ``ar`` (binutils) tools. cpio invoked
  with ``-idm --no-absolute-filenames -F <file> -D <dir>``; ar invoked
  with ``ar x`` after chdir into dest_dir.
- **Windows**: 7-Zip natively handles both CPIO and AR archive members
  via ``7z x``. The CPIO and AR formats appear in 7-Zip's manifest's
  FileExtensions list (verified against
  microsoft/winget-pkgs/manifests/7/7zip/7zip).

Both code paths produce equivalent on-disk output: archive members
written under ``ctx.dest_dir``.

Notes
-----
- ``cpio -idm --no-absolute-filenames -D <dir>`` extracts to the given
  directory. We use ``-F <file>`` to specify the input file rather than
  reading from stdin.
- GNU ``ar`` doesn't accept an ``-o`` flag; on Linux we ``cd`` into
  ``dest_dir`` via the subprocess helper's ``cwd`` so members land
  there. On Windows the 7-Zip ``-o<dir>`` form is used directly.

Version
-------
Part of RE-Unpacker 0.5.0. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

from ..detection import FileKind
from ..platform_compat import is_windows
from ..subprocess_utils import run_tool
from .base import Extractor, ExtractionContext, ExtractionResult


class CpioExtractor(Extractor):
    """Extractor for standalone CPIO archives (initramfs, etc.)."""

    name = "cpio"
    handles_kinds = frozenset({FileKind.CPIO})
    required_tools: tuple[str, ...] = (
        ("7z",) if is_windows() else ("cpio",)
    )
    priority = 100

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)

        if is_windows():
            # 7z handles CPIO natively. Use -y (yes to all prompts) and
            # -o<dest> (output dir, no space between -o and arg).
            argv = [
                ctx.tools.path_of("7z"),
                "x",
                "-y",
                f"-o{ctx.dest_dir}",
                str(ctx.source_path),
            ]
            tool_name = "7z"
            run_tool(
                argv, tool_name=tool_name,
                timeout=ctx.timeout_seconds, check=True,
                logger=ctx.logger, source_for_error=str(ctx.source_path),
            )
        else:
            # -i: extract, -d: create dirs as needed, -m: preserve mtime
            # -F: read from this file, --no-absolute-filenames: safety
            # -D: target directory
            argv = [
                ctx.tools.path_of("cpio"),
                "-idm",
                "--no-absolute-filenames",
                "-F", str(ctx.source_path),
                "-D", str(ctx.dest_dir),
            ]
            run_tool(
                argv, tool_name="cpio",
                timeout=ctx.timeout_seconds, check=True,
                logger=ctx.logger, source_for_error=str(ctx.source_path),
            )

        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )


class ArExtractor(Extractor):
    """Extractor for traditional ``ar`` archives (static libraries etc.).

    Note: DEB files are also ``ar`` archives, but :mod:`~re_unpacker.extractors.deb`
    handles them at higher priority.
    """

    name = "ar"
    handles_kinds = frozenset({FileKind.AR})
    required_tools: tuple[str, ...] = (
        ("7z",) if is_windows() else ("ar",)
    )
    priority = 100

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)

        if is_windows():
            # 7-Zip handles AR archives. Same invocation pattern as CPIO.
            argv = [
                ctx.tools.path_of("7z"),
                "x",
                "-y",
                f"-o{ctx.dest_dir}",
                str(ctx.source_path),
            ]
            run_tool(
                argv, tool_name="7z",
                timeout=ctx.timeout_seconds, check=True,
                logger=ctx.logger, source_for_error=str(ctx.source_path),
            )
        else:
            # GNU ar's "x" command writes members to the cwd.
            argv = [ctx.tools.path_of("ar"), "x", str(ctx.source_path)]
            run_tool(
                argv, tool_name="ar", cwd=ctx.dest_dir,
                timeout=ctx.timeout_seconds, check=True,
                logger=ctx.logger, source_for_error=str(ctx.source_path),
            )

        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )
