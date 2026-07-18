"""
.. module:: re_unpacker.extractors.cab
    :synopsis: Microsoft Cabinet (.cab) extractor (cross-platform).

Description
-----------
Microsoft Cabinet archive extractor. Cross-platform behavior:

- **Linux**: prefer ``cabextract`` (from the cabextract apt package); it
  handles the full feature set including multi-disk cabinets. 7-Zip is
  a capable fallback but occasionally trips on older LZX compression
  modes.
- **Windows**: use the built-in ``expand.exe`` (present on every Windows
  install since the DOS era). Invoked as ``expand -F:* <file> <dest>``
  to extract all members. ``expand.exe`` natively handles cabinets
  including LZX, MSZIP, and Quantum compression. cabextract is not
  packaged for winget; expand is the canonical Windows tool.

Both code paths produce the same on-disk output: the cabinet's member
files, with directory structure preserved, written under
``ctx.dest_dir``. The orchestrator and manifest layer see no difference.

Version
-------
See :data:`re_unpacker.constants.VERSION`. Cross-platform support added
in v0.4.0.
"""

from __future__ import annotations

from ..detection import FileKind
from ..platform_compat import is_windows
from ..subprocess_utils import run_tool
from .base import Extractor, ExtractionContext, ExtractionResult


class CabExtractor(Extractor):
    """Primary CAB extractor.

    Uses ``cabextract`` on Linux, ``expand.exe`` on Windows. Same
    ``required_tools`` mechanism either way; the orchestrator sees a
    single primary extractor for the CAB kind regardless of platform.
    """

    name = "cabextract"
    handles_kinds = frozenset({FileKind.CAB})
    # Platform-aware: resolved at class-body load time. Module import is
    # the one place where platform constancy is guaranteed for the rest
    # of the process lifetime, so this is safe.
    required_tools: tuple[str, ...] = (
        ("expand",) if is_windows() else ("cabextract",)
    )
    priority = 100

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)

        if is_windows():
            # expand.exe -F:<filter> <source> <dest>
            # The "*" filter means extract all files. The destination must
            # already exist (which mkdir above guarantees). Quiet by default.
            argv = [
                ctx.tools.path_of("expand"),
                "-F:*",
                str(ctx.source_path),
                str(ctx.dest_dir),
            ]
            tool_name = "expand"
        else:
            argv = [
                ctx.tools.path_of("cabextract"),
                "-d", str(ctx.dest_dir),   # output dir
                "-q",                      # quiet
                str(ctx.source_path),
            ]
            tool_name = "cabextract"

        run_tool(
            argv, tool_name=tool_name,
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )
