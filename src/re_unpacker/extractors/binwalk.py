"""
.. module:: re_unpacker.extractors.binwalk
    :synopsis: Last-resort fallback extractor using ``binwalk -Me``.

Description
-----------
When every format-specific extractor has failed on a binary we still
want to dump any embedded data signatures binwalk recognizes. This is
controlled by the ``--binwalk`` CLI flag (on by default per project
configuration). It's deliberately the lowest-priority extractor in the
registry so it only runs after dedicated tools have been tried.

Notes
-----
- ``binwalk -Me`` performs matryoshka extraction (recursive). We keep
  its recursion to depth 1 (we control recursion at the orchestrator
  level instead), so the output is predictable.
- binwalk writes to a ``_<name>.extracted`` directory adjacent to the
  input by default. We point it at ``--directory`` so output lands in
  ``dest_dir`` directly and leaves the input alone.
- Noisy / slow on large files. The orchestrator still applies the
  per-call timeout.

Version
-------
Part of re-unpacker 0.4.10. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

from ..detection import FileKind
from ..exceptions import ExtractorFailure, ExtractorNotApplicable
from ..subprocess_utils import run_tool
from .base import Extractor, ExtractionContext, ExtractionResult


class BinwalkExtractor(Extractor):
    """Last-resort fallback using ``binwalk -Me``."""

    name = "binwalk"
    handles_kinds = frozenset({
        FileKind.UNKNOWN_BINARY,
        FileKind.ELF,                # embedded data in ELFs
        FileKind.MACHO,
        FileKind.PE_EXECUTABLE,
        FileKind.PE_WIXBURN,
        FileKind.PE_NSIS,
        FileKind.PE_INNOSETUP,
        FileKind.PE_INSTALLSHIELD,
    })
    required_tools = ("binwalk",)
    priority = 20  # last-resort; all other extractors outrank it

    # binwalk output is often the *same* data that a successful primary extractor
    # already pulled out. We still mark it as producing extractable content so
    # nested discoveries get picked up.
    produces_extractable_content = True

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        # -M: matryoshka (recursive) + -e: extract.
        # We limit binwalk's own depth via -d 1 so we don't duplicate the
        # orchestrator's recursion (could explode combinatorially).
        argv = [
            ctx.tools.path_of("binwalk"),
            "-Me",
            "-d", "1",
            "--directory", str(ctx.dest_dir),
            str(ctx.source_path),
        ]
        try:
            run_tool(
                argv, tool_name="binwalk",
                timeout=ctx.timeout_seconds, check=True,
                logger=ctx.logger, source_for_error=str(ctx.source_path),
            )
        except ExtractorFailure as e:
            # binwalk returns rc=3 when no signatures of interest were found.
            # That's "not applicable", not a real failure.
            if e.returncode == 3:
                raise ExtractorNotApplicable(
                    f"binwalk: no signatures found in {ctx.source_path.name}",
                    context={"reason": "no_binwalk_signatures"},
                ) from e
            raise
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
            notes=["binwalk matryoshka extraction (d=1)"],
        )
