"""
.. module:: re_unpacker.extractors.android
    :synopsis: Android APK extractors (apktool resource decoding).

Description
-----------
APKs are ZIP files at the byte level (which v0.1.x already handles via
:class:`ZipExtractor`), but the AndroidManifest.xml and the resources.arsc
inside are *binary-encoded* XML / resource tables that look like binary
blobs to a plain ZIP extractor. ``apktool`` decodes:

- AndroidManifest.xml -> human-readable XML
- res/ resources -> human-readable XML / .9.png slices etc.
- classes.dex -> smali (disassembled Dalvik) under smali/

In :class:`ApktoolExtractor` runs as a higher-priority primary
than :class:`ZipExtractor` for the APK kind, so apktool's decoded layout
becomes the canonical extraction output. The ZIP extractor remains as a
fallback at priority 60 if apktool is missing.

Notes
-----
- apktool is a Java tool wrapped by a shell script. It can be slow on
  large APKs; honor ``ctx.timeout_seconds``.
- apktool's ``d`` (decode) subcommand defaults to creating a directory
  named after the APK base name in the cwd. We pass ``-o <dest>`` and
  ``-f`` (force overwrite) so the output lands in our dest_dir.
- We do NOT use ``--no-src`` -- the smali output is the most useful
  product for RE triage. Set ``--only-main-classes`` if you want to
  speed it up at the cost of completeness; out of scope for.
- apktool encrypted-APK / corrupted-APK failures surface as
  :class:`ExtractorFailure`; the orchestrator's chain falls through to
  :class:`ZipExtractor` at priority 60.

Execution parameters
--------------------
- Honor ``ctx.timeout_seconds`` (apktool can take 1+ minute on a 50 MB APK).

Examples
--------
::

    re-unpacker app-release.apk -o /scratch/apk/

Version
-------
Part of re-unpacker 0.4.10. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

from ..detection import FileKind
from ..subprocess_utils import run_tool
from .base import Extractor, ExtractionContext, ExtractionResult


class ApktoolExtractor(Extractor):
    """APK decoder using ``apktool d``."""

    name = "apktool"
    handles_kinds = frozenset({FileKind.APK})
    required_tools = ("apktool",)
    # Higher than ZipExtractor (80) so apktool's decoded layout is preferred
    # whenever apktool is available. Falls through to ZipExtractor (which
    # also handles APK as a ZIP) at priority 80 if apktool is missing.
    priority = 90

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        # apktool refuses if dest_dir exists; we use -f to force overwrite.
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            ctx.tools.path_of("apktool"), "d",
            "-f",                              # force overwrite
            "-o", str(ctx.dest_dir),
            "--",
            str(ctx.source_path),
        ]
        run_tool(
            argv, tool_name="apktool",
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
            notes=[
                "apktool produced AndroidManifest.xml (decoded), "
                "res/ (decoded resources), and smali/ (disassembled DEX classes)",
            ],
        )
