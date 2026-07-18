"""
.. module:: re_unpacker.extractors.legacy
    :synopsis: Extractors for legacy and niche unpack formats.

Description
-----------
Covers older or less common formats that still surface in real RE work:

- :class:`ArjExtractor` -- ARJ archives (DOS-era; still seen in older
  malware drops). Uses ``arj``.
- :class:`LhaExtractor` -- LHA / LZH archives (still common in some Asian
  software distributions). Uses ``lha`` (provided by the ``lhasa`` apt
  package).
- :class:`ArcExtractor` -- ARC / ARK archives (System Enhancement Associates
  format from the early DOS era). Uses ``nomarch``.
- :class:`TnefExtractor` -- Microsoft TNEF (``winmail.dat``) -- the
  rich-text MIME wrapper Outlook uses for non-plain replies. Uses ``tnef``.
- :class:`SharExtractor` -- POSIX shell archives (``.shar``). Uses
  ``unshar``. Genuinely runs the file through ``unshar`` which itself
  unpacks via ``/bin/sh``; we sandbox the cwd so the extracted content
  lands in our destination directory.
- :class:`UuencodedExtractor` -- uuencoded data (``.uu``, ``.uue``). Uses
  ``uudecode`` (sharutils).

Notes
-----
- Every tool is treated as best-effort. Failures bubble up as
  :class:`ExtractorFailure`; the orchestrator records them and tries the
  next extractor in the chain (typically falling through to ``unar`` or
  ``binwalk``).
- ``unshar`` runs shell code from the archive. This is by definition a
  code-execution path. We never run the user's input directly; we pass
  the file as a shar archive to ``unshar`` and run it from a sandbox
  cwd. RE workflows handling shar archives from untrusted sources should
  also use OS-level sandboxing (containers / namespaces); this extractor
  takes the same posture as the rest of the project (path-traversal
  audit on the output, but no further sandbox).

Execution parameters
--------------------
- All extractors honor ``ctx.timeout_seconds`` and the standard primary /
  fallback dispatch chain.

Examples
--------
::

    re-unpacker old_dropper.arj -o /scratch/arj/
    re-unpacker winmail.dat -o /scratch/winmail/

Version
-------
See :data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

from ..detection import FileKind
from ..subprocess_utils import run_tool
from .base import Extractor, ExtractionContext, ExtractionResult


# =============================================================================
# ARJ
# =============================================================================

class ArjExtractor(Extractor):
    """ARJ archive extractor using ``arj``."""

    name = "arj"
    handles_kinds = frozenset({FileKind.ARJ})
    required_tools = ("arj",)
    priority = 100

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        # arj x: extract with full paths; -y: yes to all prompts; -v: chatty
        # arj insists on running from a writable cwd; we use -y to silence
        # the "directory exists" prompt.
        argv = [
            ctx.tools.path_of("arj"), "x", "-y",
            str(ctx.source_path),
            str(ctx.dest_dir) + "/",
        ]
        run_tool(
            argv, tool_name="arj",
            cwd=ctx.dest_dir,
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )


# =============================================================================
# LHA / LZH
# =============================================================================

class LhaExtractor(Extractor):
    """LHA / LZH archive extractor using ``lha`` (provided by lhasa)."""

    name = "lha"
    handles_kinds = frozenset({FileKind.LHA})
    required_tools = ("lha",)
    priority = 100

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        # lhasa's lha CLI uses BSD-style options. e -- extract with directory
        # structure; -w specifies the output directory.
        argv = [
            ctx.tools.path_of("lha"),
            "xqw=" + str(ctx.dest_dir),
            str(ctx.source_path),
        ]
        run_tool(
            argv, tool_name="lha",
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )


# =============================================================================
# ARC / ARK
# =============================================================================

class ArcExtractor(Extractor):
    """ARC / ARK archive extractor using ``nomarch``."""

    name = "nomarch"
    handles_kinds = frozenset({FileKind.ARC})
    required_tools = ("nomarch",)
    priority = 100

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        # nomarch -U writes file content to stdout; the default extraction
        # mode writes files to the cwd. We chdir into dest_dir.
        argv = [ctx.tools.path_of("nomarch"), str(ctx.source_path)]
        run_tool(
            argv, tool_name="nomarch",
            cwd=ctx.dest_dir,
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )


# =============================================================================
# TNEF (winmail.dat)
# =============================================================================

class TnefExtractor(Extractor):
    """Microsoft TNEF extractor using ``tnef``."""

    name = "tnef"
    handles_kinds = frozenset({FileKind.TNEF})
    required_tools = ("tnef",)
    priority = 100

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        # tnef -C <dir> extracts attachments into the directory.
        argv = [
            ctx.tools.path_of("tnef"),
            "-C", str(ctx.dest_dir),
            str(ctx.source_path),
        ]
        run_tool(
            argv, tool_name="tnef",
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )


# =============================================================================
# Shell archives (.shar)
# =============================================================================

class SharExtractor(Extractor):
    """Shell archive extractor using ``unshar`` (sharutils).

    SECURITY NOTE: unshar runs the archive's content through ``/bin/sh``.
    This is a code-execution path by design (that's what shar archives are).
    We constrain the cwd so output lands in dest_dir; we do NOT add further
    sandboxing. Use OS-level sandbox if extracting shar archives from
    untrusted sources.
    """

    name = "unshar"
    handles_kinds = frozenset({FileKind.SHAR})
    required_tools = ("unshar",)
    priority = 100
    # Shell archives produce a regular file tree; no further extraction
    # specific to shar.
    produces_extractable_content = True

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        # unshar reads the archive from stdin or as an arg; -d sets dest dir
        # for the embedded shell to chdir into before running.
        argv = [
            ctx.tools.path_of("unshar"),
            "-d", str(ctx.dest_dir),
            str(ctx.source_path),
        ]
        run_tool(
            argv, tool_name="unshar",
            cwd=ctx.dest_dir,
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
            notes=["unshar invokes /bin/sh on the archive's contents"],
        )


# =============================================================================
# uuencoded data
# =============================================================================

class UuencodedExtractor(Extractor):
    """uudecode-based extractor for ``.uu`` / ``.uue`` files."""

    name = "uudecode"
    handles_kinds = frozenset({FileKind.UUENCODED})
    required_tools = ("uudecode",)
    priority = 100

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        # uudecode writes to a file named in the encoded data's "begin" line
        # by default. -p prints to stdout instead, but we want the original
        # filename preserved -- run from cwd=dest_dir.
        argv = [
            ctx.tools.path_of("uudecode"),
            str(ctx.source_path),
        ]
        run_tool(
            argv, tool_name="uudecode",
            cwd=ctx.dest_dir,
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )


# =============================================================================
# unar (broad-coverage fallback for many formats)
# =============================================================================

class UnarFallbackExtractor(Extractor):
    """The Unarchiver -- broad-coverage fallback for many formats.

    ``unar`` (from the ``unar`` apt package) understands a very wide set of
    archive formats including StuffIt SIT/SITX, ALZ, ACE, RAR4/RAR5, NSIS
    and InnoSetup variants, classic Mac archives, and several DOS-era
    formats. We register it at lower priority than format-specific tools
    so it serves as a fallback / broad-coverage option.
    """

    name = "unar"
    # Wide coverage; primary for the Apple/Korean formats that have no
    # other tool here, fallback for the rest.
    handles_kinds = frozenset({
        # Primary (no other extractor):
        FileKind.STUFFIT, FileKind.ALZ, FileKind.ACE,
        # Fallback for these (lower priority than dedicated tools):
        FileKind.RAR, FileKind.SEVENZ, FileKind.ZIP,
        FileKind.LHA, FileKind.ARJ,
        FileKind.PE_NSIS, FileKind.PE_INNOSETUP,
    })
    required_tools = ("unar",)
    priority = 55  # Below 7z (60) so 7z wins fallback ties on RAR/ZIP/etc.

    def __init__(self) -> None:
        super().__init__()
        # Priority calibration:
        # - STUFFIT / ALZ / ACE: nothing else handles these, so unar is the
        #   only option regardless of its priority value.
        # - RAR / SEVENZ / ZIP / LHA / ARJ / PE_NSIS / PE_INNOSETUP: these
        #   have dedicated extractors at higher priority. unar runs only
        #   if all of them fail or are unavailable, which is the desired
        #   broad-coverage fallback behavior.

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        # unar -o <dir> -f -q (force-overwrite, quiet)
        argv = [
            ctx.tools.path_of("unar"),
            "-o", str(ctx.dest_dir),
            "-f",  # force overwrite without prompt
            "-q",  # quiet
            str(ctx.source_path),
        ]
        run_tool(
            argv, tool_name="unar",
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
        )
