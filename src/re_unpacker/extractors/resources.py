"""
.. module:: re_unpacker.extractors.resources
    :synopsis: PE resource and ELF section extractors.

Description
-----------
User opted into resource extraction. Two extractors:

- :class:`PeResourceExtractor` -- uses ``wrestool`` (from ``icoutils``)
  to dump every resource in a PE executable (icons, version info,
  manifests, string tables, embedded binaries, etc.) into ``dest_dir``.
  Produces individual files that the orchestrator can then recurse into
  (an embedded MSI or ZIP in a resource slot will be discovered and
  extracted on the next pass).
- :class:`ElfSectionExtractor` -- uses ``readelf`` to enumerate sections
  and ``objcopy --dump-section`` to save each non-empty section. ELFs
  don't have a standardized "resources" region, but analysts frequently
  want ``.data``, ``.rodata``, ``.init_array``, and any ``.note.*``
  sections for inspection.

Notes
-----
- Both extractors produce files that are NOT further archives in most
  cases -- ``produces_extractable_content`` stays True so the orchestrator
  re-detects each output and only recurses if something extractable is
  found. No infinite loops: the resource files are regular binaries,
  not PE/ELF, so re-detection classifies them as UNKNOWN_BINARY /
  UNKNOWN_TEXT and recursion stops.
- These run in *addition* to (not instead of) the format-specific
  extractor, via a separate orchestrator dispatch pass. So a PE NSIS
  installer will be unpacked by NSIS AND have its resources dumped.

Version
-------
Part of re-unpacker 0.4.10. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..detection import FileKind
from ..exceptions import ExtractorFailure
from ..subprocess_utils import run_tool
from .base import Extractor, ExtractionContext, ExtractionResult


# =============================================================================
# PE resources (wrestool)
# =============================================================================

class PeResourceExtractor(Extractor):
    """Dumps every PE resource via ``wrestool``."""

    name = "wrestool"
    handles_kinds = frozenset({
        FileKind.PE_EXECUTABLE, FileKind.PE_NSIS, FileKind.PE_INNOSETUP,
        FileKind.PE_INSTALLSHIELD, FileKind.PE_WIXBURN,
    })
    required_tools = ("wrestool",)
    # Low-ish priority -- runs *after* the installer extractor. Since a PE's
    # "kind" is specific (NSIS/Inno/etc.) we explicitly want this dispatched
    # *in addition to*, not instead of, those. The orchestrator handles that
    # via its "run every applicable resource-kind extractor" pass.
    priority = 30

    # Runs alongside (not instead of) the primary extractor for this kind.
    is_secondary = True

    # Resource files dumped are mostly not themselves archives (some may be
    # embedded installers -- those DO get recursed into).
    produces_extractable_content = True

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        out_dir = ctx.dest_dir / "_pe_resources"
        out_dir.mkdir(parents=True, exist_ok=True)
        # wrestool -x: extract; -o: output dir; -a: all resources.
        argv = [
            ctx.tools.path_of("wrestool"),
            "-x",
            "-o", str(out_dir),
            str(ctx.source_path),
        ]
        try:
            run_tool(
                argv, tool_name="wrestool",
                timeout=min(ctx.timeout_seconds, 600),
                check=True, logger=ctx.logger,
                source_for_error=str(ctx.source_path),
            )
        except ExtractorFailure as e:
            # wrestool returns non-zero on files with no resources; treat as
            # "nothing to do" rather than a hard failure.
            if e.returncode in (0, 1) or (
                e.stderr and "no resources" in (e.stderr or "").lower()
            ):
                return ExtractionResult(
                    extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
                    notes=["no PE resources found"],
                )
            raise
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
            notes=["dumped PE resources via wrestool"],
        )


# =============================================================================
# ELF sections (readelf + objcopy)
# =============================================================================

# Sections worth dumping for RE purposes. We filter out NOBITS / SHT_NULL and
# anything zero-size; everything else is fair game.
# A denylist of sections that are rarely useful and add noise (e.g. massive
# .text that's already the whole binary) -- analysts can still dump them from
# the original with objcopy if needed.
_ELF_SECTION_DENYLIST: frozenset[str] = frozenset({
    ".comment",        # toolchain version strings, tiny & noisy
    ".shstrtab",       # section-header-names string table
    ".strtab",         # symbol name string table
    ".symtab",         # symbol table (binary)
    ".dynsym",
    ".dynstr",
    ".gnu.version",
    ".gnu.version_r",
    ".gnu.hash",
    ".hash",
    ".eh_frame_hdr",
    ".eh_frame",
    ".got", ".got.plt", ".plt", ".plt.got",
    ".rela.dyn", ".rela.plt", ".rel.dyn", ".rel.plt",
    ".interp",
})


# Matches the section-headers table in ``readelf -SW`` output.
# Format (headers line): " [Nr] Name Type ..."
# Data lines: " [ 0] NULL ..."
_RE_SECTION_LINE = re.compile(
    r"^\s*\[\s*(?P<nr>\d+)\]\s+"
    r"(?P<name>\S*)?\s+"
    r"(?P<type>\S+)\s+"
    r"(?P<addr>[0-9a-fA-F]+)\s+"
    r"(?P<offset>[0-9a-fA-F]+)\s+"
    r"(?P<size>[0-9a-fA-F]+)"
)


class ElfSectionExtractor(Extractor):
    """Dumps non-trivial ELF sections via ``objcopy --dump-section``."""

    name = "objcopy (ELF sections)"
    handles_kinds = frozenset({FileKind.ELF, FileKind.MACHO})
    required_tools = ("objcopy", "readelf")
    priority = 30
    is_secondary = True
    produces_extractable_content = True

    def _list_sections(self, ctx: ExtractionContext) -> list[tuple[str, int, str]]:
        """Return ``[(name, size, type), …]`` from ``readelf -SW``.

        Empty and denylisted sections are filtered out.
        """
        argv = [
            ctx.tools.path_of("readelf"),
            "-S", "-W",
            str(ctx.source_path),
        ]
        result = run_tool(
            argv, tool_name="readelf",
            timeout=min(ctx.timeout_seconds, 120),
            check=False, logger=ctx.logger,
            source_for_error=str(ctx.source_path),
        )
        if result.returncode != 0:
            return []

        sections: list[tuple[str, int, str]] = []
        for line in result.stdout_text.splitlines():
            m = _RE_SECTION_LINE.match(line)
            if not m:
                continue
            name = m.group("name") or ""
            stype = m.group("type")
            try:
                size = int(m.group("size"), 16)
            except ValueError:
                continue
            if not name or size == 0:
                continue
            if stype.upper() in ("NULL", "NOBITS"):
                continue
            if name in _ELF_SECTION_DENYLIST:
                continue
            sections.append((name, size, stype))
        return sections

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        # Mach-O isn't supported by GNU objcopy in any reliable way; skip
        # with a soft "nothing to do" rather than failing the whole chain.
        # Kind is passed indirectly; we detect by magic.
        try:
            with open(ctx.source_path, "rb") as f:
                head = f.read(4)
        except OSError:
            head = b""
        if not head.startswith(b"\x7fELF"):
            return ExtractionResult(
                extractor_name=self.name, success=True,
                dest_dir=ctx.dest_dir,
                notes=["skipped: not an ELF (Mach-O section dump not supported)"],
            )

        out_dir = ctx.dest_dir / "_elf_sections"
        out_dir.mkdir(parents=True, exist_ok=True)
        sections = self._list_sections(ctx)
        if not sections:
            return ExtractionResult(
                extractor_name=self.name, success=True,
                dest_dir=ctx.dest_dir,
                notes=["no ELF sections to dump"],
            )

        objcopy = ctx.tools.path_of("objcopy")
        dumped = 0
        for name, size, _stype in sections:
            # Filename sanitization: replace '/' etc. (ELF section names are
            # usually just dots + alnum, but defensive).
            safe = name.replace("/", "_").replace("\\", "_").lstrip(".")
            if not safe:
                safe = "section"
            out_file = out_dir / f"{safe}.bin"
            argv = [
                objcopy,
                f"--dump-section={name}={out_file}",
                str(ctx.source_path),
                "/dev/null",  # objcopy requires an output file arg even with --dump-section
            ]
            try:
                run_tool(
                    argv, tool_name="objcopy",
                    timeout=min(ctx.timeout_seconds, 120),
                    check=True, logger=ctx.logger,
                    source_for_error=str(ctx.source_path),
                )
                dumped += 1
            except ExtractorFailure as e:
                ctx.logger.debug(
                    "objcopy dump-section failed for %s: %s", name, e
                )
                continue

        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
            notes=[f"dumped {dumped} of {len(sections)} ELF sections"],
        )
