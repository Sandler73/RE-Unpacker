"""
.. module:: re_unpacker.extractors.pdf
    :synopsis: PDF extractors -- attached files, embedded objects, structure.

Description
-----------
promotes PDF from a terminal kind to an extractable kind. Two
extractors run as primaries on PDF input:

- :class:`PdfAttachmentExtractor` -- runs ``pdfdetach -saveall`` to copy
  every attached / embedded file out of the PDF. This is where malicious
  payloads commonly hide (PDFs are a popular polyglot delivery vector).
- :class:`PdfStructureExtractor` -- runs ``qpdf --qdf`` to produce a
  reorganized, parseable form of the PDF. The output is itself a PDF but
  with object streams unpacked, line endings normalized, and structure
  flat -- much easier for downstream tooling to walk.

Both run as primaries on the PDF kind. The orchestrator's "first
successful primary wins" semantics mean only one will produce the output
tree under the primary chain, but secondary extractors and the
recursion engine still see whatever each produced.

Notes
-----
- ``pdfdetach`` returns rc=0 even for PDFs with no attachments. We
  detect "no attachments" by checking whether ``-saveall`` produced any
  files in the destination directory; if not, we raise
  :class:`ExtractorNotApplicable` so the next primary gets a turn.
- ``qpdf --qdf`` always succeeds on a syntactically-valid PDF.
- Encrypted PDFs surface as ExtractorFailure with the tool's stderr;
  consistent with other "encrypted, no key" cases .

Execution parameters
--------------------
- Honor ``ctx.timeout_seconds``.

Examples
--------
::

    re-unpacker delivery.pdf -o /scratch/pdf/

Version
-------
Part of re-unpacker 0.4.10. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

from ..detection import FileKind
from ..exceptions import ExtractorNotApplicable
from ..subprocess_utils import run_tool
from .base import Extractor, ExtractionContext, ExtractionResult


class PdfAttachmentExtractor(Extractor):
    """Extract attached / embedded files from a PDF via ``pdfdetach``."""

    name = "pdfdetach"
    handles_kinds = frozenset({FileKind.PDF})
    required_tools = ("pdfdetach",)
    priority = 90

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            ctx.tools.path_of("pdfdetach"),
            "-saveall",
            "-o", str(ctx.dest_dir),
            str(ctx.source_path),
        ]
        run_tool(
            argv, tool_name="pdfdetach",
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        # If the PDF has no attachments, dest_dir will be empty after the
        # call. Treat that as "this primary is not applicable to this PDF"
        # so the next primary (qpdf structure) gets a turn.
        produced = list(ctx.dest_dir.iterdir())
        if not produced:
            raise ExtractorNotApplicable(
                f"pdfdetach: PDF contains no attached files ({ctx.source_path.name})",
                context={"reason": "no_pdf_attachments", "source": str(ctx.source_path)},
            )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
            files_produced=len(produced),
        )


class PdfStructureExtractor(Extractor):
    """Reorganize PDF via ``qpdf --qdf`` to make embedded streams accessible."""

    name = "qpdf"
    handles_kinds = frozenset({FileKind.PDF})
    required_tools = ("qpdf",)
    priority = 60  # Below pdfdetach: we prefer attached-file extraction first.

    def extract(self, ctx: ExtractionContext) -> ExtractionResult:
        ctx.dest_dir.mkdir(parents=True, exist_ok=True)
        outfile = ctx.dest_dir / (ctx.source_path.stem + ".qdf.pdf")
        argv = [
            ctx.tools.path_of("qpdf"),
            "--qdf",                        # Reorganize streams; stable output
            "--object-streams=disable",     # Flatten object streams
            "--",
            str(ctx.source_path),
            str(outfile),
        ]
        run_tool(
            argv, tool_name="qpdf",
            timeout=ctx.timeout_seconds, check=True,
            logger=ctx.logger, source_for_error=str(ctx.source_path),
        )
        return ExtractionResult(
            extractor_name=self.name, success=True, dest_dir=ctx.dest_dir,
            files_produced=1,
            notes=["qpdf --qdf produced reorganized PDF with object streams disabled"],
        )
