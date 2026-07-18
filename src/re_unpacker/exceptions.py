"""
.. module:: re_unpacker.exceptions
    :synopsis: Custom exception hierarchy for re-unpacker.

Description
-----------
Defines a precise, catchable exception tree so callers (orchestrator,
extractors, reporting) can distinguish fatal from recoverable failures and
attach actionable context. All exceptions chain via ``raise ... from e`` in
the callers, so tracebacks retain root cause information.

Hierarchy::

    UnpackerError (base)
    |-- ValidationError input/CLI validation failed
    |-- ToolMissingError required system tool not installed
    |-- ExtractionError a single extraction failed (recoverable)
    | |-- ExtractorFailure extractor returned non-zero / bad output
    | |-- ExtractorTimeout extractor exceeded wall-clock timeout
    |-- SafetyLimitExceeded size/file-count/depth cap tripped
    |-- PathTraversalError extracted path escaped output root

Notes
-----
- ``ExtractionError`` and its subclasses are expected to be caught by the
  orchestrator and logged as run-level errors. They must NOT abort the run.
- ``ValidationError`` and ``SafetyLimitExceeded`` at the top level DO abort
  the run (config is wrong or the user's limits were hit).

Version
-------
Part of re-unpacker 0.4.10. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations


class UnpackerError(Exception):
    """Base class for all re-unpacker exceptions."""

    def __init__(self, message: str, *, context: dict | None = None) -> None:
        super().__init__(message)
        self.message: str = message
        self.context: dict = dict(context) if context else {}

    def __str__(self) -> str:
        if self.context:
            ctx = ", ".join(f"{k}={v!r}" for k, v in self.context.items())
            return f"{self.message} [{ctx}]"
        return self.message


class ValidationError(UnpackerError):
    """CLI argument or input validation failed. Fatal at top level."""


class ToolMissingError(UnpackerError):
    """A required external tool is not installed / not on PATH."""

    def __init__(
        self,
        tool_name: str,
        *,
        package_hint: str | None = None,
        context: dict | None = None,
    ) -> None:
        msg = f"Required tool '{tool_name}' not found on PATH"
        if package_hint:
            msg += f" (install via Kali package: {package_hint})"
        super().__init__(msg, context=context)
        self.tool_name: str = tool_name
        self.package_hint: str | None = package_hint


class ExtractionError(UnpackerError):
    """A single extraction job failed. Recoverable; run continues."""


class ExtractorNotApplicable(ExtractionError):
    """Raised when an extractor determines the input isn't one it handles.

    This is an *expected* dispatch-chain event -- not a true failure. The
    orchestrator catches it silently and moves on to the next extractor
    without recording a manifest error entry. Examples:

    - :class:`UpxExtractor` on a binary that isn't UPX-packed.
    - :class:`BinwalkExtractor` returning rc=3 (no signatures found).
    """


class ExtractorFailure(ExtractionError):
    """Extractor subprocess returned non-zero or produced malformed output."""

    def __init__(
        self,
        extractor: str,
        source: str,
        *,
        returncode: int | None = None,
        stderr: str | None = None,
        context: dict | None = None,
    ) -> None:
        msg = f"Extractor '{extractor}' failed on '{source}'"
        if returncode is not None:
            msg += f" (rc={returncode})"
        super().__init__(msg, context=context)
        self.extractor: str = extractor
        self.source: str = source
        self.returncode: int | None = returncode
        self.stderr: str | None = stderr


class ExtractorTimeout(ExtractionError):
    """Extractor exceeded the configured wall-clock timeout."""

    def __init__(
        self,
        extractor: str,
        source: str,
        timeout_seconds: int,
        *,
        context: dict | None = None,
    ) -> None:
        msg = (
            f"Extractor '{extractor}' timed out after {timeout_seconds}s "
            f"on '{source}'"
        )
        super().__init__(msg, context=context)
        self.extractor: str = extractor
        self.source: str = source
        self.timeout_seconds: int = timeout_seconds


class SafetyLimitExceeded(UnpackerError):
    """A configured safety limit (size, file count, depth) was exceeded."""

    def __init__(
        self,
        limit_name: str,
        limit_value: int,
        observed: int,
        *,
        context: dict | None = None,
    ) -> None:
        msg = (
            f"Safety limit '{limit_name}' exceeded: "
            f"observed={observed} > limit={limit_value}"
        )
        super().__init__(msg, context=context)
        self.limit_name: str = limit_name
        self.limit_value: int = limit_value
        self.observed: int = observed


class PathTraversalError(UnpackerError):
    """An extracted path escaped the permitted output root."""

    def __init__(
        self,
        path: str,
        output_root: str,
        *,
        context: dict | None = None,
    ) -> None:
        msg = (
            f"Extracted path escapes output root: path={path!r}, "
            f"root={output_root!r}"
        )
        super().__init__(msg, context=context)
        self.path: str = path
        self.output_root: str = output_root
