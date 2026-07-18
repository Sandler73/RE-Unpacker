"""
.. module:: re_unpacker.verifiers.base
    :synopsis: Abstract Verifier base class, VerifierResult dataclass, and registry.

Description
-----------
Every signature/integrity verifier implements :class:`Verifier`. The
:class:`VerifierRegistry` enumerates registered verifiers; the orchestrator
asks each verifier ``applies_to(file_entry) -> bool`` and runs ``verify``
on those that return True.

Notes
-----
- Verifiers MUST be best-effort: any uncaught exception or tool failure is
  caught at the orchestrator boundary and recorded as
  ``performed=true, valid=null, error="<reason>"``. The run never aborts
  due to a verifier failure.
- A verifier's ``required_tools`` are checked via the tool registry; if any
  tool is missing, the verifier is silently filtered (no manifest entry).
- ``timeout_seconds`` argument to :meth:`verify` is the per-run cap from
  ``--enrich-timeout``. Verifier implementations pass it down to the
  underlying subprocess invocation.

Version
-------
Part of re-unpacker 0.4.10. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import abc
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ..manifest import FileEntry
from ..tools import ToolRegistry


# =============================================================================
# Result dataclass
# =============================================================================


@dataclass
class VerifierResult:
    """One verifier's outcome for one file.

    Field semantics:

    - ``performed``: True iff the verifier was invoked. False when the
      verifier didn't apply to this kind, was filtered out for missing
      tools, or was skipped for any other reason.
    - ``applicable``: True iff :meth:`Verifier.applies_to` returned True.
    - ``signed``: True iff the file was found to carry a signature of the
      type this verifier checks. None when not performed.
    - ``valid``: True iff the signature was both present AND verified
      cleanly. None when ``signed`` is None or False.
    - ``signer``: human-readable signer identity (Common Name, key ID, etc.)
      when extractable. None otherwise.
    - ``error``: populated on timeout or tool failure. Examples: "timeout",
      "tool_missing", "tool_returned_nonzero", "parse_error".
    - ``duration_seconds``: wall-clock cost of this verifier's check.

    The dict produced by :func:`dataclasses.asdict` is what gets stored in
    :attr:`FileEntry.verification` and serialized to manifest.json.
    """
    verifier_name: str
    performed: bool = False
    applicable: bool = False
    signed: bool | None = None
    valid: bool | None = None
    signer: str | None = None
    error: str | None = None
    duration_seconds: float = 0.0


# =============================================================================
# Verifier ABC
# =============================================================================


class Verifier(abc.ABC):
    """Abstract base class for all signature/integrity verifiers.

    Concrete subclasses must override :attr:`name`, :attr:`required_tools`,
    :meth:`applies_to`, and :meth:`verify`.
    """

    #: Stable identifier used in manifest output and log messages.
    name: str = "abstract"

    #: External tools required for this verifier to be available. The
    #: orchestrator silently filters verifiers whose tools aren't all on
    #: PATH (consult the ToolRegistry).
    required_tools: tuple[str, ...] = ()

    @abc.abstractmethod
    def applies_to(self, file_entry: FileEntry) -> bool:
        """Return True if this verifier should be invoked for ``file_entry``.

        Typically dispatches on ``file_entry.kind``, sometimes also on
        path / signals / mime_type. Should be cheap (no I/O).
        """
        raise NotImplementedError

    @abc.abstractmethod
    def verify(
        self,
        file_entry: FileEntry,
        *,
        timeout_seconds: int,
        logger: logging.Logger,
    ) -> VerifierResult:
        """Run verification on ``file_entry``.

        Implementations should:
        - Construct a :class:`VerifierResult` with ``verifier_name=self.name``,
          ``applicable=True``, and a fresh ``time.monotonic()`` timer.
        - Invoke the underlying tool(s) with the per-run timeout.
        - Parse the tool output and populate ``signed`` / ``valid`` / ``signer``.
        - Catch :class:`subprocess.TimeoutExpired` and record ``error="timeout"``.
        - Catch any other exception, log it, and record ``error="<class>"``.
        - Set ``duration_seconds`` from the timer before returning.

        The orchestrator handles the case where ``applies_to`` is False
        (it never calls ``verify``); implementations don't need to repeat
        that check.
        """
        raise NotImplementedError


# =============================================================================
# Registry
# =============================================================================


@dataclass
class VerifierRegistry:
    """Collection of available verifiers, filtered by tool availability."""

    _verifiers: list[Verifier] = field(default_factory=list)

    def register(self, verifier: Verifier) -> None:
        self._verifiers.append(verifier)

    def all(self) -> Iterable[Verifier]:
        return tuple(self._verifiers)

    def applicable_for(
        self,
        file_entry: FileEntry,
        tools: ToolRegistry,
    ) -> list[Verifier]:
        """Return the subset of verifiers that both apply AND are available.

        "Apply" = ``applies_to(file_entry)`` returns True.
        "Available" = every name in ``required_tools`` is present in
        ``tools``.

        The two filters are AND'd here so the orchestrator gets a single
        clean list to iterate over. Verifiers that are inapplicable OR
        unavailable produce no manifest entry at all.
        """
        out: list[Verifier] = []
        for v in self._verifiers:
            if not v.applies_to(file_entry):
                continue
            if not all(tools.have(t) for t in v.required_tools):
                continue
            out.append(v)
        return out


def build_default_verifier_registry() -> VerifierRegistry:
    """Build the canonical verifier registry.

    Imports each verifier module and registers concrete instances. The
    registry is built fresh per run; no global state.
    """
    registry = VerifierRegistry()

    # Import here to avoid circular imports at module load time.
    from .gpg import GpgVerifier
    from .deb import DebsigsVerifier, DpkgSigVerifier, DebsumsVerifier
    from .rpm import RpmVerifier
    from .apk import ApkSignerVerifier
    from .pe import OssLsignCodeVerifier
    # Windows-native Authenticode verifiers. Filtered on Linux
    # automatically because their required_tools (powershell, signtool)
    # are absent from TOOL_PACKAGE_HINTS_LINUX.
    from .windows_authenticode import (
        PowerShellAuthenticodeVerifier, SigntoolVerifier,
    )

    for v in (
        GpgVerifier(),
        DebsigsVerifier(),
        DpkgSigVerifier(),
        DebsumsVerifier(),
        RpmVerifier(),
        ApkSignerVerifier(),
        OssLsignCodeVerifier(),
        # Windows-native (auto-filtered on Linux):
        PowerShellAuthenticodeVerifier(),
        SigntoolVerifier(),
    ):
        registry.register(v)

    return registry
