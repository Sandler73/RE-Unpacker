"""
.. module:: re_unpacker.verifiers
    :synopsis: Subsystem B: per-file signature/integrity verification.

Description
-----------
Verifiers run AFTER extraction succeeds, on each file in the output tree.
They check signatures, integrity, and provenance. Verifier results are
recorded in the new ``verification`` field on :class:`FileEntry` and
appear in both the structured manifest and the human-facing summary
report.

Always-on best-effort: there is no opt-out flag. Verifiers that don't
apply to a file's kind silently record ``performed=false``. Verifiers
that ran but found no signature record ``signed=false``. Verifiers that
found a valid signature record ``signed=true, valid=true, signer="..."``.

Architecture mirrors the extractor pattern:
- :mod:`base` -- abstract :class:`Verifier` ABC + :class:`VerifierResult` dataclass + registry
- :mod:`gpg`  -- GpgVerifier (detached .sig / .asc files)
- :mod:`deb`  -- DebsigsVerifier, DpkgSigVerifier, DebsumsVerifier
- :mod:`rpm`  -- RpmVerifier (rpm -K)
- :mod:`apk`  -- ApkSignerVerifier
- :mod:`pe`   -- OssLsignCodeVerifier (Authenticode signatures on PE / MSI / CAT)

Each verifier honors ``--enrich-timeout`` (default 30s, configurable per
run). Timeouts and tool failures are recorded with ``error="timeout"`` or
``error="<reason>"`` so downstream pipelines can distinguish "verifier
ran cleanly and found nothing" from "verifier broke".

Version
-------
See :data:`re_unpacker.constants.VERSION` (added in 0.3.2).
"""

from .base import (
    Verifier,
    VerifierRegistry,
    VerifierResult,
    build_default_verifier_registry,
)

__all__ = [
    "Verifier",
    "VerifierRegistry",
    "VerifierResult",
    "build_default_verifier_registry",
]
