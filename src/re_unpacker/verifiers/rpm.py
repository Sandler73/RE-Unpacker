"""
.. module:: re_unpacker.verifiers.rpm
    :synopsis: RPM signature/integrity verification via ``rpm -K``.

Description
-----------
``rpm -K <file>`` (also written ``rpm --checksig <file>``) checks both
the RPM header MD5/SHA-256 digest AND the GPG signature embedded in the
RPM, in a single invocation. Output format on success::

    /path/to/file.rpm: digests signatures OK

On signed-but-invalid::

    /path/to/file.rpm: digests OK signatures NOT OK

On unsigned (digests valid only)::

    /path/to/file.rpm: digests OK

Notes
-----
- ``rpm -K`` checks the header digest and the embedded GPG signature in one
  invocation, so a single call distinguishes corruption from a signing
  problem.
- Signature validation depends on the invoking user's RPM keyring. A package
  signed by a key that was never imported reports as untrusted rather than
  invalid, which is a keyring gap, not a package defect.

Version
-------
Part of RE-Unpacker 0.5.0. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import logging
import re
import subprocess
import time
from pathlib import Path

from ..manifest import FileEntry
from ..subprocess_utils import run_tool
from ..exceptions import ExtractorTimeout, ExtractorFailure
from .base import Verifier, VerifierResult


# Patterns to interpret rpm -K output. The exact wording varies between
# rpm 4.x versions but the key phrases are stable.
_RPM_OK_PATTERN = re.compile(rb"signatures (?:OK|NOTRUSTED)", re.IGNORECASE)
_RPM_NOT_OK_PATTERN = re.compile(rb"signatures NOT OK", re.IGNORECASE)
_RPM_NO_SIG_PATTERN = re.compile(
    rb"\bdigests OK\b(?!.*signatures)", re.IGNORECASE
)


class RpmVerifier(Verifier):
    """Verify RPM signature + digest via ``rpm -K``."""

    name = "rpm-K"
    required_tools = ("rpm",)

    def applies_to(self, file_entry: FileEntry) -> bool:
        return file_entry.kind == "RPM"

    def verify(
        self,
        file_entry: FileEntry,
        *,
        timeout_seconds: int,
        logger: logging.Logger,
    ) -> VerifierResult:
        result = VerifierResult(
            verifier_name=self.name, performed=True, applicable=True,
        )
        start = time.monotonic()

        try:
            run_result = run_tool(
                ["rpm", "-K", file_entry.path],
                tool_name="rpm",
                timeout=timeout_seconds,
                check=False,
                logger=logger,
            )
        except ExtractorTimeout:
            result.error = "timeout"
            result.duration_seconds = time.monotonic() - start
            return result
        except (ExtractorFailure, subprocess.SubprocessError, OSError) as e:
            result.error = type(e).__name__
            result.duration_seconds = time.monotonic() - start
            return result

        # rpm -K writes its result to stdout, NOT stderr.
        combined = (run_result.stdout or b"") + (
            run_result.stderr or b""
        )

        if _RPM_NOT_OK_PATTERN.search(combined):
            result.signed = True
            result.valid = False
            result.error = "bad_signature"
        elif _RPM_OK_PATTERN.search(combined):
            result.signed = True
            result.valid = True
        elif _RPM_NO_SIG_PATTERN.search(combined):
            # Digests valid, but no GPG signature was present.
            result.signed = False
            result.valid = None
        else:
            # Unrecognized output; record as not performed effectively.
            result.error = "parse_error"

        result.duration_seconds = time.monotonic() - start
        return result
