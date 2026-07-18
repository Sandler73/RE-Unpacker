"""
.. module:: re_unpacker.verifiers.apk
    :synopsis: Android APK signature verification via ``apksigner``.

Description
-----------
``apksigner verify --verbose <file.apk>`` checks v1 (JAR-style), v2, v3
APK signatures. Output on success::

    Verifies
    Verified using v1 scheme (JAR signing): true
    Verified using v2 scheme (APK Signature Scheme v2): true
    Verified using v3 scheme (APK Signature Scheme v3): false
    Number of signers: 1

Version
-------
Added in 0.3.2.
"""

from __future__ import annotations

import logging
import re
import subprocess
import time

from ..manifest import FileEntry
from ..subprocess_utils import run_tool
from ..exceptions import ExtractorTimeout, ExtractorFailure
from .base import Verifier, VerifierResult


_APKSIGNER_VERIFIES = re.compile(rb"^Verifies\b", re.MULTILINE)
_APKSIGNER_DOES_NOT = re.compile(rb"^DOES NOT VERIFY\b", re.MULTILINE)


class ApkSignerVerifier(Verifier):
    """Verify APK signatures via ``apksigner verify``."""

    name = "apksigner"
    required_tools = ("apksigner",)

    def applies_to(self, file_entry: FileEntry) -> bool:
        return file_entry.kind == "APK"

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
                ["apksigner", "verify", "--verbose", file_entry.path],
                tool_name="apksigner",
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

        combined = (run_result.stdout or b"") + (
            run_result.stderr or b""
        )

        if _APKSIGNER_VERIFIES.search(combined):
            result.signed = True
            result.valid = True
            # Could parse "Number of signers: N" / "Signer #1 certificate
            # DN: CN=..." here for the signer field; defer to v0.4+.
        elif _APKSIGNER_DOES_NOT.search(combined):
            result.signed = True   # signature was attempted/present
            result.valid = False
            result.error = "verify_failed"
        else:
            # Unsigned APK or apksigner couldn't parse it.
            stderr = (run_result.stderr or b"").decode(
                "utf-8", errors="replace"
            )
            if "no signature" in stderr.lower():
                result.signed = False
                result.valid = None
            else:
                result.error = "parse_error"

        result.duration_seconds = time.monotonic() - start
        return result
