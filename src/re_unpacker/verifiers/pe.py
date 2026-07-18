"""
.. module:: re_unpacker.verifiers.pe
    :synopsis: PE/MSI/CAT Authenticode signature verification via ``osslsigncode``.

Description
-----------
``osslsigncode verify <file>`` validates Microsoft Authenticode
signatures embedded in PE executables, MSI installers, and CAT files.
Sample output on success::

    Signature verification: ok
    Number of signers: 1
        Signer #1:
            Subject: /C=US/ST=California/L=...
            Issuer: /C=US/...
    Number of certificates: 5

The verifier triggers on any PE-family kind that may carry an
Authenticode signature: PE_EXECUTABLE, PE_NSIS, PE_INNOSETUP,
PE_INSTALLSHIELD, PE_WIXBURN, MSI, CAB. (Authenticode signatures are
embedded in the PE/MSI structure regardless of the installer
sub-flavor.)

Notes
-----
- ``osslsigncode`` is the cross-platform path. On Windows the Authenticode
  verifiers (PowerShell and signtool) are preferred because they consult the
  system trust store, which ``osslsigncode`` does not.
- A valid signature proves integrity and publisher identity; it does not
  imply the binary is benign. Signed malware is common, and revoked or
  expired certificates still produce a structurally valid signature.

Version
-------
Part of re-unpacker 0.4.10. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
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


_OSSLSIGNCODE_OK = re.compile(rb"Signature verification: ok", re.IGNORECASE)
_OSSLSIGNCODE_FAIL = re.compile(rb"Signature verification: failed", re.IGNORECASE)
_OSSLSIGNCODE_NO_SIG = re.compile(
    rb"No signature found", re.IGNORECASE
)
_OSSLSIGNCODE_SUBJECT = re.compile(
    rb"Signer #1:[\s\S]*?Subject:\s*([^\n]+)", re.MULTILINE
)


class OssLsignCodeVerifier(Verifier):
    """Verify Authenticode signatures via ``osslsigncode verify``."""

    name = "osslsigncode"
    required_tools = ("osslsigncode",)

    # Kinds that may carry Authenticode. The PE_* sub-types share the same
    # signature structure as raw PE_EXECUTABLE.
    _APPLICABLE_KINDS = frozenset({
        "PE_EXECUTABLE",
        "PE_NSIS",
        "PE_INNOSETUP",
        "PE_INSTALLSHIELD",
        "PE_WIXBURN",
        "MSI",
        "CAB",
    })

    def applies_to(self, file_entry: FileEntry) -> bool:
        return file_entry.kind in self._APPLICABLE_KINDS

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
                ["osslsigncode", "verify", file_entry.path],
                tool_name="osslsigncode",
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

        if _OSSLSIGNCODE_OK.search(combined):
            result.signed = True
            result.valid = True
            # Try to extract subject/CN.
            m = _OSSLSIGNCODE_SUBJECT.search(combined)
            if m:
                result.signer = m.group(1).strip().decode(
                    "utf-8", errors="replace"
                )
        elif _OSSLSIGNCODE_FAIL.search(combined):
            result.signed = True
            result.valid = False
            result.error = "verify_failed"
        elif _OSSLSIGNCODE_NO_SIG.search(combined):
            result.signed = False
            result.valid = None
        else:
            # osslsigncode rc!=0 with unrecognized output -> couldn't parse
            # the file at all (corrupted PE, etc.). Record as parse_error
            # rather than misleading "unsigned".
            if run_result.returncode != 0:
                result.error = f"rc={run_result.returncode}"
            else:
                result.error = "parse_error"

        result.duration_seconds = time.monotonic() - start
        return result
