"""
.. module:: re_unpacker.verifiers.windows_authenticode
    :synopsis: Windows-native Authenticode signature verification.

Description
-----------
Two Windows-native verifiers for Microsoft Authenticode signatures
embedded in PE executables, MSI installers, and CAT files. Both produce
the same VerifierResult shape as the cross-platform OssLsignCodeVerifier
so the manifest schema is unchanged. Output-layer parity is preserved.

Two parallel paths because:

1. **PowerShellAuthenticodeVerifier**: uses the built-in PowerShell
   cmdlet ``Get-AuthenticodeSignature``. PowerShell 5.1 is present on
   every Windows install since Win10 1607; this verifier requires no
   external SDK or third-party tool. Always runs on Windows.

2. **SigntoolVerifier**: uses ``signtool.exe verify /pa /v``, which
   ships with the Windows SDK / Visual Studio Build Tools. Provides
   richer cert chain output than PowerShell's cmdlet (including
   timestamping verification details and the full chain of trust).
   Optional; runs only when signtool.exe is on PATH.

Both verifiers are filtered out on Linux because their required tools
(``powershell`` / ``signtool``) are absent from TOOL_PACKAGE_HINTS_LINUX.
The standard required_tools-based filter in the verifier registry
handles this without any explicit ``is_windows()`` checks needed.

When both run on the same file, both produce VerifierResult entries
in the manifest's ``verifiers`` array; they may agree or disagree on
trust evaluation. Disagreement signals a non-trivial signature state
(timestamping issue, partial trust chain, etc.) worth investigating.

Notes
-----
- ``Get-AuthenticodeSignature`` returns a SignerCertificate object with
  Subject, NotBefore, NotAfter, Thumbprint, etc. We extract Subject
  for the ``signer`` field of VerifierResult, matching osslsigncode's
  output format.
- The Status property is the trust-evaluation result: ``Valid``,
  ``HashMismatch``, ``NotSigned``, ``UnknownError``, etc.
- ``signtool verify /pa /v`` uses the default verification policy with
  verbose output. Returns 0 on success; non-zero with descriptive error
  on failure. Output is parsed similarly to osslsigncode.

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

from ..exceptions import ExtractorFailure, ExtractorTimeout
from ..manifest import FileEntry
from ..subprocess_utils import run_tool
from .base import Verifier, VerifierResult


# Kinds that may carry Authenticode signatures. Matches OssLsignCodeVerifier
# for cross-platform consistency.
_AUTHENTICODE_KINDS = frozenset({
    "PE_EXECUTABLE",
    "PE_NSIS",
    "PE_INNOSETUP",
    "PE_INSTALLSHIELD",
    "PE_WIXBURN",
    "MSI",
    "CAB",
})


# =============================================================================
# PowerShellAuthenticodeVerifier
# =============================================================================

# Get-AuthenticodeSignature returns an object with these key properties.
# We format-string the PowerShell call to produce a deterministic single
# line of output we can parse without dealing with PowerShell's
# multi-line object formatting.
_PS_AUTHENTICODE_SCRIPT = (
    "$sig = Get-AuthenticodeSignature -FilePath '{path}'; "
    "Write-Output (\"STATUS:\" + $sig.Status); "
    "if ($sig.SignerCertificate) { "
    "  Write-Output (\"SUBJECT:\" + $sig.SignerCertificate.Subject); "
    "  Write-Output (\"THUMBPRINT:\" + $sig.SignerCertificate.Thumbprint); "
    "}"
)

_PS_STATUS_RE = re.compile(rb"^STATUS:(\S+)", re.MULTILINE)
_PS_SUBJECT_RE = re.compile(rb"^SUBJECT:(.+)$", re.MULTILINE)


class PowerShellAuthenticodeVerifier(Verifier):
    """Authenticode verifier using PowerShell's Get-AuthenticodeSignature.

    Runs on Windows wherever PowerShell is available (which is every
    Windows 10+ install). Filtered on Linux because the ``powershell``
    tool is absent from TOOL_PACKAGE_HINTS_LINUX.
    """

    name = "powershell-authenticode"
    required_tools = ("powershell",)

    def applies_to(self, file_entry: FileEntry) -> bool:
        return file_entry.kind in _AUTHENTICODE_KINDS

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

        # Quote the path for inclusion in the PowerShell single-quoted
        # string. PowerShell's escape for a single quote is doubling it.
        ps_path = file_entry.path.replace("'", "''")
        script = _PS_AUTHENTICODE_SCRIPT.format(path=ps_path)

        try:
            run_result = run_tool(
                ["powershell", "-NoProfile", "-NonInteractive",
                 "-ExecutionPolicy", "Bypass", "-Command", script],
                tool_name="powershell",
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

        combined = (run_result.stdout or b"") + (run_result.stderr or b"")
        status_match = _PS_STATUS_RE.search(combined)

        if status_match is None:
            # Couldn't parse PowerShell output; record an error.
            result.error = (
                f"parse_error" if run_result.returncode == 0
                else f"rc={run_result.returncode}"
            )
            result.duration_seconds = time.monotonic() - start
            return result

        status = status_match.group(1).decode("utf-8", errors="replace")

        # Map PowerShell SignatureStatus enum values to VerifierResult fields.
        # See https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.signaturestatus
        if status == "Valid":
            result.signed = True
            result.valid = True
        elif status == "NotSigned":
            result.signed = False
            result.valid = None
        elif status in ("HashMismatch", "NotTrusted", "Incompatible"):
            result.signed = True
            result.valid = False
            result.error = f"status={status}"
        else:
            # UnknownError, NotSupportedFileFormat, or unrecognized status
            result.signed = False
            result.valid = None
            result.error = f"status={status}"

        # Extract signer subject if present (only meaningful when signed).
        subject_match = _PS_SUBJECT_RE.search(combined)
        if subject_match is not None and result.signed:
            result.signer = subject_match.group(1).strip().decode(
                "utf-8", errors="replace"
            )

        result.duration_seconds = time.monotonic() - start
        return result


# =============================================================================
# SigntoolVerifier
# =============================================================================

# signtool verify output patterns. Verbose mode (/v) prints "Successfully
# verified:" on success or "SignTool Error:" with details on failure.
_SIGNTOOL_OK = re.compile(rb"Successfully verified", re.IGNORECASE)
_SIGNTOOL_NO_SIG = re.compile(
    rb"No signature found|is not signed", re.IGNORECASE
)
_SIGNTOOL_SUBJECT = re.compile(
    rb"Issued to:\s*(.+?)\r?\n", re.IGNORECASE
)


class SigntoolVerifier(Verifier):
    """Authenticode verifier using ``signtool verify /pa /v``.

    Optional; runs only when signtool.exe is on PATH. signtool ships
    with the Windows SDK / Visual Studio Build Tools (see
    KNOWN_UNAVAILABLE_PACKAGES_WINDOWS in constants.py for install
    instructions).

    Provides richer cert chain output than the PowerShell cmdlet,
    including timestamping verification details. Filtered on Linux
    because ``signtool`` is absent from TOOL_PACKAGE_HINTS_LINUX.
    """

    name = "signtool"
    required_tools = ("signtool",)

    def applies_to(self, file_entry: FileEntry) -> bool:
        return file_entry.kind in _AUTHENTICODE_KINDS

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
                ["signtool", "verify", "/pa", "/v", file_entry.path],
                tool_name="signtool",
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

        combined = (run_result.stdout or b"") + (run_result.stderr or b"")

        if _SIGNTOOL_OK.search(combined):
            result.signed = True
            result.valid = True
            m = _SIGNTOOL_SUBJECT.search(combined)
            if m:
                result.signer = m.group(1).strip().decode(
                    "utf-8", errors="replace"
                )
        elif _SIGNTOOL_NO_SIG.search(combined):
            result.signed = False
            result.valid = None
        else:
            # signtool returns rc!=0 and various error messages on failed
            # verification of a signed file. Record the rc; signed=True
            # because some signature was found (just didn't verify).
            if run_result.returncode != 0:
                result.signed = True
                result.valid = False
                result.error = f"rc={run_result.returncode}"
            else:
                # rc=0 but no recognizable success/no-sig pattern; treat
                # as parse failure so the manifest doesn't mislead.
                result.error = "parse_error"

        result.duration_seconds = time.monotonic() - start
        return result
