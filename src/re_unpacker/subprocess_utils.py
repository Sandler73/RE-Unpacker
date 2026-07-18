"""
.. module:: re_unpacker.subprocess_utils
    :synopsis: Safe, uniform subprocess runner used by every extractor.

Description
-----------
One wrapper for every external-tool invocation. Guarantees:

- No ``shell=True`` anywhere (arguments always passed as a list).
- Per-call wall-clock timeout (raises :class:`ExtractorTimeout`).
- Captured stdout/stderr, truncated to a bound so giant tool output can't
  blow up memory.
- Structured :class:`RunResult` so callers never parse ``CompletedProcess``
  directly.
- Optional stdin bytes (used for pipeline cases like ``rpm2cpio | cpio``).

Notes
-----
- If ``check=True`` (default), non-zero exit raises
  :class:`ExtractorFailure`. Callers that tolerate non-zero (e.g. probing a
  tool for its version) pass ``check=False``.
- We clean up the subprocess on timeout by sending SIGTERM then SIGKILL if
  needed.

Version
-------
See :data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from .constants import DEFAULT_TIMEOUT_SECONDS
from .exceptions import ExtractorFailure, ExtractorTimeout
from .platform_compat import is_windows


# =============================================================================
# Cross-platform process termination (v0.4.2)
# =============================================================================

def _terminate_proc_tree(
    proc: subprocess.Popen, *, hard: bool = False,
) -> None:
    """Terminate or kill ``proc`` cross-platform.

    On POSIX: signals the process GROUP via ``os.killpg`` so any child
    grandprocesses (pipelines, shell-spawned helpers) are also reaped.
    The caller must have set ``start_new_session=True`` on Popen for
    this to work; we do so unconditionally.

    On Windows: ``os.killpg`` doesn't exist (POSIX-only API). We use
    ``Popen.terminate()`` (calls TerminateProcess on the immediate child)
    or ``Popen.kill()`` if ``hard=True``. Grandchildren are not reaped --
    Windows process management doesn't expose POSIX-style process groups
    cleanly, and TerminateProcess is the correct API for the immediate
    process. The trade-off: on Windows, a misbehaving tool that fork-bombs
    grandchildren may leave them orphaned. In practice this doesn't
    happen for any of the tools re-unpacker invokes.

    Defensive: any error from the kill primitives is swallowed. The
    caller is interested in "make a best effort to clean up" semantics,
    not in a precise return code.

    Added in v0.4.2 (lesson L32) after a Windows 11 Pro field bug where
    the timeout cleanup crashed with ``module 'os' has no attribute
    'killpg'`` when probing msiexec.
    """
    if is_windows():
        try:
            if hard:
                proc.kill()
            else:
                proc.terminate()
        except (ProcessLookupError, OSError):
            pass
    else:
        sig = signal.SIGKILL if hard else signal.SIGTERM
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, OSError):
            pass

_MAX_CAPTURED_BYTES: int = 1024 * 1024  # 1 MiB stdout/stderr cap per stream


@dataclass
class RunResult:
    """Structured outcome of a subprocess invocation."""

    argv: list[str]
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    duration_seconds: float = 0.0
    cwd: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def stdout_text(self) -> str:
        return _decode_with_bom(self.stdout)

    @property
    def stderr_text(self) -> str:
        return _decode_with_bom(self.stderr)


def _decode_with_bom(data: bytes) -> str:
    """Decode subprocess output bytes, honoring any leading BOM.

    v0.4.6 (lesson L41 cosmetic refinement): some Windows tools emit UTF-16
    LE/BE bytes to stdout (Sigcheck is the canonical example). Decoding such
    output as UTF-8 with errors='replace' produced mojibake: the raw 0xFF 0xFE
    BOM bytes became `\\ufffd\\ufffd` (Unicode replacement chars), and that
    is what produced the `(version: \uFFFD\uFFFD)` line in v0.4.5 testrun.txt.

    Fix: detect a UTF-16 LE/BE BOM at the byte level and decode as UTF-16 in
    that case. UTF-8 BOM bytes (\\xef\\xbb\\xbf) are also stripped explicitly
    so the leading character isn't a literal BOM in the resulting string.
    Falls back to UTF-8 with replace for the common case.
    """
    if not data:
        return ""
    # UTF-16 LE BOM: 0xFF 0xFE (but watch out: 0xFF 0xFE 0x00 0x00 is UTF-32 LE)
    if data[:4] == b"\xff\xfe\x00\x00":
        return data[4:].decode("utf-32-le", errors="replace")
    if data[:4] == b"\x00\x00\xfe\xff":
        return data[4:].decode("utf-32-be", errors="replace")
    if data[:2] == b"\xff\xfe":
        return data[2:].decode("utf-16-le", errors="replace")
    if data[:2] == b"\xfe\xff":
        return data[2:].decode("utf-16-be", errors="replace")
    if data[:3] == b"\xef\xbb\xbf":
        return data[3:].decode("utf-8", errors="replace")
    return data.decode("utf-8", errors="replace")


def _truncate(buf: bytes, limit: int) -> tuple[bytes, bool]:
    if len(buf) <= limit:
        return buf, False
    return buf[:limit] + b"\n...[truncated]...\n", True


def run_tool(
    argv: Sequence[str],
    *,
    tool_name: str | None = None,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    stdin_bytes: bytes | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    check: bool = True,
    capture_output: bool = True,
    logger: logging.Logger | None = None,
    source_for_error: str | None = None,
) -> RunResult:
    """Run ``argv`` safely.

    Parameters
    ----------
    argv
        Argument list. ``argv[0]`` is the executable.
    tool_name
        Display name for errors (defaults to ``argv[0]``).
    cwd
        Working directory for the child (optional).
    env
        Full environment map (optional; inherits parent by default).
    stdin_bytes
        Optional bytes fed to stdin (for pipeline patterns).
    timeout
        Seconds before SIGTERM / SIGKILL and :class:`ExtractorTimeout`.
    check
        Raise :class:`ExtractorFailure` on non-zero exit when True.
    capture_output
        Capture stdout/stderr when True; inherit parent when False.
    logger
        Optional logger for DEBUG-level invocation trace.
    source_for_error
        Source file reference attached to error messages.

    Returns
    -------
    RunResult
    """
    argv = list(argv)
    if not argv:
        raise ValueError("run_tool: argv must be non-empty")
    display_tool = tool_name or os.path.basename(argv[0])
    src_ref = source_for_error or ""

    import time
    start = time.monotonic()

    if logger is not None:
        logger.debug(
            "run_tool: tool=%s cwd=%s timeout=%ds argv=%r",
            display_tool,
            str(cwd) if cwd else None,
            timeout,
            argv,
        )

    # We use Popen + communicate directly so we can SIGKILL on timeout reliably.
    try:
        proc = subprocess.Popen(
            argv,
            cwd=str(cwd) if cwd else None,
            env=dict(env) if env is not None else None,
            stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            start_new_session=True,  # puts child in its own process group
        )
    except FileNotFoundError as e:
        raise ExtractorFailure(
            extractor=display_tool,
            source=src_ref,
            returncode=None,
            stderr=str(e),
            context={"reason": "executable not found"},
        ) from e
    except PermissionError as e:
        raise ExtractorFailure(
            extractor=display_tool,
            source=src_ref,
            returncode=None,
            stderr=str(e),
            context={"reason": "permission denied on executable"},
        ) from e

    try:
        stdout, stderr = proc.communicate(input=stdin_bytes, timeout=timeout)
    except subprocess.TimeoutExpired:
        # Escalate: SIGTERM the whole process group, then SIGKILL if still alive.
        _terminate_proc_tree(proc, hard=False)
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            _terminate_proc_tree(proc, hard=True)
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except Exception:
                stdout, stderr = b"", b""
        duration = time.monotonic() - start
        if logger is not None:
            logger.warning(
                "run_tool: TIMEOUT tool=%s duration=%.1fs argv=%r",
                display_tool,
                duration,
                argv,
            )
        raise ExtractorTimeout(display_tool, src_ref, timeout)

    duration = time.monotonic() - start
    stdout = stdout or b""
    stderr = stderr or b""
    stdout_t, stdout_trunc = _truncate(stdout, _MAX_CAPTURED_BYTES)
    stderr_t, stderr_trunc = _truncate(stderr, _MAX_CAPTURED_BYTES)

    result = RunResult(
        argv=argv,
        returncode=proc.returncode,
        stdout=stdout_t,
        stderr=stderr_t,
        stdout_truncated=stdout_trunc,
        stderr_truncated=stderr_trunc,
        duration_seconds=duration,
        cwd=str(cwd) if cwd else None,
    )

    if logger is not None:
        logger.debug(
            "run_tool: done tool=%s rc=%d duration=%.2fs stdout=%dB stderr=%dB",
            display_tool,
            result.returncode,
            duration,
            len(result.stdout),
            len(result.stderr),
        )

    if check and result.returncode != 0:
        snippet = result.stderr_text.strip() or result.stdout_text.strip()
        # Keep the error message bounded.
        if len(snippet) > 2000:
            snippet = snippet[:2000] + "…"
        raise ExtractorFailure(
            extractor=display_tool,
            source=src_ref,
            returncode=result.returncode,
            stderr=snippet,
            context={
                "argv": argv,
                "duration_seconds": round(duration, 3),
            },
        )

    return result


def run_pipeline(
    stages: Iterable[Sequence[str]],
    *,
    tool_name: str | None = None,
    cwd: str | Path | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    logger: logging.Logger | None = None,
    source_for_error: str | None = None,
) -> RunResult:
    """Run ``A | B | C`` style pipeline safely (no shell).

    Each stage is an argv list. Used, e.g., for
    ``rpm2cpio foo.rpm | cpio -idm``.

    Returns the RunResult of the *last* stage; intermediate stderr is
    surfaced if any stage fails.
    """
    stage_list = [list(s) for s in stages]
    if not stage_list:
        raise ValueError("run_pipeline: at least one stage required")
    if logger is not None:
        logger.debug(
            "run_pipeline: %d stages, argvs=%r",
            len(stage_list),
            stage_list,
        )

    import time
    start = time.monotonic()
    procs: list[subprocess.Popen] = []
    try:
        prev_stdout = subprocess.DEVNULL
        for idx, argv in enumerate(stage_list):
            is_last = idx == len(stage_list) - 1
            proc = subprocess.Popen(
                argv,
                cwd=str(cwd) if cwd else None,
                stdin=prev_stdout,
                stdout=subprocess.PIPE if not is_last else subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            procs.append(proc)
            if idx > 0:
                # Close parent's handle to the upstream pipe so EPIPE works.
                assert procs[idx - 1].stdout is not None
                procs[idx - 1].stdout.close()
            prev_stdout = proc.stdout  # type: ignore[assignment]

        # Collect output from last stage with timeout.
        last = procs[-1]
        try:
            stdout, stderr_last = last.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            for p in procs:
                _terminate_proc_tree(p, hard=False)
            raise ExtractorTimeout(
                tool_name or os.path.basename(stage_list[-1][0]),
                source_for_error or "",
                timeout,
            )

        # Wait for upstream stages.
        stderr_combined = b""
        for p in procs[:-1]:
            try:
                _, se = p.communicate(timeout=30)
                if se:
                    stderr_combined += se
            except subprocess.TimeoutExpired:
                _terminate_proc_tree(p, hard=True)
        stderr_combined += stderr_last or b""

        duration = time.monotonic() - start
        # Success if every stage returned 0.
        worst_rc = 0
        for p in procs:
            if p.returncode and p.returncode != 0:
                worst_rc = p.returncode
                break

        stdout_t, stdout_trunc = _truncate(stdout or b"", _MAX_CAPTURED_BYTES)
        stderr_t, stderr_trunc = _truncate(stderr_combined, _MAX_CAPTURED_BYTES)
        result = RunResult(
            argv=stage_list[-1],
            returncode=worst_rc,
            stdout=stdout_t,
            stderr=stderr_t,
            stdout_truncated=stdout_trunc,
            stderr_truncated=stderr_trunc,
            duration_seconds=duration,
            cwd=str(cwd) if cwd else None,
            extra={"pipeline_argvs": stage_list},
        )

        if worst_rc != 0:
            display = tool_name or " | ".join(
                os.path.basename(s[0]) for s in stage_list
            )
            raise ExtractorFailure(
                extractor=display,
                source=source_for_error or "",
                returncode=worst_rc,
                stderr=result.stderr_text.strip()[:2000],
                context={"pipeline": stage_list},
            )

        return result
    finally:
        for p in procs:
            if p.poll() is None:
                _terminate_proc_tree(p, hard=True)
