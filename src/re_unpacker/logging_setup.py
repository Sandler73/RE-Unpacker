"""
.. module:: re_unpacker.logging_setup
    :synopsis: Dual-sink logging setup (console + file) for re-unpacker.

Description
-----------
Configures the package's root logger with three handlers:

1. Console (human-facing, level from CLI, color-free for portability)
2. Main log file (DEBUG always, inside the run's output directory)
3. Errors-only file (WARNING+ only, for quick triage)

Each run gets a fresh, timestamped pair of log files (no rotation) so that
every invocation is self-contained and archivable. Both files are opened in
line-buffered mode so the on-disk state reflects progress in real time --
useful when extractions run for hours or crash mid-way.

Notes
-----
- We intentionally avoid ``dictConfig`` to keep the module dependency-free
  and obvious. All configuration is explicit.
- ``log_exception`` helper attaches structured context (file path, extractor,
  returncode) so errors in the log are greppable.
- Multiprocess-safe: each worker process should call :func:`setup_logging`
  itself with the same log directory; handlers write with line buffering so
  interleaved output stays readable.

Version
-------
See :data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .constants import (
    ERRORS_LOG_FILENAME,
    EXTRACTION_LOG_FILENAME,
    PROJECT_NAME,
)


_LOG_FORMAT_FILE: str = (
    "%(asctime)s.%(msecs)03d %(levelname)-8s "
    "[pid=%(process)d tid=%(thread)d] "
    "%(name)s:%(funcName)s:%(lineno)d -- %(message)s"
)
_LOG_FORMAT_CONSOLE: str = (
    "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
)
_DATE_FORMAT: str = "%Y-%m-%dT%H:%M:%S"


def _resolve_level(level_str: str) -> int:
    """Map a user-supplied level name to the numeric logging constant.

    Raises ``ValueError`` (caught by CLI layer) on bad input.
    """
    level_up = level_str.strip().upper()
    resolved = getattr(logging, level_up, None)
    if not isinstance(resolved, int):
        raise ValueError(f"Unknown log level: {level_str!r}")
    return resolved


def setup_logging(
    log_dir: Path,
    *,
    console_level: str = "INFO",
    file_level: str = "DEBUG",
    logger_name: str = PROJECT_NAME,
) -> logging.Logger:
    """Configure and return the project logger.

    Parameters
    ----------
    log_dir
        Directory where the two log files will be created. Must already exist.
    console_level
        Level name (e.g. ``"INFO"``) for stderr output.
    file_level
        Level name for the main log file. Errors log is always WARNING+.
    logger_name
        Name of the returned logger (package root by default).

    Returns
    -------
    logging.Logger
        Fully configured logger. Safe to call more than once; existing
        handlers are cleared first.
    """
    log_dir = Path(log_dir)
    if not log_dir.is_dir():
        raise FileNotFoundError(f"log_dir does not exist: {log_dir}")

    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)  # root gates at DEBUG; handlers filter
    # Clear any handlers left from a previous call (important for tests / reruns).
    for h in list(logger.handlers):
        logger.removeHandler(h)
    logger.propagate = False

    # --- Console handler ---
    console = logging.StreamHandler(stream=sys.stderr)
    console.setLevel(_resolve_level(console_level))
    console.setFormatter(
        logging.Formatter(fmt=_LOG_FORMAT_CONSOLE, datefmt=_DATE_FORMAT)
    )
    logger.addHandler(console)

    # --- Main file handler ---
    main_path = log_dir / EXTRACTION_LOG_FILENAME
    file_handler = logging.FileHandler(main_path, mode="a", encoding="utf-8")
    file_handler.setLevel(_resolve_level(file_level))
    file_handler.setFormatter(
        logging.Formatter(fmt=_LOG_FORMAT_FILE, datefmt=_DATE_FORMAT)
    )
    # Line buffering: flush after every line so the file tracks progress live.
    try:
        file_handler.stream.reconfigure(line_buffering=True)  # type: ignore[attr-defined]
    except Exception:
        # Older Pythons or non-reconfigurable streams: fall back to flush after emit.
        _orig_emit = file_handler.emit

        def _flushing_emit(record: logging.LogRecord) -> None:
            _orig_emit(record)
            try:
                file_handler.flush()
            except Exception:
                pass

        file_handler.emit = _flushing_emit  # type: ignore[assignment]
    logger.addHandler(file_handler)

    # --- Errors-only file handler ---
    err_path = log_dir / ERRORS_LOG_FILENAME
    err_handler = logging.FileHandler(err_path, mode="a", encoding="utf-8")
    err_handler.setLevel(logging.WARNING)
    err_handler.setFormatter(
        logging.Formatter(fmt=_LOG_FORMAT_FILE, datefmt=_DATE_FORMAT)
    )
    logger.addHandler(err_handler)

    # Startup breadcrumbs.
    logger.debug(
        "Logging initialized: dir=%s, console=%s, file=%s",
        log_dir,
        console_level,
        file_level,
    )
    logger.debug(
        "Process: pid=%d, python=%s, cwd=%s",
        os.getpid(),
        sys.version.split()[0],
        os.getcwd(),
    )
    return logger


def log_exception(
    logger: logging.Logger,
    exc: BaseException,
    message: str,
    *,
    context: dict[str, Any] | None = None,
) -> None:
    """Log an exception with full traceback and optional structured context.

    Preserves cause chain (``__cause__`` / ``__context__``) via
    ``traceback.format_exception``.
    """
    ctx_str = ""
    if context:
        ctx_str = " | " + " ".join(f"{k}={v!r}" for k, v in context.items())
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    logger.error("%s%s\n%s", message, ctx_str, tb.rstrip())


def iso_utc_now() -> str:
    """Return an ISO-8601 UTC timestamp with 'Z' suffix (log / manifest use)."""
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


# =============================================================================
# v0.3.1 (ISS-001 + ISS-002): Default file logging for non-extract modes
#                             plus --log-file flag support
# =============================================================================

def default_mode_log_path(mode: str) -> Path:
    """Compute the default log file path for a non-extract mode invocation.

    Resolution priority:
        1. ``$XDG_CACHE_HOME/re-unpacker/logs/`` if XDG_CACHE_HOME is set
        2. ``~/.cache/re-unpacker/logs/`` otherwise

    Filename pattern: ``<mode>-<UTC_YYYYMMDD-HHMMSS>-<pid>.log``.

    The directory is NOT created here -- the caller (typically
    :func:`setup_dual_logging`) handles creation with mode 0700 on first use.
    Kept pure to make it easy to compute the path for display ahead of
    actually opening the file.

    Parameters
    ----------
    mode : str
        Short mode identifier, used as the filename prefix. Examples:
        ``"install"``, ``"uninstall"``, ``"repair"``, ``"tools-check"``,
        ``"dry-run-install"``.

    Returns
    -------
    Path
        Absolute path to the (not-yet-created) default log file.
    """
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        base = Path(xdg)
    else:
        # Path.home() raises RuntimeError on weird environments where HOME
        # cannot be resolved. Fall back to /tmp in that case rather than
        # propagate the error -- file logging is best-effort.
        try:
            base = Path.home() / ".cache"
        except RuntimeError:
            base = Path("/tmp")
    log_dir = base / "re-unpacker" / "logs"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    pid = os.getpid()
    sanitized_mode = mode.replace("/", "-").replace(" ", "-")
    return log_dir / f"{sanitized_mode}-{timestamp}-{pid}.log"


def setup_dual_logging(
    *,
    mode: str,
    console_level: int,
    file_path: Path | str | None = None,
    file_level: int = logging.DEBUG,
) -> tuple[logging.Logger, Path | None]:
    """Configure dual-sink logging for non-extract CLI modes.

    Console output respects ``console_level``; file output is always
    DEBUG-level (or whatever ``file_level`` is set to).

    The ``file_path`` argument has special semantics:

    - ``None`` -- use the default cache-dir path from
      :func:`default_mode_log_path`. This is what the CLI passes when no
      ``--log-file`` flag is given.
    - ``"-"`` (literal hyphen string) -- file logging is DISABLED for this
      run. Console-only.
    - any other path -- write the log to exactly that path. Parent
      directories are created with mode 0700 if missing. If the path is
      unwritable for any reason, fall back to console-only with a WARNING
      and continue (file logging is best-effort, never fatal).

    Parameters
    ----------
    mode : str
        Mode name (e.g. ``"install"``, ``"tools-check"``). Used as the
        default log filename prefix.
    console_level : int
        Logging level for console output (e.g. ``logging.INFO``).
    file_path : Path | str | None, optional
        Override path for the file log. See special semantics above.
    file_level : int, optional
        Logging level for file output. Defaults to DEBUG (capture everything
        even when the console is quieter).

    Returns
    -------
    tuple[logging.Logger, Path | None]
        ``(logger, actual_file_path)``. The path is ``None`` when file
        logging was disabled (either by ``"-"`` or by a fallback failure).
    """
    logger = logging.getLogger(PROJECT_NAME)
    # Wipe any pre-existing handlers (so re-entry from inside a subprocess or
    # from setup_logging() doesn't double-log).
    for h in list(logger.handlers):
        logger.removeHandler(h)
    logger.setLevel(min(console_level, file_level))

    # Always: a console handler.
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(console_level)
    console_handler.setFormatter(
        logging.Formatter(_LOG_FORMAT_CONSOLE, datefmt=_DATE_FORMAT)
    )
    logger.addHandler(console_handler)

    # Resolve the file path.
    actual_path: Path | None
    if file_path == "-":
        # Explicit disable.
        actual_path = None
    else:
        if file_path is None:
            actual_path = default_mode_log_path(mode)
        else:
            actual_path = Path(file_path) if not isinstance(file_path, Path) else file_path

        # Ensure parent dir exists (cache-dir-style 0700 perms).
        try:
            actual_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as e:
            logger.warning(
                "Could not create log directory %s: %s -- file logging disabled.",
                actual_path.parent, e,
            )
            actual_path = None

    if actual_path is not None:
        try:
            file_handler = logging.FileHandler(
                actual_path, mode="a", encoding="utf-8",
            )
            file_handler.setLevel(file_level)
            file_handler.setFormatter(
                logging.Formatter(_LOG_FORMAT_FILE, datefmt=_DATE_FORMAT)
            )
            logger.addHandler(file_handler)
        except OSError as e:
            logger.warning(
                "Could not open log file %s: %s -- file logging disabled.",
                actual_path, e,
            )
            actual_path = None

    logger.propagate = False
    return logger, actual_path
