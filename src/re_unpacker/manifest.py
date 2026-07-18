"""
.. module:: re_unpacker.manifest
    :synopsis: Crash-resilient manifest builder (JSONL stream + final JSON).

Description
-----------
Records every file the orchestrator produces. Two artifacts:

- ``manifest.jsonl`` -- one JSON object per line, flushed after each entry.
  Survives crashes: even if the run dies at depth 7, the analyst still has
  every entry up to that point.
- ``manifest.json`` -- consolidated at the end: stats, tool inventory,
  errors, and the full file list.

Schema versioned via :data:`re_unpacker.constants.SCHEMA_VERSION` so
downstream tooling (your binary-analysis automation) can pin against it.

Notes
-----
- Writes are locked (:class:`threading.Lock`) so multiple extractors can
  emit entries concurrently without interleaving.
- ``add_error`` and ``add_file`` are the only mutators. The rest is
  finalized state.

Version
-------
Part of RE-Unpacker 0.5.0. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import socket
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .constants import (
    MANIFEST_FILENAME,
    MANIFEST_JSONL_FILENAME,
    PROJECT_NAME,
    SCHEMA_VERSION,
    VERSION,
)
from .logging_setup import iso_utc_now


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class FileEntry:
    """One extracted (or skipped) file entry.

    Schema fields are listed first; schema additions are
    listed at the end and are all OPTIONAL with sensible defaults. A
    reader written against schema can ignore the fields, and a
    reader written against loading a manifest gets the
    defaults transparently. This two-way tolerance is what allows the
    schema minor version to advance without breaking consumers.
    """
    path: str                       # absolute
    rel_path: str                   # relative to output root
    rel_path_from_source: str | None  # path inside the source archive (if known)
    source_archive: str | None      # path to the archive this came out of
    source_archive_sha256: str | None
    size: int
    sha256: str | None
    md5: str | None
    file_magic: str
    mime_type: str
    kind: str                       # FileKind.value
    extractor: str | None           # name of extractor that produced this file
    depth: int
    mode: str                       # octal string, e.g. "0755"
    mtime: str                      # ISO-8601 UTC
    signals: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------------
    # Schema additions
    # ------------------------------------------------------------------------

    # Subsystem C (classification): per-file enrichment fields. All optional;
    # default to None / empty. Files larger than ENRICHMENT_SIZE_CAP_BYTES
    # have these all set to None and enrichment_skipped="size_exceeds_cap".
    ssdeep: str | None = None
    tlsh: str | None = None
    entropy: float | None = None
    encrypted: bool | None = None         # True iff classifiers detected encryption
    encryption_scheme: str | None = None  # "luks", "gpg", "encrypted_zip", etc., or None
    yara_matches: list[dict] = field(default_factory=list)
    exif_metadata: dict = field(default_factory=dict)
    enrichment_skipped: str | None = None  # populated when classification skipped

    # Subsystem B (verification): list of VerifierResult dicts, one per
    # verifier that ran (whether applicable or not). Empty list means no
    # verifier was registered for this kind, NOT that verification failed.
    verification: list[dict] = field(default_factory=list)


@dataclass
class ErrorEntry:
    """One recorded run-level error (non-fatal)."""
    timestamp: str
    path: str | None
    extractor: str | None
    error_class: str
    message: str
    returncode: int | None = None
    stderr_snippet: str | None = None
    context: dict = field(default_factory=dict)


@dataclass
class RunStats:
    """End-of-run counters.

    Schema counters first, schema additions at the end.
    """
    inputs_scanned: int = 0
    files_extracted: int = 0
    archives_processed: int = 0
    archives_failed: int = 0
    archives_skipped_dedup: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    duration_seconds: float = 0.0
    max_depth_reached: int = 0
    errors_count: int = 0
    quarantined_paths: int = 0
    symlinks_neutralized: int = 0
    # Schema additions -- enrichment + verification counters
    verifications_performed: int = 0       # total verifier runs (any verifier, any file)
    verifications_signed_valid: int = 0    # signed=true AND valid=true
    verifications_signed_invalid: int = 0  # signed=true AND valid=false
    verifications_unsigned: int = 0        # performed=true AND signed=false
    yara_matches_total: int = 0            # total individual YARA rule matches
    files_yara_matched: int = 0            # distinct files with at least one YARA match
    enrichment_timeouts: int = 0           # any pass timed out
    enrichment_skipped_size: int = 0       # files skipped due to ENRICHMENT_SIZE_CAP_BYTES


# =============================================================================
# ManifestBuilder
# =============================================================================

class ManifestBuilder:
    """Accumulates file entries and errors; flushes as JSONL; consolidates at end.

    Usage::

        mb = ManifestBuilder(out_dir, argv=sys.argv, input_root=in_path)
        mb.open()
        try:
            mb.add_file(entry)
            ...
        finally:
            mb.close(stats=stats, tools_summary=tools.summary())
    """

    def __init__(
        self,
        output_root: Path,
        *,
        argv: list[str],
        input_root: Path,
        logger: logging.Logger | None = None,
    ) -> None:
        self.output_root = Path(output_root)
        self.input_root = Path(input_root)
        self.argv = list(argv)
        self.logger = logger

        self._jsonl_path = self.output_root / MANIFEST_JSONL_FILENAME
        self._json_path = self.output_root / MANIFEST_FILENAME

        self._files: list[FileEntry] = []
        self._errors: list[ErrorEntry] = []
        self._lock = threading.Lock()
        self._jsonl_fh = None
        self._opened_at: str = ""
        self._start_monotonic: float = 0.0

    # ---------------------------------------------------------------- open/close

    def open(self) -> None:
        """Open the JSONL stream for append."""
        self.output_root.mkdir(parents=True, exist_ok=True)
        self._jsonl_fh = open(
            self._jsonl_path, "a", encoding="utf-8", buffering=1
        )
        self._opened_at = iso_utc_now()
        self._start_monotonic = time.monotonic()
        # Header record -- so the JSONL stream is self-documenting too.
        self._write_raw({
            "record_type": "header",
            "tool": PROJECT_NAME,
            "tool_version": VERSION,
            "schema_version": SCHEMA_VERSION,
            "opened_at": self._opened_at,
            "host": socket.gethostname(),
            "os": platform.platform(),
            "invocation": {
                "argv": self.argv,
                "cwd": os.getcwd(),
                "pid": os.getpid(),
            },
            "input_root": str(self.input_root),
            "output_root": str(self.output_root),
        })

    def close(
        self,
        *,
        stats: RunStats,
        tools_summary: dict[str, dict[str, str | None]],
    ) -> None:
        """Flush the JSONL and write the consolidated JSON manifest."""
        if self._jsonl_fh is not None:
            try:
                self._write_raw({
                    "record_type": "footer",
                    "closed_at": iso_utc_now(),
                    "duration_seconds": round(time.monotonic() - self._start_monotonic, 3),
                })
                self._jsonl_fh.flush()
                self._jsonl_fh.close()
            except Exception:
                pass
            self._jsonl_fh = None

        # Consolidated manifest.json
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "tool": PROJECT_NAME,
            "tool_version": VERSION,
            "generated_at": iso_utc_now(),
            "opened_at": self._opened_at,
            "host": socket.gethostname(),
            "os": platform.platform(),
            "invocation": {
                "argv": self.argv,
                "cwd": os.getcwd(),
                "pid": os.getpid(),
            },
            "input_root": str(self.input_root),
            "output_root": str(self.output_root),
            "tools_detected": tools_summary,
            "stats": asdict(stats),
            "errors": [asdict(e) for e in self._errors],
            "files": [asdict(f) for f in self._files],
        }
        try:
            with open(self._json_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2, sort_keys=False, default=str)
                f.write("\n")
        except Exception as e:
            if self.logger:
                self.logger.error("Failed to write consolidated manifest: %s", e)
            raise

    # ---------------------------------------------------------------- mutators

    def add_file(self, entry: FileEntry) -> None:
        """Append a file entry (thread-safe)."""
        with self._lock:
            self._files.append(entry)
            self._write_raw({"record_type": "file", **asdict(entry)})

    def add_error(self, error: ErrorEntry) -> None:
        """Append an error entry (thread-safe)."""
        with self._lock:
            self._errors.append(error)
            self._write_raw({"record_type": "error", **asdict(error)})

    # ---------------------------------------------------------------- queries

    def files(self) -> Iterable[FileEntry]:
        """Snapshot of recorded file entries."""
        with self._lock:
            return list(self._files)

    def errors(self) -> Iterable[ErrorEntry]:
        """Snapshot of recorded error entries."""
        with self._lock:
            return list(self._errors)

    # ---------------------------------------------------------------- internals

    def _write_raw(self, obj: dict[str, Any]) -> None:
        fh = self._jsonl_fh
        if fh is None:
            return
        try:
            fh.write(json.dumps(obj, default=str, ensure_ascii=False))
            fh.write("\n")
        except Exception as e:
            if self.logger:
                self.logger.error("Failed to write JSONL record: %s", e)


def build_file_entry(
    *,
    abs_path: Path,
    output_root: Path,
    rel_path_from_source: str | None,
    source_archive: Path | None,
    source_archive_sha256: str | None,
    kind: str,
    magic_description: str,
    mime_type: str,
    extractor: str | None,
    depth: int,
    sha256: str | None,
    md5: str | None,
    size: int,
    signals: list[str] | None = None,
) -> FileEntry:
    """Convenience constructor that fills mode/mtime/rel_path from stat()."""
    try:
        st = abs_path.stat()
        mode = f"{st.st_mode & 0o7777:04o}"
        mtime = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(st.st_mtime)
        )
    except OSError:
        mode = "0000"
        mtime = iso_utc_now()
    try:
        rel = str(abs_path.resolve().relative_to(output_root.resolve()))
    except ValueError:
        rel = str(abs_path)
    return FileEntry(
        path=str(abs_path),
        rel_path=rel,
        rel_path_from_source=rel_path_from_source,
        source_archive=str(source_archive) if source_archive else None,
        source_archive_sha256=source_archive_sha256,
        size=size,
        sha256=sha256,
        md5=md5,
        file_magic=magic_description,
        mime_type=mime_type,
        kind=kind,
        extractor=extractor,
        depth=depth,
        mode=mode,
        mtime=mtime,
        signals=list(signals) if signals else [],
    )
