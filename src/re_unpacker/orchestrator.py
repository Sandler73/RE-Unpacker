"""
.. module:: re_unpacker.orchestrator
    :synopsis: Recursive-unpack orchestrator (BFS with dedup + safety audit).

Description
-----------
Drives the whole show:

1. Seeds a BFS work queue from the input path (file or directory).
2. For each work item:

   a. Compute SHA-256 of the source (cheap dedup key).
   b. Skip if seen (avoids infinite loops on circular archives).
   c. Detect kind (``detection.detect_file``).
   d. Record a :class:`FileEntry` in the manifest.
   e. If extractable AND under depth limit: dispatch to extractors.

3. Dispatch runs:

   - Primary pass: walk primary extractors in priority order; stop on
     first success. Catches :class:`ExtractionError` from each attempt
     and logs it.
   - Secondary pass: runs every applicable secondary extractor regardless
     of primary outcome (this is where PE resources / ELF sections get
     dumped).
   - Fallback binwalk: if all primaries failed AND the kind is one
     binwalk might crack, run it.

4. After any successful extraction, the output subtree is audited for
   path-traversal escapes (:func:`safety.audit_extracted_tree`).

5. Every new file produced by an extractor is enqueued at depth+1, up
   to ``max_depth``.

Notes
-----
- Parallel workers: ``jobs > 1`` uses a :class:`ThreadPoolExecutor` for
  extraction (workers spend most of their time waiting on subprocesses,
  so threads beat processes; we also don't need to share Python state
  between jobs). Manifest writes are already lock-protected.
- The orchestrator NEVER raises to the CLI except for
  :class:`SafetyLimitExceeded` at the run-wide level (which aborts).
  Every other error becomes an :class:`ErrorEntry` in the manifest.

Version
-------
Part of RE-Unpacker 0.5.0. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import logging
import queue
import shutil
import threading
import time
from concurrent.futures import (
    FIRST_COMPLETED,
    Future,
    ThreadPoolExecutor,
    wait as futures_wait,
)
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .constants import (
    DEFAULT_JOBS,
    DEFAULT_MAX_DEPTH,
    DEFAULT_TIMEOUT_SECONDS,
    ENRICH_TIMEOUT_DEFAULT_SECONDS,
    ENRICHMENT_SIZE_CAP_BYTES,
    EXTRACTED_DIRNAME,
    UNPACKED_SUFFIX,
)
from .detection import EXTRACTABLE_KINDS, FileKind, detect_file
from .exceptions import (
    ExtractionError,
    ExtractorFailure,
    ExtractorNotApplicable,
    ExtractorTimeout,
    PathTraversalError,
    SafetyLimitExceeded,
    ToolMissingError,
)
from .extractors.base import (
    Extractor,
    ExtractionContext,
    ExtractorRegistry,
    build_default_registry,
)
from .logging_setup import iso_utc_now, log_exception
from .manifest import (
    ErrorEntry,
    FileEntry,
    ManifestBuilder,
    RunStats,
    build_file_entry,
)
from .safety import (
    FileHashes,
    QuotaTracker,
    audit_extracted_tree,
    compute_hashes,
    iter_files,
    measure_tree,
    sanitize_name,
)
from .subprocess_utils import set_output_byte_cap
from .tools import ToolRegistry
from .verifiers import (
    VerifierRegistry,
    VerifierResult,
    build_default_verifier_registry,
)
from .classifiers import (
    ClassifierRegistry,
    build_default_classifier_registry,
)
from dataclasses import asdict


# =============================================================================
# Work items
# =============================================================================

@dataclass
class _WorkItem:
    """One unit of work on the BFS queue."""
    path: Path
    depth: int
    source_archive: Path | None
    source_archive_sha256: str | None
    source_rel_inside_archive: str | None


# =============================================================================
# Orchestrator
# =============================================================================

class RecursiveUnpacker:
    """The main engine. Run once per invocation."""

    def __init__(
        self,
        *,
        input_path: Path,
        output_root: Path,
        tools: ToolRegistry,
        registry: ExtractorRegistry | None = None,
        logger: logging.Logger,
        manifest: ManifestBuilder,
        quota: QuotaTracker,
        max_depth: int = DEFAULT_MAX_DEPTH,
        jobs: int = DEFAULT_JOBS,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        binwalk_fallback: bool = True,
        extract_resources: bool = True,
        compute_source_hashes: bool = True,
        dedup_by_hash: bool = True,
        include_globs: tuple[str, ...] = (),
        exclude_globs: tuple[str, ...] = (),
        # additions: verifier + classifier configuration
        verifier_registry: VerifierRegistry | None = None,
        classifier_registry: ClassifierRegistry | None = None,
        enrich_timeout_seconds: int = ENRICH_TIMEOUT_DEFAULT_SECONDS,
    ) -> None:
        self.input_path = Path(input_path)
        self.output_root = Path(output_root)
        self.tools = tools
        self.registry = registry or build_default_registry()
        self.logger = logger
        self.manifest = manifest
        self.quota = quota
        self.max_depth = max_depth
        self.jobs = max(1, jobs)
        self.timeout_seconds = timeout_seconds
        self.binwalk_fallback = binwalk_fallback
        self.extract_resources = extract_resources
        self.compute_source_hashes = compute_source_hashes
        self.dedup_by_hash = dedup_by_hash
        self.include_globs = tuple(include_globs)
        self.exclude_globs = tuple(exclude_globs)
        # enrichment registries (default to canonical builds when
        # not injected; tests / API embedders can supply custom).
        self.verifier_registry = (
            verifier_registry or build_default_verifier_registry()
        )
        self.classifier_registry = (
            classifier_registry or build_default_classifier_registry()
        )
        self.enrich_timeout_seconds = enrich_timeout_seconds

        self._queue: queue.Queue[_WorkItem] = queue.Queue()
        self._seen_hashes: set[str] = set()
        self._seen_lock = threading.Lock()
        self._stats_lock = threading.Lock()

        self.stats = RunStats()
        self._start_monotonic: float = 0.0

    # ------------------------------------------------------------ entrypoint

    def run(self) -> RunStats:
        """Run to completion. Returns final stats."""
        self._start_monotonic = time.monotonic()
        self.logger.info(
            "Starting run: input=%s output=%s max_depth=%d jobs=%d",
            self.input_path, self.output_root, self.max_depth, self.jobs,
        )

        # SEC-1: install a run-wide per-file output ceiling on extraction
        # children (RLIMIT_FSIZE on POSIX) so a single-file decompression bomb
        # is stopped mid-write rather than only detected afterward. Sized to the
        # per-archive byte ceiling. No-op on Windows (documented platform gap);
        # the post-extraction byte and file-count checks are the backstop there.
        set_output_byte_cap(self.quota.max_archive_bytes)

        # Seed the queue.
        if self.input_path.is_dir():
            seeded = self._seed_from_directory(self.input_path)
            self.logger.info("Seeded %d top-level items from directory", seeded)
        elif self.input_path.is_file():
            self._enqueue(_WorkItem(
                path=self.input_path,
                depth=0,
                source_archive=None,
                source_archive_sha256=None,
                source_rel_inside_archive=None,
            ))
        else:
            raise FileNotFoundError(f"Input not found or unsupported: {self.input_path}")

        # Drain the queue.
        if self.jobs == 1:
            self._drain_sequential()
        else:
            self._drain_parallel()

        # Enrichment phase. Runs after extraction completes;
        # iterates over all FileEntry records collected during the BFS
        # drain and applies verifiers + classifiers to each. Best-effort:
        # any failure here records an error in the manifest but does NOT
        # abort the run.
        self._run_enrichment_phase()

        # Final stats.
        with self._stats_lock:
            self.stats.duration_seconds = round(
                time.monotonic() - self._start_monotonic, 3
            )
        self.logger.info(
            "Run complete: files=%d archives=%d errors=%d duration=%.1fs",
            self.stats.files_extracted,
            self.stats.archives_processed,
            self.stats.errors_count,
            self.stats.duration_seconds,
        )
        return self.stats

    # ------------------------------------------------------------ enrichment

    def _run_enrichment_phase(self) -> None:
        """Run verifiers + classifiers against every recorded FileEntry.

        Verifiers run UNCONDITIONALLY on every file (they're not subject to
        the 256MB enrichment size cap because signature verification on
        large ISOs / disk images is exactly the use case to support).

        Classifiers run only when ``file_entry.size <= ENRICHMENT_SIZE_CAP_BYTES``.
        Files exceeding the cap have ``enrichment_skipped="size_exceeds_cap"``
        recorded.

        Each verifier and classifier honors ``self.enrich_timeout_seconds``.
        Failures inside the enrichment phase are logged at DEBUG (per-file)
        and counted in :class:`RunStats` aggregates; they never abort the run.

        Note on stats accuracy: classifiers mutate FileEntry in place. The
        manifest already wrote each entry to manifest.jsonl during the BFS
        drain (without enrichment fields populated). The final manifest.json
        is written after this phase, so it captures the enriched form.
        manifest.jsonl callers consuming streamed records won't see
        enrichment fields and must read manifest.json for those.
        """
        files = list(self.manifest.files())
        if not files:
            return

        verifiers = list(self.verifier_registry.all())
        classifiers = self.classifier_registry.active_for_run(self.tools)
        if not verifiers and not classifiers:
            self.logger.info(
                "Enrichment phase: no verifiers or classifiers active; skipping.",
            )
            return

        self.logger.info(
            "Enrichment phase: %d files, %d applicable verifiers, "
            "%d active classifiers, timeout=%ds, size_cap=%dMiB",
            len(files), len(verifiers), len(classifiers),
            self.enrich_timeout_seconds,
            ENRICHMENT_SIZE_CAP_BYTES // (1024 * 1024),
        )

        for fe in files:
            try:
                self._enrich_one(fe, verifiers, classifiers)
            except Exception as e:
                # Defensive: enrichment phase MUST NOT abort the run.
                self.logger.debug(
                    "Enrichment failure on %s: %s", fe.path, e,
                )

    def _enrich_one(
        self,
        fe: FileEntry,
        verifiers: list,
        classifiers: list,
    ) -> None:
        """Enrich a single FileEntry. Modifies ``fe`` in place."""
        # ---- Verifiers (no size cap) ----
        applicable_verifiers = self.verifier_registry.applicable_for(
            fe, self.tools,
        )
        for verifier in applicable_verifiers:
            try:
                result = verifier.verify(
                    fe,
                    timeout_seconds=self.enrich_timeout_seconds,
                    logger=self.logger,
                )
            except Exception as e:
                # Verifiers are designed to never raise, but defend anyway.
                self.logger.debug(
                    "Verifier %s raised on %s: %s",
                    verifier.name, fe.path, e,
                )
                continue
            fe.verification.append(asdict(result))
            with self._stats_lock:
                self.stats.verifications_performed += 1
                if result.error == "timeout":
                    self.stats.enrichment_timeouts += 1
                elif result.signed and result.valid:
                    self.stats.verifications_signed_valid += 1
                elif result.signed and result.valid is False:
                    self.stats.verifications_signed_invalid += 1
                elif result.signed is False:
                    self.stats.verifications_unsigned += 1

        # ---- Classifiers (subject to size cap) ----
        if fe.size > ENRICHMENT_SIZE_CAP_BYTES:
            fe.enrichment_skipped = "size_exceeds_cap"
            with self._stats_lock:
                self.stats.enrichment_skipped_size += 1
            return

        for classifier in classifiers:
            try:
                classifier.classify(
                    fe,
                    timeout_seconds=self.enrich_timeout_seconds,
                    logger=self.logger,
                )
            except Exception as e:
                # Classifiers should never raise either, but defend.
                self.logger.debug(
                    "Classifier %s raised on %s: %s",
                    classifier.name, fe.path, e,
                )

        # YARA stats roll-up (computed after all classifiers ran since
        # yara_matches is the field they populate)
        if fe.yara_matches:
            with self._stats_lock:
                self.stats.yara_matches_total += len(fe.yara_matches)
                self.stats.files_yara_matched += 1

    # ------------------------------------------------------------ seeding

    def _seed_from_directory(self, directory: Path) -> int:
        count = 0
        for p in iter_files(directory):
            if self._matches_filters(p):
                self._enqueue(_WorkItem(
                    path=p, depth=0,
                    source_archive=None, source_archive_sha256=None,
                    source_rel_inside_archive=None,
                ))
                count += 1
        return count

    def _matches_filters(self, path: Path) -> bool:
        name = path.name
        if self.include_globs:
            import fnmatch
            if not any(fnmatch.fnmatch(name, g) for g in self.include_globs):
                return False
        if self.exclude_globs:
            import fnmatch
            if any(fnmatch.fnmatch(name, g) for g in self.exclude_globs):
                return False
        return True

    def _enqueue(self, item: _WorkItem) -> None:
        self._queue.put(item)

    # ------------------------------------------------------------ drains

    def _drain_sequential(self) -> None:
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                return
            try:
                self._process(item)
            except SafetyLimitExceeded:
                raise
            except Exception as e:
                log_exception(self.logger, e, "Worker exception (ignored)")

    def _drain_parallel(self) -> None:
        """BFS drain across a thread pool.

        Workers are I/O-bound (they spend their time inside subprocess calls),
        so threads give us the parallelism we want without the overhead of
        processes or the shared-state headache of multiprocessing. The
        manifest and seen-set already use locks.

        Termination condition: queue is empty AND no futures in flight.
        We rely on ``concurrent.futures.wait`` (not a raw busy-loop) so
        timeouts don't silently mark unfinished futures as done.
        """
        inflight: set[Future] = set()
        with ThreadPoolExecutor(
            max_workers=self.jobs, thread_name_prefix="reunp"
        ) as pool:
            while True:
                # Top up in-flight from the queue.
                while len(inflight) < self.jobs:
                    try:
                        item = self._queue.get_nowait()
                    except queue.Empty:
                        break
                    inflight.add(pool.submit(self._safe_process, item))

                if not inflight:
                    # Queue drained and no workers running -> done.
                    return

                # Wait for at least one worker to finish. Short timeout so a
                # worker enqueueing new items becomes visible promptly.
                done, inflight = futures_wait(
                    inflight, timeout=0.5, return_when=FIRST_COMPLETED,
                )
                # done is a set; inflight is the remainder (still running).
                # Cast inflight back to a set (wait returns a frozenset).
                inflight = set(inflight)

                # Consume results. SafetyLimitExceeded is fatal; everything
                # else becomes a log line and we keep going.
                for f in done:
                    try:
                        f.result()
                    except SafetyLimitExceeded:
                        raise
                    except Exception as e:
                        log_exception(
                            self.logger, e, "Worker exception (ignored)",
                        )

    def _safe_process(self, item: _WorkItem) -> None:
        try:
            self._process(item)
        except SafetyLimitExceeded:
            raise
        except Exception as e:
            log_exception(self.logger, e, "Worker exception (ignored)")

    # ------------------------------------------------------------ core

    def _process(self, item: _WorkItem) -> None:
        path = item.path
        self.logger.debug("Processing: %s (depth=%d)", path, item.depth)

        if not path.is_file():
            self.logger.debug("Skipping non-file: %s", path)
            return

        with self._stats_lock:
            self.stats.inputs_scanned += 1
            if item.depth > self.stats.max_depth_reached:
                self.stats.max_depth_reached = item.depth

        # 1. Hash for dedup (and for manifest).
        source_sha256: str | None = None
        source_md5: str | None = None
        size: int = 0
        try:
            if self.compute_source_hashes:
                hashes = compute_hashes(path)
                source_sha256, source_md5, size = (
                    hashes.sha256, hashes.md5, hashes.size,
                )
            else:
                size = path.stat().st_size
        except OSError as e:
            self._record_error(
                path=path, extractor=None, error_class="OSError",
                message=f"stat/hash failed: {e}",
            )
            return

        # 2. Dedup.
        if (
            self.dedup_by_hash and source_sha256 is not None
            and source_sha256 in self._check_seen(source_sha256)
        ):
            with self._stats_lock:
                self.stats.archives_skipped_dedup += 1
            self.logger.debug(
                "Dedup skip: %s (sha256=%s)", path, source_sha256[:12]
            )
            return

        # 3. Detect.
        detected = detect_file(path, self.tools, logger=self.logger)

        # 4. Record in manifest.
        entry = build_file_entry(
            abs_path=path,
            output_root=self.output_root,
            rel_path_from_source=item.source_rel_inside_archive,
            source_archive=item.source_archive,
            source_archive_sha256=item.source_archive_sha256,
            kind=detected.kind.value,
            magic_description=detected.magic_description,
            mime_type=detected.mime_type,
            extractor=None,  # set when extraction happens
            depth=item.depth,
            sha256=source_sha256,
            md5=source_md5,
            size=size,
            signals=detected.signals,
        )
        self.manifest.add_file(entry)
        with self._stats_lock:
            self.stats.files_extracted += 1

        # 5. Decide whether to extract deeper.
        if detected.kind not in EXTRACTABLE_KINDS:
            return
        if item.depth >= self.max_depth:
            self.logger.debug(
                "Max depth reached for %s (depth=%d >= %d)",
                path, item.depth, self.max_depth,
            )
            return

        # 6. Dispatch.
        dest_dir = self._allocate_dest_dir(path, item)
        self._dispatch(
            detected_kind=detected.kind,
            source_path=path,
            source_sha256=source_sha256 or "",
            dest_dir=dest_dir,
            depth=item.depth,
        )

    # ------------------------------------------------------------ seen set

    def _check_seen(self, sha256: str) -> set[str]:
        """Atomically test-and-add. Returns the set for membership check."""
        with self._seen_lock:
            if sha256 in self._seen_hashes:
                return self._seen_hashes
            self._seen_hashes.add(sha256)
            # Return a set that does NOT contain sha256 so the caller's
            # "in" check is False for first-time-seen.
            return set()

    # ------------------------------------------------------------ dest dir

    def _allocate_dest_dir(self, source: Path, item: _WorkItem) -> Path:
        """Compute the output directory for extracting ``source``.

        Layout:
            <output_root>/extracted/<input_name>.unpacked/ (depth 0)
            <output_root>/extracted/<input_name>.unpacked/<nested>.unpacked/ (deeper)
        """
        extracted_root = self.output_root / EXTRACTED_DIRNAME
        extracted_root.mkdir(parents=True, exist_ok=True)

        if item.depth == 0 and item.source_archive is None:
            # Top-level input file.
            safe = sanitize_name(source.name)
            return extracted_root / (safe + UNPACKED_SUFFIX)

        # Nested: dest sits next to the source file under a .unpacked subdir.
        safe = sanitize_name(source.name)
        return source.parent / (safe + UNPACKED_SUFFIX)

    # ------------------------------------------------------------ dispatch

    def _dispatch(
        self,
        *,
        detected_kind: FileKind,
        source_path: Path,
        source_sha256: str,
        dest_dir: Path,
        depth: int,
    ) -> None:
        """Run primary + secondary extractors for one file.

        Primary extractors are tried in priority order until one succeeds.
        ``ExtractorNotApplicable`` from an extractor is silent (no manifest
        error recorded) -- it just means "move on to the next one".
        Secondary extractors run regardless of whether a primary succeeded.
        """

        # ----- primary pass -----
        primaries = [
            e for e in self.registry.primary_for_kind(detected_kind)
            if e.is_available(self.tools)
        ]
        # Drop binwalk at this stage if user opted out of the fallback.
        if not self.binwalk_fallback:
            primaries = [e for e in primaries if e.name != "binwalk"]

        # filter root-requiring extractors when we are not root.
        # The orchestrator does not abort -- it just skips the root-required
        # extractor so the next extractor in the chain (if any) gets a turn.
        # If the entire chain is root-required, the file falls through to
        # the same "no available primary" branch as a missing-tools case.
        if primaries:
            from .pkg_manager import is_root  # local import: avoid module cycle
            if not is_root():
                root_skipped = [e for e in primaries if e.requires_root]
                primaries = [e for e in primaries if not e.requires_root]
                for ex in root_skipped:
                    self.logger.info(
                        "Skipping extractor %s on %s -- requires root for FUSE mount; "
                        "rerun with sudo to enable this extractor.",
                        ex.name, source_path,
                    )

        chosen_primary: Extractor | None = None
        last_real_error: Exception | None = None
        had_real_error: bool = False

        if not primaries:
            # No tools available for this kind at all. Record one info-level
            # error so the analyst knows they might want to install something.
            self._record_error(
                path=source_path, extractor=None,
                error_class="NoExtractor",
                message=(
                    f"No available primary extractor for kind={detected_kind.value} "
                    f"(missing tools or unsupported)"
                ),
            )
        else:
            for ex in primaries:
                self.logger.debug(
                    "Trying primary extractor %s on %s", ex.name, source_path
                )
                try:
                    self._run_single_extractor(
                        extractor=ex,
                        source_path=source_path,
                        source_sha256=source_sha256,
                        dest_dir=dest_dir,
                        depth=depth,
                    )
                    chosen_primary = ex
                    break
                except SafetyLimitExceeded:
                    raise
                except ExtractorNotApplicable as e:
                    # Expected non-applicability; silent move to next extractor.
                    self.logger.debug(
                        "Extractor %s not applicable for %s: %s",
                        ex.name, source_path.name, e.message,
                    )
                    continue
                except ExtractionError as e:
                    last_real_error = e
                    had_real_error = True
                    self._record_error(
                        path=source_path, extractor=ex.name,
                        error_class=type(e).__name__,
                        message=str(e),
                        returncode=getattr(e, "returncode", None),
                        stderr=getattr(e, "stderr", None),
                    )
                    continue
                except ToolMissingError as e:
                    last_real_error = e
                    self.logger.debug(
                        "Tool missing mid-dispatch for %s: %s", ex.name, e
                    )
                    continue

        # Log / counter update for the primary outcome.
        if chosen_primary is not None:
            with self._stats_lock:
                self.stats.archives_processed += 1
        elif had_real_error:
            # Genuine primary-extractor failures.
            with self._stats_lock:
                self.stats.archives_failed += 1
            self.logger.warning(
                "All primary extractors failed for %s (kind=%s). Last error: %s",
                source_path, detected_kind.value, last_real_error,
            )
        else:
            # Every attempt was "not applicable" -- normal for bare binaries.
            # Don't increment archives_failed; the file just didn't have a
            # container for us to pop open.
            self.logger.debug(
                "No primary extractor applied to %s (kind=%s); "
                "secondaries (if any) will still run.",
                source_path.name, detected_kind.value,
            )

        # ----- secondary pass (always runs, independent of primary outcome) -----
        if self.extract_resources:
            secondaries = [
                e for e in self.registry.secondary_for_kind(detected_kind)
                if e.is_available(self.tools)
            ]
            # same root-requirement filter as primaries.
            if secondaries:
                from .pkg_manager import is_root
                if not is_root():
                    secondaries = [e for e in secondaries if not e.requires_root]
            for ex in secondaries:
                self.logger.debug(
                    "Running secondary extractor %s on %s", ex.name, source_path
                )
                try:
                    self._run_single_extractor(
                        extractor=ex,
                        source_path=source_path,
                        source_sha256=source_sha256,
                        dest_dir=dest_dir,
                        depth=depth,
                        is_secondary=True,
                    )
                except SafetyLimitExceeded:
                    raise
                except ExtractorNotApplicable as e:
                    self.logger.debug(
                        "Secondary %s not applicable for %s: %s",
                        ex.name, source_path.name, e.message,
                    )
                    continue
                except ExtractionError as e:
                    # Secondary failures are non-fatal and common.
                    self._record_error(
                        path=source_path, extractor=ex.name,
                        error_class=type(e).__name__,
                        message=str(e),
                        returncode=getattr(e, "returncode", None),
                        stderr=getattr(e, "stderr", None),
                    )
                    continue

    # ------------------------------------------------------------ single ext

    def _run_single_extractor(
        self,
        *,
        extractor: Extractor,
        source_path: Path,
        source_sha256: str,
        dest_dir: Path,
        depth: int,
        is_secondary: bool = False,
    ) -> None:
        # Fresh dest for primary; secondary gets a subdir so its output
        # doesn't collide with the primary extraction.
        actual_dest = dest_dir
        if is_secondary:
            actual_dest = dest_dir / f"_secondary_{sanitize_name(extractor.name)}"
        actual_dest.mkdir(parents=True, exist_ok=True)

        ctx = ExtractionContext(
            source_path=source_path,
            source_sha256=source_sha256,
            dest_dir=actual_dest,
            depth=depth,
            output_root=self.output_root,
            timeout_seconds=self.timeout_seconds,
            logger=self.logger,
            tools=self.tools,
        )

        result = extractor.extract(ctx)
        self.logger.info(
            "Extracted: %s -> %s via %s",
            source_path.name, actual_dest, extractor.name,
        )

        # Audit path-traversal escapes.
        try:
            quarantined, symlink_fixed = audit_extracted_tree(
                actual_dest, self.output_root, logger=self.logger,
            )
        except Exception as e:
            log_exception(
                self.logger, e,
                "Path-safety audit failed (continuing with raw output)",
                context={"dest": str(actual_dest)},
            )
            quarantined, symlink_fixed = 0, 0
        with self._stats_lock:
            self.stats.quarantined_paths += quarantined
            self.stats.symlinks_neutralized += symlink_fixed

        # Quota accounting + enqueue discovered files.
        out_bytes, out_files = measure_tree(actual_dest)
        try:
            self.quota.add_bytes(out_bytes, archive_bytes_so_far=0)
            # SEC-2: enforce the per-archive file-count ceiling (--max-files).
            # Previously out_files was measured but discarded, leaving the
            # ceiling inert; now this extraction step's output count is checked.
            self.quota.add_files(out_files, archive_files_so_far=0)
            with self._stats_lock:
                self.stats.bytes_out += out_bytes
        except SafetyLimitExceeded as e:
            log_exception(self.logger, e, "Quota exceeded on extractor output")
            raise

        # Enqueue children only if the extractor says they're extractable
        # (binwalk, PE resources, and ELF sections do produce recurseable
        # content in general, so they're marked True).
        if extractor.produces_extractable_content and depth + 1 <= self.max_depth:
            for child in iter_files(actual_dest):
                self._enqueue(_WorkItem(
                    path=child,
                    depth=depth + 1,
                    source_archive=source_path,
                    source_archive_sha256=source_sha256,
                    source_rel_inside_archive=str(
                        child.relative_to(actual_dest)
                    ),
                ))

    # ------------------------------------------------------------ errors

    def _record_error(
        self,
        *,
        path: Path | None,
        extractor: str | None,
        error_class: str,
        message: str,
        returncode: int | None = None,
        stderr: str | None = None,
        context: dict | None = None,
    ) -> None:
        self.manifest.add_error(ErrorEntry(
            timestamp=iso_utc_now(),
            path=str(path) if path else None,
            extractor=extractor,
            error_class=error_class,
            message=message,
            returncode=returncode,
            stderr_snippet=(stderr[:2000] if stderr else None),
            context=dict(context or {}),
        ))
        with self._stats_lock:
            self.stats.errors_count += 1
