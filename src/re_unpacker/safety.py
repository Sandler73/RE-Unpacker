"""
.. module:: re_unpacker.safety
    :synopsis: Path-traversal defense, hashing, and quota tracking.

Description
-----------
Three concerns live here because they're security-adjacent utilities used
by both extractors and the orchestrator:

1. **Path traversal defense** -- after an extractor runs, walk the output
   subtree and confirm every path stays under ``output_root``. Anything
   that escapes (via malicious archive entries with absolute or ``../``
   paths, or post-extraction symlinks pointing outward) is *quarantined*
   rather than trusted. This catches extractor bugs as well as attacks.

2. **Hashing** -- streaming SHA-256 + MD5 computed with bounded memory use.
   Used for the manifest, dedup, and downstream RE analyst workflow.

3. **Quota tracking** -- a thread-safe counter for bytes extracted and
   files produced, so the orchestrator can enforce the run-wide budget
   without one extractor overrunning it.

Notes
-----
- Path checks use ``Path.resolve(strict=False)`` then compare against the
  resolved output root. ``os.path.commonpath`` handles any residual edge
  cases with symlinked output roots.
- We rebase escaping paths into a quarantine directory inside the output
  rather than deleting them -- an RE analyst may still want to inspect
  what the malicious archive tried to drop.

Version
-------
See :data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .constants import DEFAULT_READ_CHUNK_SIZE, QUARANTINE_DIRNAME
from .exceptions import PathTraversalError, SafetyLimitExceeded


# =============================================================================
# Path safety
# =============================================================================

def is_inside(candidate: Path, root: Path) -> bool:
    """Return True iff ``candidate`` resolves to a location inside ``root``.

    Both paths are resolved (symlinks followed). Comparison is done via
    ``commonpath`` to avoid prefix-string pitfalls (``/out`` vs ``/output``).
    """
    try:
        c = candidate.resolve(strict=False)
        r = root.resolve(strict=False)
        return os.path.commonpath([str(c), str(r)]) == str(r)
    except (ValueError, OSError):
        # ValueError: paths on different drives (Windows -- shouldn't happen on Kali)
        # OSError: broken symlink or missing intermediate
        return False


def audit_extracted_tree(
    extract_dir: Path,
    output_root: Path,
    *,
    logger: logging.Logger,
) -> tuple[int, int]:
    """Walk ``extract_dir`` and quarantine any path that escapes ``output_root``.

    Returns ``(quarantined_count, symlink_fixed_count)``.

    - Symlinks pointing outside ``output_root`` are replaced with a small
      placeholder text file recording their original target (so analysts
      keep a record without following the link).
    - Regular files / directories with a resolved path outside the output
      root are moved into ``output_root/_quarantine/``.
    """
    quarantined = 0
    symlink_fixed = 0
    quarantine_dir = output_root / QUARANTINE_DIRNAME
    if not quarantine_dir.exists():
        quarantine_dir.mkdir(parents=True, exist_ok=True)

    for root, dirs, files in os.walk(extract_dir, followlinks=False):
        # First handle symlinks (in both dirs and files lists).
        for entry in list(dirs) + list(files):
            p = Path(root) / entry
            try:
                if p.is_symlink():
                    target_raw = os.readlink(p)
                    # Resolve w.r.t. the link's own directory.
                    target_abs = (p.parent / target_raw).resolve(strict=False)
                    if not is_inside(target_abs, output_root):
                        # Replace the symlink with a placeholder.
                        try:
                            p.unlink()
                            placeholder = p.with_suffix(p.suffix + ".escaping_symlink.txt")
                            with open(placeholder, "w", encoding="utf-8") as f:
                                f.write(
                                    "Original symlink escaped output root.\n"
                                    f"original_link: {p}\n"
                                    f"original_target: {target_raw}\n"
                                )
                            symlink_fixed += 1
                            logger.warning(
                                "Neutralized escaping symlink: %s -> %s (placeholder: %s)",
                                p, target_raw, placeholder,
                            )
                        except OSError as e:
                            logger.error(
                                "Failed to neutralize escaping symlink %s: %s", p, e
                            )
            except OSError:
                continue

        # Regular files whose resolved path somehow escapes (rare: happens if
        # the extractor wrote through a symlink that existed beforehand).
        for fname in files:
            p = Path(root) / fname
            try:
                if p.is_symlink():
                    continue  # already handled above
                if not is_inside(p, output_root):
                    dest = quarantine_dir / (
                        p.name + f".{os.getpid()}.{quarantined}"
                    )
                    shutil.move(str(p), str(dest))
                    quarantined += 1
                    logger.warning(
                        "Quarantined escaping file: %s -> %s", p, dest
                    )
            except OSError as e:
                logger.debug("audit skip %s: %s", p, e)
                continue

    return quarantined, symlink_fixed


def assert_inside(candidate: Path, root: Path) -> None:
    """Raise :class:`PathTraversalError` if ``candidate`` escapes ``root``."""
    if not is_inside(candidate, root):
        raise PathTraversalError(path=str(candidate), output_root=str(root))


def sanitize_name(name: str, *, max_len: int = 200) -> str:
    """Return a filesystem-safe, shell-friendly derivative of ``name``.

    - Strips NUL, path separators, leading dots.
    - Replaces shell-special characters (parens, brackets, quotes, $ & ; |
      < > * ? ! backtick, whitespace) with underscores so the resulting
      path is safe to paste into any shell without escaping.
    - Truncates to ``max_len`` while preserving any extension.
    """
    # Drop NULs and path separators outright.
    cleaned = name.replace("\x00", "").replace("/", "_").replace("\\", "_")
    cleaned = cleaned.strip().lstrip(".")
    # Replace shell-special characters with underscores.
    _BAD = set(" \t\n\r\v\f()[]{}<>|&;*?!$`'\"")
    cleaned = "".join("_" if c in _BAD else c for c in cleaned)
    # Collapse runs of underscores.
    while "__" in cleaned:
        cleaned = cleaned.replace("__", "_")
    cleaned = cleaned.strip("_")
    if not cleaned:
        cleaned = "unnamed"
    if len(cleaned) <= max_len:
        return cleaned
    # Preserve extension if short enough to keep.
    if "." in cleaned[-20:]:
        stem, ext = cleaned.rsplit(".", 1)
        keep = max_len - len(ext) - 1
        if keep > 0:
            return stem[:keep] + "." + ext
    return cleaned[:max_len]


# =============================================================================
# Hashing
# =============================================================================

@dataclass(frozen=True)
class FileHashes:
    """Pair of common hashes for a file."""
    sha256: str
    md5: str
    size: int


def compute_hashes(path: Path, *, chunk_size: int = DEFAULT_READ_CHUNK_SIZE) -> FileHashes:
    """Stream the file through SHA-256 and MD5 in one pass.

    Returns a :class:`FileHashes` with both digests and the total byte count.
    Handles EIO / permission errors by re-raising as-is (caller decides).
    """
    sha = hashlib.sha256()
    md = hashlib.md5()
    total = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha.update(chunk)
            md.update(chunk)
            total += len(chunk)
    return FileHashes(sha256=sha.hexdigest(), md5=md.hexdigest(), size=total)


def iter_files(root: Path, *, follow_symlinks: bool = False) -> Iterator[Path]:
    """Yield every regular file under ``root`` (post-order not required)."""
    for dirpath, _dirs, files in os.walk(root, followlinks=follow_symlinks):
        for f in files:
            p = Path(dirpath) / f
            try:
                if p.is_file() and (follow_symlinks or not p.is_symlink()):
                    yield p
            except OSError:
                continue


# =============================================================================
# Quota tracker
# =============================================================================

class QuotaTracker:
    """Thread-safe byte/file counter with hard ceilings.

    Extractors call ``add_bytes`` / ``add_file`` after each successful output
    write. When a ceiling would be exceeded, :class:`SafetyLimitExceeded`
    is raised; the orchestrator catches it, logs the affected archive, and
    aborts further extraction of that archive (not the whole run).
    """

    __slots__ = (
        "max_total_bytes", "max_archive_bytes", "max_files_per_archive",
        "total_bytes", "total_files",
        "_lock",
    )

    def __init__(
        self,
        *,
        max_total_bytes: int,
        max_archive_bytes: int,
        max_files_per_archive: int,
    ) -> None:
        self.max_total_bytes: int = max_total_bytes
        self.max_archive_bytes: int = max_archive_bytes
        self.max_files_per_archive: int = max_files_per_archive
        self.total_bytes: int = 0
        self.total_files: int = 0
        self._lock = threading.Lock()

    def add_bytes(self, n: int, *, archive_bytes_so_far: int = 0) -> None:
        with self._lock:
            new_total = self.total_bytes + n
            if new_total > self.max_total_bytes:
                raise SafetyLimitExceeded(
                    "max_total_bytes", self.max_total_bytes, new_total
                )
            if archive_bytes_so_far + n > self.max_archive_bytes:
                raise SafetyLimitExceeded(
                    "max_archive_bytes",
                    self.max_archive_bytes,
                    archive_bytes_so_far + n,
                )
            self.total_bytes = new_total

    def add_file(self, *, archive_files_so_far: int = 0) -> None:
        with self._lock:
            if archive_files_so_far + 1 > self.max_files_per_archive:
                raise SafetyLimitExceeded(
                    "max_files_per_archive",
                    self.max_files_per_archive,
                    archive_files_so_far + 1,
                )
            self.total_files += 1

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {
                "total_bytes": self.total_bytes,
                "total_files": self.total_files,
                "max_total_bytes": self.max_total_bytes,
                "max_archive_bytes": self.max_archive_bytes,
                "max_files_per_archive": self.max_files_per_archive,
            }


def measure_tree(root: Path) -> tuple[int, int]:
    """Return ``(total_bytes, total_files)`` for all regular files under root."""
    total_bytes = 0
    total_files = 0
    for p in iter_files(root):
        try:
            total_bytes += p.stat().st_size
            total_files += 1
        except OSError:
            continue
    return total_bytes, total_files
