"""
.. module:: re_unpacker.reporting
    :synopsis: Human-readable post-run reports (tree.txt, summary.txt).

Description
-----------
Generates two flat-text artifacts inside the output root:

- ``tree.txt`` -- a pure-Python ``tree(1)``-style rendering of
  ``<output_root>/extracted/`` using box-drawing characters. Useful for
  eyeballing the full extracted hierarchy without external tools.
- ``summary.txt`` -- top-level run statistics, counts by file kind,
  the N largest files, and an error summary grouped by extractor.

Notes
-----
- Both are plain UTF-8 text. Long paths and file counts are truncated
  to keep the files readable (truncation is explicit with a "[…N more]"
  marker).
- We never include hashes or sensitive content in these reports -- they
  are overview artifacts. The full manifest.json is the authoritative
  machine-readable record.

Version
-------
Part of re-unpacker 0.4.10. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import logging
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

from .constants import (
    EXTRACTED_DIRNAME,
    PROJECT_NAME,
    SUMMARY_FILENAME,
    TREE_FILENAME,
    VERSION,
)
from .manifest import ErrorEntry, FileEntry, RunStats


# =============================================================================
# tree.txt
# =============================================================================

_TREE_BRANCH_MID = "├── "
_TREE_BRANCH_LAST = "└── "
_TREE_PIPE = "│   "
_TREE_SPACE = "    "

# Hard cap on nodes to render -- protect against a truly exploded output dir
# generating a multi-GB tree.txt. Analyst can still use `find`/`fd` for full.
_TREE_MAX_NODES: int = 50_000


def _render_tree(
    root: Path,
    *,
    max_nodes: int = _TREE_MAX_NODES,
) -> str:
    """Render a tree-style listing. Pure-Python; no external tool."""
    if not root.exists():
        return f"(nothing to render: {root} does not exist)\n"
    lines: list[str] = [str(root)]
    node_count = [1]  # mutable via closure
    truncated = [False]

    def _walk(cur: Path, prefix: str) -> None:
        if truncated[0]:
            return
        try:
            children = sorted(cur.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
        except OSError as e:
            lines.append(prefix + f"[error listing {cur.name}: {e}]")
            return
        for idx, child in enumerate(children):
            if node_count[0] >= max_nodes:
                lines.append(prefix + f"[… {max_nodes}+ nodes reached; tree truncated]")
                truncated[0] = True
                return
            last = idx == len(children) - 1
            branch = _TREE_BRANCH_LAST if last else _TREE_BRANCH_MID
            suffix = ""
            try:
                if child.is_symlink():
                    link_tgt = os.readlink(child)
                    suffix = f"  -> {link_tgt}"
                elif child.is_dir():
                    suffix = "/"
            except OSError:
                suffix = ""
            size_suffix = ""
            try:
                if child.is_file() and not child.is_symlink():
                    sz = child.stat().st_size
                    size_suffix = f"  ({_human_bytes(sz)})"
            except OSError:
                pass
            lines.append(prefix + branch + child.name + suffix + size_suffix)
            node_count[0] += 1
            if child.is_dir() and not child.is_symlink():
                next_prefix = prefix + (_TREE_SPACE if last else _TREE_PIPE)
                _walk(child, next_prefix)

    _walk(root, "")
    lines.append("")
    lines.append(
        f"[total rendered: {node_count[0]} nodes"
        f"{' (TRUNCATED)' if truncated[0] else ''}]"
    )
    return "\n".join(lines) + "\n"


def write_tree_report(
    output_root: Path,
    *,
    logger: logging.Logger | None = None,
) -> Path:
    """Write ``tree.txt`` for the extracted directory. Returns its path."""
    target = output_root / TREE_FILENAME
    root_to_render = output_root / EXTRACTED_DIRNAME
    body = _render_tree(root_to_render)
    target.write_text(body, encoding="utf-8")
    if logger is not None:
        logger.info("Wrote tree report: %s (%d bytes)", target, target.stat().st_size)
    return target


# =============================================================================
# summary.txt
# =============================================================================

def _human_bytes(n: int) -> str:
    """Render a byte count in a human-friendly way."""
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    f = float(n)
    for u in units:
        if f < 1024.0 or u == units[-1]:
            return f"{f:.1f} {u}" if u != "B" else f"{int(f)} {u}"
        f /= 1024.0
    return f"{f:.1f} {units[-1]}"


def _format_kv_block(title: str, rows: Iterable[tuple[str, str]]) -> str:
    items = list(rows)
    if not items:
        return f"{title}\n  (none)\n"
    width = max(len(k) for k, _ in items)
    out = [title]
    for k, v in items:
        out.append(f"  {k:<{width}}  {v}")
    return "\n".join(out) + "\n"


def _top_kinds(files: Iterable[FileEntry], top_n: int = 25) -> list[tuple[str, int]]:
    c = Counter(f.kind for f in files)
    return c.most_common(top_n)


def _top_files_by_size(
    files: Iterable[FileEntry], top_n: int = 20
) -> list[FileEntry]:
    return sorted(files, key=lambda f: f.size, reverse=True)[:top_n]


def _errors_by_extractor(
    errors: Iterable[ErrorEntry],
) -> list[tuple[str, int]]:
    c: Counter[str] = Counter()
    for e in errors:
        c[e.extractor or "(none)"] += 1
    return c.most_common()


def _format_errors_by_class(
    errors: Iterable[ErrorEntry],
) -> list[tuple[str, int]]:
    c: Counter[str] = Counter()
    for e in errors:
        c[e.error_class] += 1
    return c.most_common()


# =============================================================================
# Verification + Classification rendering for summary.txt
# =============================================================================


def _append_verification_section(
    lines: list[str],
    files: list[FileEntry],
) -> None:
    """Render the full Subsystem B verification breakdown into ``lines``.

    Format:
      - Top-level rollup of counts (signed-valid / signed-invalid /
        unsigned / not-applicable) by verifier name.
      - Per-file breakdown grouped by FileEntry, listing each verifier
        result with a short status string.

    Per locked-in design decision (Q2): full breakdown lives in summary.txt
    AND in manifest.json. This is the human-readable view; programmatic
    consumers should read manifest.json.
    """
    # Top-level rollup by verifier name + status.
    by_verifier: Counter[tuple[str, str]] = Counter()
    files_with_verification: list[FileEntry] = []
    for fe in files:
        if not fe.verification:
            continue
        files_with_verification.append(fe)
        for v in fe.verification:
            status = _verification_status(v)
            by_verifier[(v.get("verifier_name", "?"), status)] += 1

    if not by_verifier:
        lines.append("")
        lines.append("  (No verifier ran on any file; either no applicable")
        lines.append("   kinds were extracted, or all required verifier")
        lines.append("   tools are missing. Run --tools-check to see the gap.)")
        return

    lines.append("")
    lines.append("Rollup by verifier:")
    # Sort: verifier name, then status order
    status_order = {
        "signed_valid": 0, "signed_invalid": 1, "unsigned": 2,
        "timeout": 3, "error": 4, "unknown": 5,
    }
    for (vname, status), n in sorted(
        by_verifier.items(),
        key=lambda kv: (kv[0][0], status_order.get(kv[0][1], 99)),
    ):
        lines.append(f"  {vname:<14}  {status:<14}  {n:>6,}")
    lines.append("")

    # Per-file breakdown.
    lines.append(f"Per-file results ({len(files_with_verification)} files with at least one verifier run):")
    for fe in files_with_verification:
        lines.append(f"  {fe.rel_path}  (kind={fe.kind})")
        for v in fe.verification:
            vname = v.get("verifier_name", "?")
            status = _verification_status(v)
            signer = v.get("signer")
            error = v.get("error")
            duration = v.get("duration_seconds", 0.0)
            extra_bits: list[str] = []
            if signer:
                extra_bits.append(f"signer={signer!r}")
            if error:
                extra_bits.append(f"error={error}")
            extra = (" " + " ".join(extra_bits)) if extra_bits else ""
            lines.append(
                f"    -> {vname:<14}  {status:<14}  {duration:.3f}s{extra}"
            )


def _verification_status(v: dict) -> str:
    """Map a VerifierResult-as-dict to a short status string."""
    if v.get("error") == "timeout":
        return "timeout"
    if v.get("error") and v.get("signed") is None:
        return "error"
    if v.get("signed") is True and v.get("valid") is True:
        return "signed_valid"
    if v.get("signed") is True and v.get("valid") is False:
        return "signed_invalid"
    if v.get("signed") is False:
        return "unsigned"
    return "unknown"


def _append_classification_section(
    lines: list[str],
    files: list[FileEntry],
    stats: RunStats,
) -> None:
    """Render the Subsystem C classification rollup into ``lines``.

    Format:
      - Counts of files with each enrichment field populated
      - Encrypted file roster (kind, encryption_scheme, path)
      - YARA match roster (per-rule counts; per-file matches)
      - Enrichment-skipped roster (files >= 256MiB)
    """
    enrichment_skipped: list[FileEntry] = []
    encrypted_files: list[FileEntry] = []
    files_with_yara: list[FileEntry] = []
    have_entropy = 0
    have_ssdeep = 0
    have_tlsh = 0
    have_exif = 0

    for fe in files:
        if fe.enrichment_skipped:
            enrichment_skipped.append(fe)
        if fe.encrypted is True:
            encrypted_files.append(fe)
        if fe.yara_matches:
            files_with_yara.append(fe)
        if fe.entropy is not None:
            have_entropy += 1
        if fe.ssdeep:
            have_ssdeep += 1
        if fe.tlsh:
            have_tlsh += 1
        if fe.exif_metadata:
            have_exif += 1

    lines.append("")
    lines.append("Coverage:")
    lines.append(f"  files_with_entropy        {have_entropy:>6,} / {len(files):>6,}")
    lines.append(f"  files_with_ssdeep         {have_ssdeep:>6,} / {len(files):>6,}")
    lines.append(f"  files_with_tlsh           {have_tlsh:>6,} / {len(files):>6,}")
    lines.append(f"  files_with_exif_metadata  {have_exif:>6,} / {len(files):>6,}")
    lines.append(f"  enrichment_skipped (size) {stats.enrichment_skipped_size:>6,}")
    lines.append(f"  enrichment_timeouts       {stats.enrichment_timeouts:>6,}")
    lines.append("")

    # Encrypted files
    lines.append(f"Encrypted files detected ({len(encrypted_files)}):")
    if encrypted_files:
        for fe in encrypted_files:
            scheme = fe.encryption_scheme or "(unknown)"
            entropy = (
                f"entropy={fe.entropy:.4f}"
                if fe.entropy is not None else "entropy=N/A"
            )
            lines.append(
                f"  scheme={scheme:<16}  {entropy:<18}  kind={fe.kind:<14}  {fe.rel_path}"
            )
    else:
        lines.append("  (none)")
    lines.append("")

    # YARA matches
    lines.append(f"YARA matches ({stats.yara_matches_total:,} total across {stats.files_yara_matched} files):")
    if files_with_yara:
        # Roll up by rule name across all files.
        rule_counts: Counter[str] = Counter()
        for fe in files_with_yara:
            for m in fe.yara_matches:
                key = f"{m.get('namespace', 'default')}:{m.get('rule_name', '?')}"
                rule_counts[key] += 1
        lines.append("  Rule rollup:")
        for rule, n in rule_counts.most_common():
            lines.append(f"    {rule:<48}  {n:>6,}")
        lines.append("  Per-file matches:")
        for fe in files_with_yara:
            rules = ", ".join(
                f"{m.get('namespace', 'default')}:{m.get('rule_name', '?')}"
                for m in fe.yara_matches
            )
            lines.append(f"    {fe.rel_path}  ->  {rules}")
    else:
        lines.append("  (none -- either no rules loaded or no matches)")
    lines.append("")

    # Enrichment-skipped roster (files too large for classification)
    if enrichment_skipped:
        lines.append(f"Files skipped for classification due to size cap ({len(enrichment_skipped)}):")
        for fe in enrichment_skipped:
            lines.append(
                f"  {_human_bytes(fe.size):>10}  kind={fe.kind:<14}  {fe.rel_path}"
            )


def write_summary_report(
    output_root: Path,
    *,
    stats: RunStats,
    files: list[FileEntry],
    errors: list[ErrorEntry],
    tools_summary: dict[str, dict[str, str | None]],
    invocation_argv: list[str],
    input_root: Path,
    logger: logging.Logger | None = None,
) -> Path:
    """Write ``summary.txt`` with top-level run stats. Returns its path."""
    target = output_root / SUMMARY_FILENAME
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append(f"{PROJECT_NAME} {VERSION} -- run summary")
    lines.append("=" * 72)
    lines.append("")

    # Invocation block
    lines.append(_format_kv_block("Invocation", [
        ("input", str(input_root)),
        ("output_root", str(output_root)),
        ("argv", " ".join(invocation_argv)),
    ]))
    lines.append("")

    # Stats block
    lines.append(_format_kv_block("Run stats", [
        ("inputs_scanned", f"{stats.inputs_scanned:,}"),
        ("files_extracted", f"{stats.files_extracted:,}"),
        ("archives_processed", f"{stats.archives_processed:,}"),
        ("archives_failed", f"{stats.archives_failed:,}"),
        ("archives_skipped_dedup", f"{stats.archives_skipped_dedup:,}"),
        ("bytes_out", _human_bytes(stats.bytes_out)),
        ("max_depth_reached", f"{stats.max_depth_reached}"),
        ("errors_count", f"{stats.errors_count:,}"),
        ("quarantined_paths", f"{stats.quarantined_paths:,}"),
        ("symlinks_neutralized", f"{stats.symlinks_neutralized:,}"),
        # (Subsystems B + C)
        ("verifications_performed", f"{stats.verifications_performed:,}"),
        ("verifications_signed_valid", f"{stats.verifications_signed_valid:,}"),
        ("verifications_signed_invalid", f"{stats.verifications_signed_invalid:,}"),
        ("verifications_unsigned", f"{stats.verifications_unsigned:,}"),
        ("yara_matches_total", f"{stats.yara_matches_total:,}"),
        ("files_yara_matched", f"{stats.files_yara_matched:,}"),
        ("enrichment_timeouts", f"{stats.enrichment_timeouts:,}"),
        ("enrichment_skipped_size", f"{stats.enrichment_skipped_size:,}"),
        ("duration_seconds", f"{stats.duration_seconds:.2f}"),
    ]))
    lines.append("")

    # Kind distribution
    lines.append("File kind distribution (top 25)")
    kind_rows = _top_kinds(files, top_n=25)
    if kind_rows:
        width = max(len(k) for k, _ in kind_rows)
        for kind, count in kind_rows:
            lines.append(f"  {kind:<{width}}  {count:>8,}")
    else:
        lines.append("  (none)")
    lines.append("")

    # Biggest files
    lines.append("Largest extracted files (top 20)")
    big = _top_files_by_size(files, top_n=20)
    if big:
        for f in big:
            lines.append(
                f"  {_human_bytes(f.size):>10}  d{f.depth:02d}  "
                f"{f.kind:<14}  {f.rel_path}"
            )
    else:
        lines.append("  (none)")
    lines.append("")

    # Error summary
    lines.append("Errors by extractor")
    err_by_extr = _errors_by_extractor(errors)
    if err_by_extr:
        width = max(len(k) for k, _ in err_by_extr)
        for k, n in err_by_extr:
            lines.append(f"  {k:<{width}}  {n:>6,}")
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append("Errors by class")
    err_by_cls = _format_errors_by_class(errors)
    if err_by_cls:
        width = max(len(k) for k, _ in err_by_cls)
        for k, n in err_by_cls:
            lines.append(f"  {k:<{width}}  {n:>6,}")
    else:
        lines.append("  (none)")
    lines.append("")

    # Tools inventory
    lines.append("Tools detected at startup")
    present = [n for n, info in tools_summary.items() if info.get("available") == "yes"]
    missing = [n for n, info in tools_summary.items() if info.get("available") != "yes"]
    lines.append(f"  present ({len(present)}): " + ", ".join(sorted(present)))
    lines.append(f"  missing ({len(missing)}): " + ", ".join(sorted(missing)))
    lines.append("")

    # =========================================================================
    # Subsystem B (verification) breakdown
    # =========================================================================
    lines.append("=" * 72)
    lines.append("Signature verification results (Subsystem B)")
    lines.append("=" * 72)
    _append_verification_section(lines, files)
    lines.append("")

    # =========================================================================
    # Subsystem C (classification) breakdown
    # =========================================================================
    lines.append("=" * 72)
    lines.append("Classification enrichment summary (Subsystem C)")
    lines.append("=" * 72)
    _append_classification_section(lines, files, stats)
    lines.append("")

    target.write_text("\n".join(lines), encoding="utf-8")
    if logger is not None:
        logger.info("Wrote summary report: %s (%d bytes)",
                    target, target.stat().st_size)
    return target
