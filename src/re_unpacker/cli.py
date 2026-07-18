"""
.. module:: re_unpacker.cli
    :synopsis: Command-line interface for re-unpacker.

Description
-----------
Parses arguments, validates the environment, builds the execution
graph (logger → tool registry → manifest → orchestrator), runs, and
writes reports. Returns an integer exit code suitable for ``sys.exit``::

    0 run completed successfully (any errors recorded in manifest)
    1 input path invalid / filesystem error
    2 safety limit exceeded mid-run (manifest preserved)
    3 tools-check mode: one or more required tools missing
    4 other unexpected fatal error (bug)

Notes
-----
- ``--tools-check`` probes every known tool and exits without running.
  Intended for pre-flight checks on fresh boxes.
- ``--dry-run`` walks the input (directory or single file) and only
  performs detection; nothing is extracted. A manifest is still written
  so analysts can see what would be processed.
- Defaults match the project-wide choices: UPX unpack ON, binwalk fallback
  ON, PE/ELF resource extraction ON. Use ``--no-*`` flags to disable.

Version
-------
Part of re-unpacker 0.4.10. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from .constants import (
    DEFAULT_JOBS,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_EXTRACTED_SIZE,
    DEFAULT_MAX_FILES_PER_ARCHIVE,
    DEFAULT_MAX_TOTAL_SIZE,
    DEFAULT_TIMEOUT_SECONDS,
    EXTRACTED_DIRNAME,
    PROJECT_NAME,
    VERSION,
)
from .detection import detect_file
from .exceptions import (
    SafetyLimitExceeded,
    ValidationError,
)
from .extractors.base import build_default_registry
from .logging_setup import setup_logging, setup_dual_logging, log_exception, iso_utc_now
from .manifest import ManifestBuilder, RunStats, build_file_entry
from .orchestrator import RecursiveUnpacker
from .reporting import write_summary_report, write_tree_report
from .safety import QuotaTracker, iter_files, sanitize_name
from .tools import build_and_probe_registry, format_tools_check_report


_EPILOG = """\
Quick start:
  Linux / macOS:        ./re-unpacker sample.deb
  Windows PowerShell:   .\\re-unpacker.ps1 sample.cab
  Windows cmd.exe:      re-unpacker.cmd sample.cab
  Direct python:        python -m re_unpacker sample.deb

Examples:
  re-unpacker ./sample.deb
      Unpack a single file into ./sample.deb.unpacked/

  re-unpacker ./samples -o ./out -j 4
      Unpack every file under ./samples/ into ./out/ with 4 workers

  .\\re-unpacker.ps1 C:\\samples\\firmware.bin -o C:\\scratch\\out
      Windows: unpack a binary into a specified output directory

  re-unpacker foo.exe --no-binwalk --no-resources
      Unpack foo.exe without binwalk fallback or resource extraction

  re-unpacker --tools-check
      Print which extractor tools are installed and how to install missing ones

  re-unpacker --install --yes
      Install all missing tools via the platform's package manager
      (apt on Linux; winget on Windows; requires elevation)

  re-unpacker --dry-run ./samples
      Detect file kinds without extracting anything

For full documentation see ReUnpacker-README.html and
ReUnpacker-Usage-Guide.html. The Usage Guide's section 22
("Running on Windows") covers Windows-specific workflows in depth.
"""


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROJECT_NAME,
        description=(
            "Recursively unpack any package, installer, archive, filesystem "
            "image, or binary for downstream RE analysis. "
            "Pass a file or directory as the first argument; "
            "see Examples below for concrete invocations on each platform."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "input", nargs="?", type=Path,
        help="File or directory to unpack (required unless --tools-check).",
    )
    p.add_argument(
        "-o", "--output", type=Path, default=None,
        help="Output root directory. Default: derived from input name.",
    )
    p.add_argument(
        "-d", "--max-depth", type=int, default=DEFAULT_MAX_DEPTH,
        help=f"Maximum recursion depth (default: {DEFAULT_MAX_DEPTH}).",
    )
    p.add_argument(
        "-j", "--jobs", type=int, default=DEFAULT_JOBS,
        help=f"Parallel worker threads (default: {DEFAULT_JOBS}).",
    )
    p.add_argument(
        "--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Per-extraction timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS}).",
    )
    p.add_argument(
        "--max-extracted-size", type=int, default=DEFAULT_MAX_EXTRACTED_SIZE,
        help=(
            "Max bytes one archive may produce "
            f"(default: {DEFAULT_MAX_EXTRACTED_SIZE:,})."
        ),
    )
    p.add_argument(
        "--max-total-size", type=int, default=DEFAULT_MAX_TOTAL_SIZE,
        help=(
            "Max bytes produced run-wide "
            f"(default: {DEFAULT_MAX_TOTAL_SIZE:,})."
        ),
    )
    p.add_argument(
        "--max-files", type=int, default=DEFAULT_MAX_FILES_PER_ARCHIVE,
        help=(
            "Max files one archive may produce "
            f"(default: {DEFAULT_MAX_FILES_PER_ARCHIVE:,})."
        ),
    )

    feat = p.add_argument_group("Feature flags")
    feat.add_argument(
        "--binwalk", dest="binwalk", action="store_true", default=True,
        help="Enable binwalk fallback for unknown binaries (default: ON).",
    )
    feat.add_argument(
        "--no-binwalk", dest="binwalk", action="store_false",
        help="Disable binwalk fallback.",
    )
    feat.add_argument(
        "--resources", dest="resources", action="store_true", default=True,
        help="Extract PE resources and ELF sections (default: ON).",
    )
    feat.add_argument(
        "--no-resources", dest="resources", action="store_false",
        help="Disable PE/ELF resource extraction.",
    )
    feat.add_argument(
        "--hash", dest="hash", action="store_true", default=True,
        help="Compute SHA-256 + MD5 for every file (default: ON).",
    )
    feat.add_argument(
        "--no-hash", dest="hash", action="store_false",
        help="Skip hashing (faster for large inputs).",
    )
    feat.add_argument(
        "--dedup", dest="dedup", action="store_true", default=True,
        help="Skip re-processing files with identical SHA-256 (default: ON).",
    )
    feat.add_argument(
        "--no-dedup", dest="dedup", action="store_false",
        help="Process every occurrence even if content hash was seen before.",
    )

    # =========================================================================
    # Enrichment flags (Subsystem B verification + Subsystem C classification)
    # =========================================================================
    enrich = p.add_argument_group("Enrichment")
    enrich.add_argument(
        "--no-yara", dest="enable_yara", action="store_false", default=True,
        help="Skip YARA rule matching pass (Subsystem C).",
    )
    enrich.add_argument(
        "--no-fuzzy-hash", dest="enable_fuzzy_hash", action="store_false", default=True,
        help="Skip ssdeep + TLSH fuzzy hash computation.",
    )
    enrich.add_argument(
        "--no-exif", dest="enable_exif", action="store_false", default=True,
        help="Skip exiftool metadata extraction.",
    )
    enrich.add_argument(
        "--no-entropy", dest="enable_entropy", action="store_false", default=True,
        help="Skip Shannon entropy computation (also disables encryption "
             "heuristic that relies on it).",
    )
    enrich.add_argument(
        "--yara-rules", dest="yara_rules", default=None, metavar="PATH",
        help="YARA rules file or directory. Bypasses default auto-discovery "
             "from /etc/yara/, ~/.config/re-unpacker/yara/, and YARA Forge "
             "default. When this flag is NOT given, all three default "
             "directories are loaded as a union (rules namespaced "
             "etc:/user:/forge:).",
    )
    enrich.add_argument(
        "--enrich-timeout", dest="enrich_timeout", type=int, default=30,
        metavar="SEC",
        help="Per-pass per-file timeout for verifiers and classifiers "
             "(default: 30 seconds). Verifiers and classifiers that exceed "
             "this record error='timeout' in their result entry.",
    )

    filt = p.add_argument_group("Filters")
    filt.add_argument(
        "--include", action="append", default=[], metavar="GLOB",
        help="Only process files whose basename matches the glob "
             "(may be repeated). Applies to the initial seed walk only.",
    )
    filt.add_argument(
        "--exclude", action="append", default=[], metavar="GLOB",
        help="Skip files whose basename matches the glob (may be repeated).",
    )

    mode = p.add_argument_group("Modes")
    mode.add_argument(
        "--tools-check", action="store_true",
        help="Probe external tools, print status table, and exit.",
    )
    mode.add_argument(
        "--dry-run", action="store_true",
        help="Detect file kinds without extracting anything.",
    )
    # ----: package-management modes (require root) ----
    mode.add_argument(
        "--install", action="store_true",
        help="Install all known unpack tools that are currently missing. "
             "Requires root. Prompts for confirmation unless --yes.",
    )
    mode.add_argument(
        "--install-missing", dest="install", action="store_true",
        help=argparse.SUPPRESS,  # alias for --install
    )
    mode.add_argument(
        "--uninstall", action="store_true",
        help="Remove every unpack tool currently present from the system. "
             "Requires root and confirmation (use --yes to skip prompt).",
    )
    mode.add_argument(
        "--repair", action="store_true",
        help="Reinstall every currently-present unpack tool (recovers from "
             "broken / half-installed state). Requires root.",
    )
    mode.add_argument(
        "--dry-run-install", action="store_true",
        help="Print the exact apt commands the install/uninstall/repair "
             "modes would run, without executing. Does not require root.",
    )
    mode.add_argument(
        "-y", "--yes", action="store_true",
        help="Skip interactive y/N confirmation prompts (install/uninstall).",
    )
    mode.add_argument(
        "--no-refresh-index", action="store_true",
        help="Skip the apt-get update step before --install. Faster on "
             "repeated runs; off by default for safety.",
    )

    log = p.add_argument_group("Logging")
    log.add_argument(
        "--log-level", default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help=(
            "Console log level (default: INFO). File log always records "
            "DEBUG. Explicit --log-level overrides -v / -vv / -q with a "
            "warning logged."
        ),
    )
    # ISS-005: conventional verbosity shortcuts.
    # -q = WARNING, -v = INFO (default), -vv = DEBUG. -q and -v are
    # mutually exclusive at the argparse level so we get a clean error
    # if both are passed.
    verbosity = log.add_mutually_exclusive_group()
    verbosity.add_argument(
        "-v", "--verbose", action="count", default=0,
        help=(
            "Increase verbosity. -v = INFO (default), -vv = DEBUG. "
            "Mutually exclusive with -q / --quiet."
        ),
    )
    verbosity.add_argument(
        "-q", "--quiet", action="store_true",
        help=(
            "Decrease verbosity to WARNING (suppress INFO). "
            "Mutually exclusive with -v / --verbose."
        ),
    )
    # ISS-002: explicit log file path.
    log.add_argument(
        "--log-file", default=None, metavar="PATH",
        help=(
            "Write file log to PATH. Default for non-extract modes is "
            "$XDG_CACHE_HOME/re-unpacker/logs/<mode>-<timestamp>-<pid>.log "
            "(or ~/.cache/re-unpacker/logs/...); default for extract mode "
            "is <output>/extraction.log (always written). Use '-' to "
            "disable file logging entirely."
        ),
    )

    p.add_argument("-V", "--version", action="version",
                   version=f"{PROJECT_NAME} {VERSION}")
    return p


def _validate_args(args: argparse.Namespace) -> Path | None:
    """Validate parsed args. Returns the resolved input path, or None for
    modes that don't take an input (tools-check, install, uninstall, repair,
    dry-run-install).
    """
    # Mutual exclusion among the various modes.
    mode_flags = [
        ("--tools-check", args.tools_check),
        ("--dry-run", args.dry_run),
        ("--install", args.install),
        ("--uninstall", args.uninstall),
        ("--repair", args.repair),
        ("--dry-run-install", args.dry_run_install),
    ]
    chosen = [name for name, flag in mode_flags if flag]
    if len(chosen) > 1:
        raise ValidationError(
            f"mutually exclusive modes specified: {', '.join(chosen)}"
        )

    # Modes that don't take an input path:
    no_input_modes = (
        args.tools_check or args.install or args.uninstall
        or args.repair or args.dry_run_install
    )
    if no_input_modes:
        if args.input is not None:
            raise ValidationError(
                "the chosen mode does not accept an input path"
            )
        return None

    # Standard / dry-run path: input required.
    if args.input is None:
        # include a literal usage example so the user knows
        # what to type next. Platform-aware example so Windows users
        # see .\re-unpacker.ps1 not just ./re-unpacker (see L31).
        from .platform_compat import is_windows
        example = (
            ".\\re-unpacker.ps1 sample.cab" if is_windows()
            else "./re-unpacker sample.deb"
        )
        raise ValidationError(
            "input path is required. Pass a file or directory as the "
            "first argument, e.g.:\n\n"
            f"  {example}\n\n"
            "Or use one of the no-input modes: --tools-check, --install, "
            "--uninstall, --repair, --dry-run-install. "
            "Run with --help for the full list of flags."
        )
    inp = args.input.expanduser().resolve()
    if not inp.exists():
        raise ValidationError(f"input does not exist: {inp}")
    if args.max_depth < 0:
        raise ValidationError(f"--max-depth must be >= 0, got {args.max_depth}")
    if args.jobs < 1:
        raise ValidationError(f"--jobs must be >= 1, got {args.jobs}")
    if args.timeout < 1:
        raise ValidationError(f"--timeout must be >= 1, got {args.timeout}")
    for name, val in (
        ("--max-extracted-size", args.max_extracted_size),
        ("--max-total-size", args.max_total_size),
        ("--max-files", args.max_files),
    ):
        if val < 1:
            raise ValidationError(f"{name} must be >= 1, got {val}")
    return inp


def _derive_output_root(input_path: Path, user_choice: Path | None) -> Path:
    if user_choice is not None:
        return user_choice.expanduser().resolve()
    # Default: <cwd>/<sanitized-input-name>.re-unpacker/
    safe = sanitize_name(input_path.name)
    return (Path.cwd() / f"{safe}.re-unpacker").resolve()


# =============================================================================
# Run modes
# =============================================================================

def _print_log_banner(file_path, mode: str) -> None:
    """Print a one-line banner to stderr telling the user where the log goes.

    ISS-001: every non-extract mode shows this so the user can find
    the log without grepping.
    """
    if file_path is None:
        # Either --log-file - was given (explicit disable) or fallback failed.
        sys.stderr.write(f"[{mode}] (file logging disabled)\n")
    else:
        sys.stderr.write(f"[{mode}] Logging to {file_path}\n")
    sys.stderr.flush()


def _emit_log_level_conflict_warning(args, logger) -> None:
    """If both --log-level and -v/-q were given, warn that --log-level wins."""
    if getattr(args, "_log_level_conflict", False):
        logger.warning(
            "Both --log-level and -v/-q were given; --log-level=%s wins.",
            args.log_level,
        )


def _run_tools_check(args: argparse.Namespace) -> int:
    # ISS-001: tools-check now writes a default file log to
    # ~/.cache/re-unpacker/logs/tools-check-*.log (or the path given by
    # --log-file). Console output respects -v / -vv / -q / --log-level.
    console_level = getattr(logging, args.log_level)
    logger, log_path = setup_dual_logging(
        mode="tools-check",
        console_level=console_level,
        file_path=args.log_file,
    )
    _print_log_banner(log_path, "tools-check")
    _emit_log_level_conflict_warning(args, logger)

    reg = build_and_probe_registry(logger=logger)
    print(format_tools_check_report(reg))
    # Exit code reflects whether anything is missing -- useful for CI.
    any_missing = any(not t.available for t in reg.all_known())
    return 3 if any_missing else 0


def _run_dry_run(
    args: argparse.Namespace, input_path: Path, output_root: Path,
) -> int:
    output_root.mkdir(parents=True, exist_ok=True)
    logger = setup_logging(output_root, console_level=args.log_level)
    logger.info("Dry-run mode: detection only, no extraction.")
    tools = build_and_probe_registry(logger=logger)
    mb = ManifestBuilder(
        output_root,
        argv=sys.argv,
        input_root=input_path,
        logger=logger,
    )
    mb.open()
    stats = RunStats()
    try:
        paths = (
            list(iter_files(input_path)) if input_path.is_dir()
            else [input_path]
        )
        for p in paths:
            try:
                detected = detect_file(p, tools, logger=logger)
                try:
                    size = p.stat().st_size
                except OSError:
                    size = 0
                entry = build_file_entry(
                    abs_path=p,
                    output_root=output_root,
                    rel_path_from_source=None,
                    source_archive=None,
                    source_archive_sha256=None,
                    kind=detected.kind.value,
                    magic_description=detected.magic_description,
                    mime_type=detected.mime_type,
                    extractor=None,
                    depth=0,
                    sha256=None,
                    md5=None,
                    size=size,
                    signals=detected.signals,
                )
                mb.add_file(entry)
                stats.inputs_scanned += 1
                stats.files_extracted += 1
            except Exception as e:
                log_exception(logger, e, "dry-run detection failed", context={"path": str(p)})
    finally:
        mb.close(stats=stats, tools_summary=tools.summary())
    write_tree_report(output_root, logger=logger)
    write_summary_report(
        output_root, stats=stats,
        files=list(mb.files()), errors=list(mb.errors()),
        tools_summary=tools.summary(),
        invocation_argv=sys.argv,
        input_root=input_path, logger=logger,
    )
    return 0


def _run_normal(
    args: argparse.Namespace, input_path: Path, output_root: Path,
) -> int:
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / EXTRACTED_DIRNAME).mkdir(parents=True, exist_ok=True)

    logger = setup_logging(output_root, console_level=args.log_level)
    # ISS-002: when --log-file is passed in extract mode, attach an
    # additional file handler ON TOP of the default <output>/extraction.log.
    # Both files receive output. Using the same dual-logging function but
    # injecting it as an additional handler so extraction.log keeps working.
    _emit_log_level_conflict_warning(args, logger)
    if args.log_file is not None and args.log_file != "-":
        try:
            extra_path = Path(args.log_file)
            extra_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            extra_handler = logging.FileHandler(
                extra_path, mode="a", encoding="utf-8",
            )
            extra_handler.setLevel(logging.DEBUG)
            extra_handler.setFormatter(logging.Formatter(
                "%(asctime)s.%(msecs)03d %(levelname)-8s "
                "[pid=%(process)d tid=%(thread)d] "
                "%(name)s:%(funcName)s:%(lineno)d -- %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            ))
            logger.addHandler(extra_handler)
            sys.stderr.write(f"[extract] Additional log file: {extra_path}\n")
        except OSError as e:
            logger.warning(
                "Could not open extra log file %s: %s -- skipping (extraction.log unaffected).",
                args.log_file, e,
            )
    logger.info(
        "%s %s starting at %s", PROJECT_NAME, VERSION, iso_utc_now(),
    )

    tools = build_and_probe_registry(logger=logger)
    registry = build_default_registry()
    manifest = ManifestBuilder(
        output_root, argv=sys.argv, input_root=input_path, logger=logger,
    )
    quota = QuotaTracker(
        max_total_bytes=args.max_total_size,
        max_archive_bytes=args.max_extracted_size,
        max_files_per_archive=args.max_files,
    )
    manifest.open()

    # Configure enrichment registries from CLI flags.
    from .verifiers import build_default_verifier_registry
    from .classifiers import build_default_classifier_registry
    verifier_registry = build_default_verifier_registry()
    classifier_registry = build_default_classifier_registry()
    if not args.enable_entropy:
        classifier_registry.disable("entropy")
    if not args.enable_fuzzy_hash:
        classifier_registry.disable("fuzzy_hash")
    if not args.enable_exif:
        classifier_registry.disable("exif")
    if not args.enable_yara:
        classifier_registry.disable("yara")

    # YARA rule loading: when --yara-rules PATH is given, propagate it via
    # env var (the YaraMatchClassifier reads REUNP_YARA_RULES_PATH at
    # rule-compile time). When the flag is absent, the env var is unset
    # and the classifier falls back to default auto-discovery.
    if args.yara_rules:
        os.environ["REUNP_YARA_RULES_PATH"] = args.yara_rules
    else:
        # Defensive: clear any inherited value so test runs don't leak.
        os.environ.pop("REUNP_YARA_RULES_PATH", None)

    unpacker = RecursiveUnpacker(
        input_path=input_path,
        output_root=output_root,
        tools=tools,
        registry=registry,
        logger=logger,
        manifest=manifest,
        quota=quota,
        max_depth=args.max_depth,
        jobs=args.jobs,
        timeout_seconds=args.timeout,
        binwalk_fallback=args.binwalk,
        extract_resources=args.resources,
        compute_source_hashes=args.hash,
        dedup_by_hash=args.dedup,
        include_globs=tuple(args.include or ()),
        exclude_globs=tuple(args.exclude or ()),
        # enrichment params
        verifier_registry=verifier_registry,
        classifier_registry=classifier_registry,
        enrich_timeout_seconds=args.enrich_timeout,
    )

    exit_code = 0
    try:
        unpacker.run()
    except SafetyLimitExceeded as e:
        log_exception(
            logger, e, "Safety limit exceeded -- aborting further extraction",
        )
        exit_code = 2
    except Exception as e:  # pragma: no cover -- guardrail
        log_exception(logger, e, "Unexpected fatal error in orchestrator")
        exit_code = 4
    finally:
        manifest.close(stats=unpacker.stats, tools_summary=tools.summary())
        try:
            write_tree_report(output_root, logger=logger)
        except Exception as e:
            log_exception(logger, e, "tree report failed")
        try:
            write_summary_report(
                output_root, stats=unpacker.stats,
                files=list(manifest.files()), errors=list(manifest.errors()),
                tools_summary=tools.summary(),
                invocation_argv=sys.argv,
                input_root=input_path, logger=logger,
            )
        except Exception as e:
            log_exception(logger, e, "summary report failed")

    return exit_code


# =============================================================================
# Package-management run modes
# =============================================================================

def _stderr_logger() -> logging.Logger:
    """Minimal stderr logger for modes that run before / without an output dir."""
    logger = logging.getLogger(PROJECT_NAME)
    if not logger.handlers:
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        logger.addHandler(h)
    return logger


def _ensure_root(*, mode_name: str) -> bool:
    """Return True iff running as root. Prints a clear error if not.

    Caller is responsible for translating False to exit code 5; this
    function does not call sys.exit so unit tests and embedded callers
    can intercept cleanly.
    """
    from .pkg_manager import is_root  # local import: keep top of module clean
    if is_root():
        return True
    print(
        f"error: {mode_name} requires root privileges (uid 0).\n"
        f"Hint: rerun with sudo, e.g. 'sudo re-unpacker {mode_name}'.",
        file=sys.stderr,
    )
    return False


def _compute_install_targets(
    registry, *, only_missing: bool = True
) -> tuple[list[str], list[str]]:
    """Return ``(packages_to_install, missing_tool_names)``.

    Tools whose ``package_hint`` is None are silently skipped (we don't
    know how to install them on this distribution). Tools in
    ``PROTECTED_TOOLS`` and packages in ``PROTECTED_PACKAGES`` are never
    targeted -- they are infrastructure (apt, dpkg) without which the
    system cannot manage packages at all. They are still reported by
    ``--tools-check`` so the user knows their state.
    """
    from .constants import PROTECTED_PACKAGES, PROTECTED_TOOLS
    missing_tools: list[str] = []
    packages: list[str] = []
    seen_pkgs: set[str] = set()
    for tool in registry.all_known():
        if tool.name in PROTECTED_TOOLS:
            continue
        if tool.package_hint and tool.package_hint in PROTECTED_PACKAGES:
            continue
        if only_missing and tool.available:
            continue
        if tool.package_hint and tool.package_hint not in seen_pkgs:
            seen_pkgs.add(tool.package_hint)
            packages.append(tool.package_hint)
        if not tool.available:
            missing_tools.append(tool.name)
    return packages, missing_tools


def _compute_present_packages(
    registry,
    backend=None,
) -> tuple[list[str], list[str], list[str]]:
    """Return ``(packages, present_tool_names, essentials_skipped)``.

    Three-tuple now: the third element lists package names that *would*
    have been included but were filtered out because they are flagged
    Essential:yes by dpkg. We surface them so the user can see what was
    not touched and why.

    Excludes ``PROTECTED_TOOLS`` and ``PROTECTED_PACKAGES`` -- removing or
    reinstalling apt or dpkg via this tool is never appropriate.
    Additionally, when ``backend`` is provided, packages flagged
    Essential:yes by dpkg are filtered: apt refuses to remove them and
    handing them to apt-get remove returns rc=100, failing the whole run.
    """
    from .constants import PROTECTED_PACKAGES, PROTECTED_TOOLS
    present_tools: list[str] = []
    packages: list[str] = []
    essentials_skipped: list[str] = []
    seen_pkgs: set[str] = set()
    for tool in registry.all_known():
        if tool.name in PROTECTED_TOOLS:
            continue
        if tool.package_hint and tool.package_hint in PROTECTED_PACKAGES:
            continue
        if not tool.available:
            continue
        present_tools.append(tool.name)
        if tool.package_hint and tool.package_hint not in seen_pkgs:
            seen_pkgs.add(tool.package_hint)
            # Essential:yes filter (only when a backend is available to ask).
            if backend is not None and backend.is_essential_package(tool.package_hint):
                essentials_skipped.append(tool.package_hint)
                continue
            packages.append(tool.package_hint)
    return packages, present_tools, essentials_skipped


def _print_pkg_summary(action: str, packages: list[str], tool_names: list[str]) -> None:
    print(f"\n{action}: {len(packages)} package(s) for {len(tool_names)} tool(s):")
    print("  packages: " + (", ".join(packages) if packages else "(none)"))
    if tool_names:
        # Wrap tools list for readability.
        line_buf = "    "
        out_lines: list[str] = []
        for name in tool_names:
            if len(line_buf) + len(name) + 2 > 78:
                out_lines.append(line_buf.rstrip())
                line_buf = "    "
            line_buf += name + ", "
        if line_buf.strip():
            out_lines.append(line_buf.rstrip().rstrip(","))
        print("  tools:")
        for line in out_lines:
            print(line)


def _run_install(args: argparse.Namespace) -> int:
    """``--install`` mode: install all known unpack tools that are missing."""
    if not _ensure_root(mode_name="--install"):
        return 5
    # ISS-001: default file log to ~/.cache/re-unpacker/logs/.
    console_level = getattr(logging, args.log_level)
    logger, log_path = setup_dual_logging(
        mode="install", console_level=console_level, file_path=args.log_file,
    )
    _print_log_banner(log_path, "install")
    _emit_log_level_conflict_warning(args, logger)

    from .pkg_manager import (
        PackageManagerError, confirm, detect_backend,
    )

    registry = build_and_probe_registry(logger=logger)
    packages, missing_tools = _compute_install_targets(registry, only_missing=True)

    if not packages:
        print("All known unpack tools are already installed. Nothing to do.")
        return 0

    _print_pkg_summary("Will install", packages, missing_tools)

    if not args.yes:
        if not confirm("Proceed with installation?", default_no=True):
            print("Aborted.")
            return 0

    try:
        backend = detect_backend(
            refresh_index=not args.no_refresh_index, logger=logger,
        )
        backend.install_packages(packages, logger=logger)
    except PackageManagerError as e:
        log_exception(logger, e, "Package install failed")
        return 6

    # Lesson L33: on Windows, several winget packages add
    # themselves to PATH via the registry but the current Python
    # process's os.environ['PATH'] snapshot doesn't see them. Re-read
    # PATH from the registry so a subsequent --tools-check in the same
    # invocation can detect the freshly-installed tools. The
    # well-known-directory fallback in platform_compat.which_tool covers
    # tools that don't add to PATH at all (7-Zip, Sigcheck, etc.).
    from .platform_compat import is_windows, refresh_path_from_registry
    if is_windows():
        if refresh_path_from_registry():
            logger.debug("Refreshed PATH from Windows registry post-install")

    # after the winget batch completes, run manual-install handlers
    # for the ~30 Windows tools that have no winget Package ID. Per the
    # user-confirmed scope:
    # Q1 -> install to C:\Program Files\re-unpacker\bin\
    # Q2 -> auto-download from upstream GitHub releases at install time
    # Q3 -> handle everything except signtool / Android tools
    # Q4 -> per-tool failures log + continue; non-zero exit if any failed
    manual_install_failed = False
    if is_windows():
        # Lesson L40: manual_install_windows is imported here
        # (locally) because it's Windows-only and we don't want to import
        # it on Linux. build_and_probe_registry is NOT re-imported here --
        # it's already imported at module level (line 62), and adding a
        # local import would shadow the module-level binding for the
        # entire function and break earlier references at line 777.
        from .manual_install_windows import install_missing_tools_windows

        # Re-probe to find out what's STILL missing after the winget batch.
        # The well-known fallback in which_tool catches winget-installed
        # binaries even before PATH is refreshed in a new shell.
        post_winget_registry = build_and_probe_registry(logger=logger)
        still_missing_with_no_winget_hint = [
            t.name for t in post_winget_registry.all_known()
            if not t.available and not t.package_hint
        ]

        if still_missing_with_no_winget_hint:
            logger.info(
                "Manual install batch: %d non-winget tool(s) still missing",
                len(still_missing_with_no_winget_hint),
            )
            print()
            print("=" * 72)
            print(
                f"Running manual install handlers for "
                f"{len(still_missing_with_no_winget_hint)} non-winget tool(s)..."
            )
            print("=" * 72)
            print()

            summary = install_missing_tools_windows(
                still_missing_with_no_winget_hint,
                logger=logger,
            )
            print()
            print(summary.format_human())
            manual_install_failed = summary.any_failed
        else:
            logger.debug("No non-winget tools missing; skipping manual install batch")

    print("\nInstall complete. Run 're-unpacker --tools-check' to verify.")
    if is_windows():
        print(
            "Note: if any tools still appear missing after this, restart "
            "your shell (close+reopen the PowerShell/cmd window) to pick "
            "up the installer-updated PATH and re-run --tools-check."
        )
    # Per L39: non-zero exit code if any handler failed (signal to CI / scripts)
    return 6 if manual_install_failed else 0


def _run_uninstall(args: argparse.Namespace) -> int:
    """``--uninstall`` mode: remove every currently-present unpack tool."""
    if not _ensure_root(mode_name="--uninstall"):
        return 5
    # ISS-001: default file log.
    console_level = getattr(logging, args.log_level)
    logger, log_path = setup_dual_logging(
        mode="uninstall", console_level=console_level, file_path=args.log_file,
    )
    _print_log_banner(log_path, "uninstall")
    _emit_log_level_conflict_warning(args, logger)

    from .pkg_manager import (
        PackageManagerError, confirm, detect_backend,
    )

    # Instantiate backend up front so we can ask it about Essential:yes
    # packages while computing the package list.
    try:
        backend = detect_backend(refresh_index=False, logger=logger)
    except PackageManagerError as e:
        log_exception(logger, e, "Could not detect package manager")
        return 6

    registry = build_and_probe_registry(logger=logger)
    packages, present_tools, essentials_skipped = _compute_present_packages(
        registry, backend=backend,
    )

    if not packages and not essentials_skipped:
        print("No known unpack tools are currently installed. Nothing to do.")
        return 0

    if essentials_skipped:
        print(
            "\nThe following packages are flagged Essential:yes by dpkg "
            "and will NOT be removed:"
        )
        print("  " + ", ".join(essentials_skipped))
        print(
            "  (Essential packages are required for system stability; apt "
            "refuses to remove them, and so do we.)"
        )

    if not packages:
        print(
            "\nAfter excluding essential packages, nothing remains to remove."
        )
        return 0

    _print_pkg_summary("Will REMOVE", packages, present_tools)
    print(
        "\nWARNING: this removes the listed packages from the system. "
        "Other software depending on these packages may break."
    )

    if not args.yes:
        if not confirm("Proceed with removal?", default_no=True):
            print("Aborted.")
            return 0

    try:
        backend.remove_packages(packages, logger=logger)
    except PackageManagerError as e:
        log_exception(logger, e, "Package removal failed")
        return 6

    print("\nUninstall complete.")
    return 0


def _run_repair(args: argparse.Namespace) -> int:
    """``--repair`` mode: reinstall every currently-present unpack tool."""
    if not _ensure_root(mode_name="--repair"):
        return 5
    # ISS-001: default file log.
    console_level = getattr(logging, args.log_level)
    logger, log_path = setup_dual_logging(
        mode="repair", console_level=console_level, file_path=args.log_file,
    )
    _print_log_banner(log_path, "repair")
    _emit_log_level_conflict_warning(args, logger)

    from .pkg_manager import (
        PackageManagerError, confirm, detect_backend,
    )

    try:
        backend = detect_backend(
            refresh_index=not args.no_refresh_index, logger=logger,
        )
    except PackageManagerError as e:
        log_exception(logger, e, "Could not detect package manager")
        return 6

    registry = build_and_probe_registry(logger=logger)
    # Reinstalling Essential:yes packages is technically allowed by apt
    # (essentials can be reinstalled, just not removed). Pass backend=None
    # here so essentials are NOT filtered for repair -- a damaged tar or
    # gzip is exactly the kind of thing the user might be trying to fix.
    packages, present_tools, _ = _compute_present_packages(
        registry, backend=None,
    )

    if not packages:
        print("No known unpack tools are currently installed. Nothing to repair.")
        print("Hint: use --install to install the recommended toolset.")
        return 0

    _print_pkg_summary("Will REINSTALL", packages, present_tools)

    if not args.yes:
        if not confirm("Proceed with reinstallation?", default_no=True):
            print("Aborted.")
            return 0

    try:
        backend.reinstall_packages(packages, logger=logger)
    except PackageManagerError as e:
        log_exception(logger, e, "Package reinstall failed")
        return 6

    print("\nRepair complete. Run 're-unpacker --tools-check' to verify.")
    return 0


def _run_dry_run_install(args: argparse.Namespace) -> int:
    """``--dry-run-install`` mode: print what would be done. No root needed."""
    # ISS-001: default file log.
    console_level = getattr(logging, args.log_level)
    logger, log_path = setup_dual_logging(
        mode="dry-run-install", console_level=console_level,
        file_path=args.log_file,
    )
    _print_log_banner(log_path, "dry-run-install")
    _emit_log_level_conflict_warning(args, logger)

    from .pkg_manager import PackageManagerError, detect_backend

    registry = build_and_probe_registry(logger=logger)

    # Try to detect the backend so we can ask about Essential:yes packages.
    # If detection fails (no apt on this host), fall through with backend=None
    # and skip the essential filter.
    try:
        backend = detect_backend(refresh_index=False, logger=logger)
    except PackageManagerError:
        backend = None

    install_pkgs, missing_tools = _compute_install_targets(
        registry, only_missing=True,
    )
    present_pkgs, present_tools, essentials_skipped = _compute_present_packages(
        registry, backend=backend,
    )

    print("=" * 72)
    print("DRY RUN: re-unpacker package-management commands")
    print("=" * 72)
    print()

    # Lesson L34: platform-aware command rendering. On Windows
    # the suggested commands are winget; on Linux apt.
    from .platform_compat import is_windows as _is_win
    is_win = _is_win()
    if is_win:
        install_cmd_prefix = (
            "    re-unpacker --install --yes\n"
            "    (internally: winget install --id <ID> --exact "
            "--silent ... per Package ID below)"
        )
        remove_cmd_template = (
            "    re-unpacker --uninstall --yes\n"
            "    (internally: winget uninstall --id <ID> --exact "
            "--silent --accept-source-agreements per Package ID below)"
        )
        repair_cmd_template = (
            "    re-unpacker --repair --yes\n"
            "    (internally: winget uninstall + winget install per "
            "Package ID below; winget has no atomic reinstall)"
        )
    else:
        install_cmd_prefix = None  # built inline below for apt
        remove_cmd_template = None
        repair_cmd_template = None

    if install_pkgs:
        _print_pkg_summary("[--install] would install", install_pkgs, missing_tools)
        if is_win:
            print("  command:")
            print(install_cmd_prefix)
        else:
            print(
                "  command:\n"
                "    sudo apt-get update && sudo apt-get install -y "
                "--no-install-recommends -- " + " ".join(install_pkgs)
            )
    else:
        print("[--install] nothing to do; all known unpack tools are present.")
    print()

    if present_pkgs:
        _print_pkg_summary("[--uninstall] would remove", present_pkgs, present_tools)
        if essentials_skipped:
            print(
                "  excluded (Essential:yes -- protected by dpkg): "
                + ", ".join(essentials_skipped)
            )
        if is_win:
            print("  command:")
            print(remove_cmd_template)
        else:
            print(
                "  command:\n"
                "    sudo apt-get remove -y -- " + " ".join(present_pkgs)
            )
        print()

        # For --repair we do NOT filter essentials (apt can reinstall them).
        repair_pkgs, _repair_tools, _ = _compute_present_packages(
            registry, backend=None,
        )
        _print_pkg_summary("[--repair] would reinstall", repair_pkgs, present_tools)
        if is_win:
            print("  command:")
            print(repair_cmd_template)
        else:
            print(
                "  command:\n"
                "    sudo apt-get install --reinstall -y -- " + " ".join(repair_pkgs)
            )
    else:
        print("[--uninstall / --repair] no currently-installed unpack tools to act on.")

    print()
    if is_win:
        print("(Dry run -- no winget commands were executed.)")
    else:
        print("(Dry run -- no apt commands were executed.)")
    return 0


# =============================================================================
# Entry point
# =============================================================================

def _resolve_effective_log_level(args: argparse.Namespace) -> str:
    """Derive the effective log_level from args (, ISS-005).

    Resolution priority:
        1. ``--log-level`` if explicitly set -- wins, with a warning logged
           if -v / -q was also given.
        2. ``-q`` -> WARNING.
        3. ``-v`` (count=1) -> INFO; ``-vv`` (count>=2) -> DEBUG.
        4. Default -> INFO.
    """
    explicit = args.log_level
    quiet = bool(getattr(args, "quiet", False))
    verbose_count = int(getattr(args, "verbose", 0) or 0)

    if explicit is not None:
        if quiet or verbose_count:
            # Stash the conflict; we log the warning later (we don't have a
            # logger yet at this point).
            args._log_level_conflict = True
        return explicit

    if quiet:
        return "WARNING"
    if verbose_count >= 2:
        return "DEBUG"
    if verbose_count == 1:
        return "INFO"
    return "INFO"


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    # resolve -v / -vv / -q into args.log_level so downstream code
    # (which already reads args.log_level) keeps working unchanged.
    args.log_level = _resolve_effective_log_level(args)
    try:
        input_path = _validate_args(args)
    except ValidationError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    # Modes that don't take an input path.
    if args.tools_check:
        return _run_tools_check(args)
    if args.dry_run_install:
        return _run_dry_run_install(args)
    if args.install:
        return _run_install(args)
    if args.uninstall:
        return _run_uninstall(args)
    if args.repair:
        return _run_repair(args)

    # Standard run / dry-run.
    assert input_path is not None
    output_root = _derive_output_root(input_path, args.output)

    if args.dry_run:
        return _run_dry_run(args, input_path, output_root)
    return _run_normal(args, input_path, output_root)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
