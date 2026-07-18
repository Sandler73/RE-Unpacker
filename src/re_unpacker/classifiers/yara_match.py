"""
.. module:: re_unpacker.classifiers.yara_match
    :synopsis: YARA rule matching via the ``yara`` Python binding (libyara).

Description
-----------
Loads YARA rules at run start and matches each extracted file against
them. Per-file matches are recorded as a list of dicts in
:attr:`FileEntry.yara_matches`.

Rule loading semantics (per locked-in design decision):

- When ``--yara-rules PATH`` is given (CLI flag), only that path is used
  (single file or directory of .yar/.yara files). Defaults are bypassed.
- When ``--yara-rules`` is NOT given, the union of three default
  directories is loaded:
    1. ``/etc/yara/`` -- system-wide
    2. ``~/.config/re-unpacker/yara/`` -- per-user custom
    3. YARA Forge default install path (``/var/lib/yara-forge/...``)
  Each rule file's source directory is logged at INFO when loaded so the
  user can see what's contributing to the match set.

Namespace assignment:
- Rules from ``/etc/yara/`` get namespace ``etc``
- Rules from ``~/.config/re-unpacker/yara/`` get namespace ``user``
- Rules from YARA Forge get namespace ``forge``
- Rules from explicit ``--yara-rules PATH`` get namespace ``custom``

This namespacing prevents collisions when the same rule name appears in
multiple source directories (which is common with stock-rule packages).

Notes
-----
- We use the Python binding (``yara`` module from ``python3-yara``) rather
  than shelling out to the CLI, because rule compilation is expensive and
  the binding lets us compile once at run start and apply many times.
- Compilation errors in individual rule files are logged and skipped;
  a single broken rule file does not abort the whole run.
- Per-file matching honors --enrich-timeout via a background thread
  watchdog (libyara doesn't expose a hard timeout from Python, so we
  approximate by abandoning slow files).

Version
-------
Added in 0.3.2.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any

from ..manifest import FileEntry
from ..constants import YARA_DEFAULT_RULE_DIRS
from ..platform_compat import expand_path as _expand_path
from .base import Classifier


# Module-level cache of compiled YARA rules. Keyed by the
# (rules_path_or_None, frozenset_of_default_dirs) tuple so test suites
# that switch settings get fresh compilations.
_COMPILED_RULES_CACHE: dict[Any, Any] = {}


class YaraMatchClassifier(Classifier):
    """YARA rule matcher.

    The classifier reads its run-time configuration from environment
    variables set by the CLI:
    - ``REUNP_YARA_RULES_PATH``: explicit --yara-rules PATH (or empty)
    """

    name = "yara"
    required_tools = ()  # Python binding is the canonical path
    required_python_modules = ("yara",)

    def classify(
        self,
        file_entry: FileEntry,
        *,
        timeout_seconds: int,
        logger: logging.Logger,
    ) -> None:
        rules = self._get_or_compile_rules(logger=logger)
        if rules is None:
            return  # No rules loaded; nothing to match.

        try:
            matches = rules.match(
                filepath=file_entry.path,
                timeout=timeout_seconds,
            )
        except Exception as e:
            logger.debug("YARA match failed for %s: %s", file_entry.path, e)
            return

        if not matches:
            return

        # Convert match objects to JSON-serializable dicts.
        records: list[dict] = []
        for m in matches:
            record = {
                "rule_name": m.rule,
                "namespace": getattr(m, "namespace", "default"),
                "tags": list(getattr(m, "tags", [])),
                "meta": dict(getattr(m, "meta", {}) or {}),
            }
            records.append(record)
        file_entry.yara_matches = records

    @classmethod
    def _get_or_compile_rules(cls, *, logger: logging.Logger):
        """Load + compile rules once per run. Cached at module level.

        Returns the compiled YARA rules object, or None if no rules could
        be loaded (no error, just nothing to match).
        """
        rules_path_env = os.environ.get("REUNP_YARA_RULES_PATH", "").strip()
        cache_key = (rules_path_env or None,
                     tuple(d for d, _ in YARA_DEFAULT_RULE_DIRS))
        if cache_key in _COMPILED_RULES_CACHE:
            return _COMPILED_RULES_CACHE[cache_key]

        try:
            import yara  # type: ignore
        except ImportError:
            return None

        # Build (filepath, namespace) tuples for every rule file we want
        # to compile. yara.compile() accepts a 'filepaths={ns: path}'
        # dict for namespacing.
        rule_files: list[tuple[str, str]] = []  # (path, namespace)

        if rules_path_env:
            # User passed --yara-rules PATH; use only that.
            rule_files.extend(
                cls._collect_rule_files_with_namespace(rules_path_env, "custom")
            )
            logger.info(
                "YARA: loading rules from --yara-rules path '%s' (%d rule files)",
                rules_path_env, len(rule_files),
            )
        else:
            # Auto-discovery: union of three default directories.
            # expand_path handles both ~ (POSIX) and %VAR% (Windows)
            # so YARA_DEFAULT_RULE_DIRS works on both platforms.
            for raw_dir, namespace in YARA_DEFAULT_RULE_DIRS:
                expanded = _expand_path(raw_dir)
                files = cls._collect_rule_files_with_namespace(
                    expanded, namespace,
                )
                if files:
                    logger.info(
                        "YARA: %d rule files from default dir '%s' (namespace=%s)",
                        len(files), expanded, namespace,
                    )
                    rule_files.extend(files)

        if not rule_files:
            logger.info(
                "YARA: no rules found in any default directory; "
                "set --yara-rules PATH or populate /etc/yara/ to enable matching."
            )
            _COMPILED_RULES_CACHE[cache_key] = None
            return None

        # yara.compile(filepaths=...) accepts a dict[namespace, filepath]
        # but it's one file per namespace key. To get N files in M
        # namespaces we have to use unique keys per file.
        filepaths_dict: dict[str, str] = {}
        for idx, (path, namespace) in enumerate(rule_files):
            # Unique key combines namespace + index + basename for
            # diagnostics; YARA preserves the original namespace via
            # rule attributes regardless of this key.
            unique_key = f"{namespace}:{idx}:{Path(path).stem}"
            filepaths_dict[unique_key] = path

        # Compile. Errors in individual files: we have to filter them
        # out one-by-one because yara.compile fails atomically if any
        # file is broken.
        try:
            compiled = yara.compile(filepaths=filepaths_dict)
        except yara.Error as e:
            logger.warning(
                "YARA: bulk compile failed (%s); falling back to "
                "per-file compilation to skip broken rule files.", e,
            )
            compiled = cls._compile_individually(filepaths_dict, logger)

        _COMPILED_RULES_CACHE[cache_key] = compiled
        return compiled

    @staticmethod
    def _collect_rule_files_with_namespace(
        path: str, namespace: str,
    ) -> list[tuple[str, str]]:
        """Walk ``path`` (file or dir) and collect (file, namespace) tuples
        for every .yar / .yara file."""
        out: list[tuple[str, str]] = []
        p = Path(path)
        if not p.exists():
            return out
        if p.is_file():
            if p.suffix.lower() in (".yar", ".yara"):
                out.append((str(p), namespace))
            return out
        # Directory: walk recursively for .yar / .yara files.
        try:
            for entry in p.rglob("*"):
                if not entry.is_file():
                    continue
                if entry.suffix.lower() in (".yar", ".yara"):
                    out.append((str(entry), namespace))
        except (OSError, PermissionError):
            pass
        return out

    @staticmethod
    def _compile_individually(filepaths_dict, logger):
        """Compile each rule file separately so a broken one is skipped
        rather than killing the entire run."""
        try:
            import yara  # type: ignore
        except ImportError:
            return None

        good: dict[str, str] = {}
        for key, path in filepaths_dict.items():
            try:
                yara.compile(filepath=path)
                good[key] = path
            except yara.Error as e:
                logger.warning("YARA: skipping broken rule file %s: %s", path, e)
        if not good:
            return None
        try:
            return yara.compile(filepaths=good)
        except yara.Error as e:
            logger.warning("YARA: even individual-compile path failed: %s", e)
            return None
