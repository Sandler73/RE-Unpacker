"""
.. module:: re_unpacker.classifiers.base
    :synopsis: Abstract Classifier base + ClassifierRegistry.

Description
-----------
Each classifier mutates the :class:`FileEntry` directly (in-place) rather
than returning a result dict. This is different from the verifier pattern
because each FileEntry has many enrichment fields (entropy, ssdeep, tlsh,
exif_metadata, yara_matches, encrypted, encryption_scheme) and threading
them through return values would be cumbersome. The orchestrator
serializes the FileEntry after all classifiers run.

Notes
-----
- Classifiers are best-effort; tool failures and timeouts are caught at
  the orchestrator boundary. A classifier that fails leaves its
  corresponding FileEntry field at the default (None / empty).
- ``enabled`` is set per run from CLI flags (``--no-entropy``, etc.) and
  passed via the registry's filter; the orchestrator never invokes a
  disabled classifier.
- Classifiers must NOT raise; they catch their own exceptions and log.
  Internal code uses defensive try/except around all I/O paths.

Version
-------
Part of re-unpacker 0.4.10. The authoritative value is
:data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ..manifest import FileEntry
from ..tools import ToolRegistry


class Classifier(abc.ABC):
    """Abstract base class for per-file enrichment passes.

    Concrete subclasses override :attr:`name`, :attr:`required_tools`
    (CLI tools, optional), :attr:`required_python_modules` (Python
    bindings, optional), :meth:`is_available`, and :meth:`classify`.
    """

    #: Stable identifier used in log messages and the disable-flag mapping.
    name: str = "abstract"

    #: External CLI tools required for this classifier. Empty tuple means
    #: no CLI tool dependency (Python-binding-only classifiers).
    required_tools: tuple[str, ...] = ()

    #: Python modules required for this classifier. Detected at registry
    #: build time via :func:`importlib.util.find_spec`.
    required_python_modules: tuple[str, ...] = ()

    def is_available(self, tools: ToolRegistry) -> bool:
        """Return True iff the classifier can run on this host.

        Default implementation: every CLI tool in :attr:`required_tools`
        is present, and every module in :attr:`required_python_modules`
        is importable. Subclasses override when they support fallback
        chains (e.g. Python binding OR CLI tool).
        """
        if self.required_tools:
            if not all(tools.have(t) for t in self.required_tools):
                return False
        if self.required_python_modules:
            import importlib.util
            for mod in self.required_python_modules:
                if importlib.util.find_spec(mod) is None:
                    return False
        return True

    @abc.abstractmethod
    def classify(
        self,
        file_entry: FileEntry,
        *,
        timeout_seconds: int,
        logger: logging.Logger,
    ) -> None:
        """Run this enrichment pass against ``file_entry``, mutating it in-place.

        Implementations should:
        - Wrap all I/O in try/except so they never raise to the orchestrator.
        - Honor ``timeout_seconds`` for any subprocess invocation.
        - Populate the appropriate FileEntry field(s) on success; leave
          them at default on failure.
        - Log timeouts and exceptions at DEBUG; log success at DEBUG only
          (this runs per-file, so INFO would be too noisy).
        """
        raise NotImplementedError


@dataclass
class ClassifierRegistry:
    """Collection of available classifiers, filtered by tool availability AND
    by per-run enable/disable settings."""

    _classifiers: list[Classifier] = field(default_factory=list)
    _disabled: set[str] = field(default_factory=set)

    def register(self, classifier: Classifier) -> None:
        self._classifiers.append(classifier)

    def disable(self, name: str) -> None:
        """Mark a classifier as disabled for this run (CLI flag mapping)."""
        self._disabled.add(name)

    def all(self) -> Iterable[Classifier]:
        return tuple(self._classifiers)

    def active_for_run(self, tools: ToolRegistry) -> list[Classifier]:
        """Return enabled, available classifiers in canonical pipeline order.

        The canonical pipeline order is:
          1. entropy (cheap; runs first)
          2. fuzzy_hash
          3. exif
          4. yara (most expensive; runs last)

        Sorting here ensures the orchestrator doesn't depend on the
        registration order in :func:`build_default_classifier_registry`.
        """
        order = {"entropy": 0, "fuzzy_hash": 1, "exif": 2, "yara": 3}
        result = [
            c for c in self._classifiers
            if c.name not in self._disabled
            and c.is_available(tools)
        ]
        result.sort(key=lambda c: order.get(c.name, 99))
        return result


def build_default_classifier_registry() -> ClassifierRegistry:
    """Build the canonical classifier registry.

    Imports each classifier module and registers concrete instances. The
    registry is built fresh per run; no global state.
    """
    registry = ClassifierRegistry()

    # Import here to avoid circular imports at module load time.
    from .entropy import EntropyClassifier
    from .fuzzy_hash import FuzzyHashClassifier
    from .exif import ExifClassifier
    from .yara_match import YaraMatchClassifier

    for c in (
        EntropyClassifier(),
        FuzzyHashClassifier(),
        ExifClassifier(),
        YaraMatchClassifier(),
    ):
        registry.register(c)

    return registry
