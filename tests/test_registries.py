"""
.. module:: tests.test_registries
    :synopsis: Registry-build invariants for extractors, verifiers, classifiers.

Description
-----------
The orchestrator dispatches purely through the registries, so these tests are
the contract check for "every registered handler is well-formed and the
registry knows the kinds it claims to cover". Uses the registries' public
accessors (``all()``, ``primary_for_kind()``, ``secondary_for_kind()``).

Version
-------
See :data:`re_unpacker.constants.VERSION`.
"""

from __future__ import annotations

from re_unpacker.classifiers.base import build_default_classifier_registry
from re_unpacker.detection import FileKind
from re_unpacker.extractors.base import build_default_registry
from re_unpacker.verifiers.base import build_default_verifier_registry

# --------------------------------------------------------------------------- #
# Extractor registry
# --------------------------------------------------------------------------- #

def test_extractor_registry_builds():
    reg = build_default_registry()
    kinds = reg.known_kinds()
    assert isinstance(kinds, frozenset)
    assert len(kinds) > 0


def test_extractor_known_kinds_are_filekinds():
    reg = build_default_registry()
    for kind in reg.known_kinds():
        assert isinstance(kind, FileKind), kind


def test_core_kinds_have_a_primary_extractor():
    reg = build_default_registry()
    for name in ("DEB", "RPM", "MSI", "CAB", "ZIP", "TAR", "ISO", "SQUASHFS"):
        kind = getattr(FileKind, name)
        assert reg.primary_for_kind(kind), name


def test_every_extractor_is_well_formed():
    reg = build_default_registry()
    handlers = list(reg.all())
    assert handlers
    for ex in handlers:
        assert isinstance(ex.name, str) and ex.name, ex
        assert isinstance(ex.required_tools, tuple), ex.name
        assert isinstance(ex.handles_kinds, frozenset), ex.name
        assert isinstance(ex.priority, int), ex.name


def test_primary_buckets_sorted_by_descending_priority():
    reg = build_default_registry()
    for kind in reg.known_kinds():
        prios = [ex.priority for ex in reg.primary_for_kind(kind)]
        assert prios == sorted(prios, reverse=True), kind


# --------------------------------------------------------------------------- #
# Verifier registry
# --------------------------------------------------------------------------- #

def test_verifier_registry_builds():
    reg = build_default_verifier_registry()
    assert tuple(reg.all())


def test_expected_verifiers_registered():
    reg = build_default_verifier_registry()
    names = [v.name.lower() for v in reg.all()]
    for expected in ("gpg", "rpm", "debsig", "apksigner"):
        assert any(expected in n for n in names), (expected, names)


def test_verifiers_declare_required_tools():
    reg = build_default_verifier_registry()
    for v in reg.all():
        assert isinstance(v.name, str) and v.name
        assert isinstance(v.required_tools, tuple)


# --------------------------------------------------------------------------- #
# Classifier registry
# --------------------------------------------------------------------------- #

def test_classifier_registry_builds():
    reg = build_default_classifier_registry()
    assert tuple(reg.all())


def test_expected_classifiers_registered():
    reg = build_default_classifier_registry()
    names = [c.name.lower() for c in reg.all()]
    for expected in ("entropy", "fuzzy", "exif", "yara"):
        assert any(expected in n for n in names), (expected, names)


def test_classifier_disable_removes_from_active(tool_registry):
    reg = build_default_classifier_registry()
    all_names = [c.name for c in reg.all()]
    if not all_names:
        return
    target = all_names[0]
    reg.disable(target)
    active = [c.name for c in reg.active_for_run(tool_registry)]
    assert target not in active
