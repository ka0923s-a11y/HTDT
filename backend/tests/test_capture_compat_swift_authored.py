"""Swift-authored bundle compatibility gate.

The ``swift-maximal`` fixture was produced by HTDT-Capture's production
Swift emit path (working-set store → seal → ``BundleRevisionFinalizer``)
on the ka0923s-a11y/HTDT-Capture emit branch — not by a Python fixture
generator — so it exercises every payload family the app actually
finalizes, including ``capture-advisory`` 1.1.0, ``entities`` 1.3.0,
``derived-geometry-candidates``, and the coordinate-space policy
document.

Unlike ``test_capture_compat_pinned`` (which pins the historical
phase-6 fixture via ``docs/CAPTURE_COMPATIBILITY.json``), this gate
pins its identity inline: the bytes are generated inside HTDT-Capture's
own test harness, so a digest change means the emit side changed.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from htdt.capture_bundle import FrozenBundle
from htdt.capture_reference import (
    CaptureIngestionContractError,
    build_ingestion_plan,
    canonical_plan_bytes,
)

FIXTURE_ROOT = (
    Path(__file__).resolve().parent / 'fixtures' / 'capture' / 'swift-maximal'
)

BUNDLE_DIGEST = (
    'caf013fc373221b2e96c40f3f60a885fca520dbf19370129126d94d9795094d2'
)
PLAN_CANONICAL_SHA256 = (
    '9d8e6f7d4aaab3d4fdda6871f42b8d081ca62007e51cd7c2a5d0403f3be609e2'
)


def _frozen() -> FrozenBundle:
    return FrozenBundle(FIXTURE_ROOT)


def test_swift_authored_bundle_is_contract_valid() -> None:
    report = _frozen().report
    assert report['valid'] is True
    assert report['bundle_digest'] == BUNDLE_DIGEST
    assert report['payload_count'] == 28
    # The emit side's current contract surface — every family the app
    # actually writes, at its emitted schema version.
    assert report['payload_versions'] == {
        'advisory-notes': '1.0.0',
        'entities': '1.3.0',
        'measurements': '1.1.0',
        'authority-dependencies': '1.0.0',
        'derived-geometry-candidates': '1.0.0',
        'mesh-anchors': '1.0.0',
        'capture-advisory': '1.1.0',
        'quality': '1.0.0',
        'capabilities': '1.0.0',
        'capture-configuration': '1.0.0',
        'session': '1.0.0',
        'capture-strategy': '1.0.0',
        'coordinate-space-policy': '1.0.0',
        'device': '1.0.0',
        'field-notes': '1.0.0',
        'working-revision-state': '1.0.0',
        'revisit-flags': '1.0.0',
        'timing': '1.0.0',
    }


def test_swift_authored_manifest_digest_is_bundle_digest() -> None:
    frozen = _frozen()
    assert (
        frozen.report['bundle_digest']
        == hashlib.sha256(frozen.manifest_bytes).hexdigest()
    )


def test_swift_authored_plan_is_stable() -> None:
    plan = build_ingestion_plan(_frozen())
    assert (
        hashlib.sha256(canonical_plan_bytes(plan)).hexdigest()
        == PLAN_CANONICAL_SHA256
    )
    assert len(plan['source_evidence']) == 28
    assert len(plan['roomplan_records']) == 2


def test_swift_authored_derived_entries_carry_source_refs() -> None:
    """Derived-role manifest entries must declare provenance refs —
    the receiver rejects dangling derived provenance."""
    plan = build_ingestion_plan(_frozen())
    derived = [
        e for e in plan['source_evidence'] if e['role'] == 'derived'
    ]
    assert derived, 'fixture must contain derived-role evidence'
    for entry in derived:
        assert entry['source_refs'], (
            f"{entry['path']}: derived entry without source_refs"
        )


@pytest.mark.parametrize('field', ['raw_byte_count', 'processed_byte_count'])
def test_roomplan_metadata_byte_counts_match_manifest(tmp_path: Path, field: str) -> None:
    bundle = tmp_path / 'bundle'
    shutil.copytree(FIXTURE_ROOT, bundle)
    relative = 'roomplan/captured-room-metadata.json'
    metadata_path = bundle / relative
    metadata = json.loads(metadata_path.read_bytes())
    metadata[field] += 1
    payload = json.dumps(metadata, sort_keys=True, separators=(',', ':')).encode()
    metadata_path.write_bytes(payload)
    manifest_path = bundle / 'manifest.json'
    manifest = json.loads(manifest_path.read_bytes())
    entry = next(row for row in manifest['files'] if row['path'] == relative)
    entry.update(bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest())
    manifest_path.write_bytes(
        json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
    )
    frozen = FrozenBundle(bundle)
    assert frozen.report['valid'] is True
    with pytest.raises(CaptureIngestionContractError, match=f'{field} conflicts with the manifest'):
        build_ingestion_plan(frozen)
