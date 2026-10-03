from __future__ import annotations

import hashlib

import json
import math
import re
import unicodedata
from uuid import UUID

from .canonical_json import hash_parts as _hash_parts
from htdt.capture_bundle import (
    FOUNDATION_REQUIRED_PATHS,
    MAX_SOURCE_REF_BYTES,
    MAX_SOURCE_REFS_PER_ENTRY,
    MAX_SOURCE_REFS_TOTAL,
    PROVENANCE,
    SOURCE_REF_SENTINELS,
    FrozenBundle,
    canonical_json_bytes,
    parse_json_bytes,
    validate_relative_path,
    validate_uuid4,
)

INGESTOR_NAME = "htdt-capture-reference-ingestor"
INGESTOR_VERSION = "1.0.0"
PLAN_SCHEMA = "htdt.capture.ingestion-plan"
PLAN_SCHEMA_VERSION = "1.0.0"
CONFIGURATION = {
    "schema_version": PLAN_SCHEMA_VERSION,
    "strict": True,
}

JSON_MEDIA_TYPE = "application/json"

# Canonical reserved payload paths for a finalized Capture Bundle v1.
QUALITY_PATH = "quality/capture-quality.json"
QUALITY_SCHEMA = "htdt.capture.quality"
SESSION_PATH = "session/capture-session.json"
SESSION_SCHEMA = "htdt.capture.session"
SESSION_CONFIGURATION_PATH = "session/capture-configuration.json"
SESSION_TIMING_PATH = "session/timing.json"
MESH_ANCHORS_PATH = "mesh/anchors.json"
ENTITIES_PATH = "annotations/entities.json"
MEASUREMENTS_PATH = "annotations/measurements.json"
ROOMPLAN_RAW_PATH = "roomplan/captured-room-data.json"
ROOMPLAN_PROCESSED_PATH = "roomplan/captured-room.json"
ROOMPLAN_METADATA_PATH = "roomplan/captured-room-metadata.json"
ROOMPLAN_METADATA_SCHEMA = "htdt.captured-room-metadata"
FRAME_DESCRIPTOR_PREFIX = "evidence/frames/"
FRAME_DESCRIPTOR_SUFFIX = ".json"

# Quality ruleset versions this ingestor can evaluate the readiness gate
# against. A finalized bundle produced under any other ruleset fails closed.
SUPPORTED_QUALITY_RULESETS = {"1.0.0", "1.1.0", "1.2.0"}


class CaptureIngestionContractError(ValueError):
    """A validated-shape contract failure in untrusted Capture evidence/plan data."""


def _validate_finite_json(value, path: str = "$") -> None:
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CaptureIngestionContractError(f"non-finite number at {path}")
        return
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise CaptureIngestionContractError(f"non-NFC string at {path}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _validate_finite_json(child, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise CaptureIngestionContractError(f"non-string object key at {path}")
            if unicodedata.normalize("NFC", key) != key:
                raise CaptureIngestionContractError(f"non-NFC key at {path}: {key!r}")
            _validate_finite_json(child, f"{path}.{key}")
        return
    raise CaptureIngestionContractError(f"unsupported JSON value at {path}: {type(value).__name__}")


def canonical_plan_bytes(value) -> bytes:
    _validate_finite_json(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


class FrozenBundle:
    """Serves bundle payloads from bytes frozen at the validation boundary.

    ``validate_bundle(path)`` proves the on-disk bundle matches its canonical
    manifest and yields the authoritative ``bundle_digest``. The reader then
    snapshots every bundle member once through the validator's own source
    abstraction and re-verifies the snapshot against the validated manifest:
    the frozen manifest must hash to ``bundle_digest``, the frozen file set
    must equal the declared payload set, and every frozen payload must match
    its manifest byte length and SHA-256. All ``read`` calls then serve only
    these frozen, hash-verified bytes, so the bytes parsed by ingestion are
    exactly the bytes hashed into ``bundle_digest`` even if the supplied path
    mutates after validation. A mutable input therefore fails closed instead
    of producing lineage bound to stale hashes.
    """

    def __init__(self, path: Path):
        self.path = path
        self.report = validate_bundle(path)
        self._payloads = self._freeze_verified_payloads()

    def _freeze_verified_payloads(self) -> dict[str, bytes]:
        source: DirectorySource | ZipSource
        archive: zipfile.ZipFile | None = None
        if self.path.is_dir():
            source = DirectorySource(self.path)
        else:
            source = ZipSource(self.path)
            archive = source.zf
        try:
            payloads = {
                name: source.read_bytes(name)
                for name in source.list_files()
            }
        finally:
            if archive is not None:
                archive.close()

        manifest_bytes = payloads.get("manifest.json")
        if manifest_bytes is None:
            raise CaptureIngestionContractError(
                "manifest.json missing from bundle after validation"
            )
        digest = hashlib.sha256(manifest_bytes).hexdigest()
        if digest != self.report["bundle_digest"]:
            raise CaptureIngestionContractError(
                "bundle manifest changed after validation: "
                "refusing to ingest bytes outside the validated digest"
            )

        manifest = parse_json_bytes(manifest_bytes)
        declared = {entry["path"]: entry for entry in manifest["files"]}
        expected = set(declared) | {"manifest.json"}
        if set(payloads) != expected:
            raise CaptureIngestionContractError(
                "bundle file set changed after validation: "
                "refusing to ingest a mutated bundle"
            )
        for entry_path, entry in declared.items():
            data = payloads[entry_path]
            if (
                len(data) != entry["bytes"]
                or hashlib.sha256(data).hexdigest() != entry["sha256"]
            ):
                raise CaptureIngestionContractError(
                    "bundle payload changed after validation: "
                    f"{entry_path}"
                )
        return payloads

    def close(self) -> None:
        self._payloads = None

    def read(self, logical_path: str) -> bytes:
        logical_path = validate_relative_path(logical_path)
        if self._payloads is None:
            raise CaptureIngestionContractError("bundle reader is closed")
        try:
            return self._payloads[logical_path]
        except KeyError as exc:
            raise CaptureIngestionContractError(
                f"validated bundle payload unexpectedly missing: {logical_path}"
            ) from exc


def _source_evidence_id(
    bundle_digest: str,
    path: str,
    payload_sha256: str,
) -> str:
    return _hash_parts(
        "htdt.capture.source-evidence.v1",
        bundle_digest,
        path,
        payload_sha256,
    )


def _raw_visual_mesh_handoff_id(
    bundle_digest: str,
    anchor_id: str,
    geometry_sha256: str,
) -> str:
    return _hash_parts(
        "htdt.capture.raw-visual-mesh-handoff.v1",
        bundle_digest,
        anchor_id,
        geometry_sha256,
    )


def _authority_record_handoff_id(
    bundle_digest: str,
    source_payload_sha256: str,
    record_kind: str,
    record_id: str,
) -> str:
    return _hash_parts(
        "htdt.capture.authority-record.v1",
        bundle_digest,
        source_payload_sha256,
        record_kind,
        record_id,
    )


# Readable document versions per schema, mirroring the capture bundle
# support matrix's `read` sets (entities 1.0.0–1.3.0, measurements
# 1.0.0–1.1.0 ship in capture_contract/). Schemas not listed here
# accept only "1.0.0".
SUPPORTED_DOCUMENT_VERSIONS = {
    "htdt.capture.entities": {"1.0.0", "1.1.0", "1.2.0", "1.3.0"},
    "htdt.capture.measurements": {"1.0.0", "1.1.0"},
}


def _require_schema(document: dict, schema: str) -> None:
    if not isinstance(document, dict):
        raise CaptureIngestionContractError(f"{schema} document root must be an object")
    if document.get("schema") != schema:
        raise CaptureIngestionContractError(
            f"unexpected document schema: expected {schema!r}, "
            f"got {document.get('schema')!r}"
        )
    versions = SUPPORTED_DOCUMENT_VERSIONS.get(schema, {"1.0.0"})
    if document.get("schema_version") not in versions:
        raise CaptureIngestionContractError(
            f"unsupported {schema} schema version: "
            f"{document.get('schema_version')!r}"
        )


def _require_document_keys(
    document: dict,
    required: set[str],
    optional: set[str],
    field: str,
) -> None:
    """Fail closed on missing or unexpected keys of a schema-owned object."""
    keys = set(document)
    missing = required - keys
    extra = keys - required - optional
    if missing or extra:
        raise CaptureIngestionContractError(
            f"{field} keys mismatch: missing={sorted(missing)} "
            f"extra={sorted(extra)}"
        )


def _require_sha256_text(value, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CaptureIngestionContractError(f"{field} must be lowercase SHA-256 hex text")
    return value


def _require_finite_number(value, field: str, minimum: float | None = None):
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(value)
    ):
        raise CaptureIngestionContractError(f"{field} must be a finite number")
    if minimum is not None and value < minimum:
        raise CaptureIngestionContractError(f"{field} must be >= {minimum}")
    return value


def _require_non_negative_int(value, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CaptureIngestionContractError(f"{field} must be a non-negative integer")
    return value


def _require_unique_text_list(value, field: str) -> list[str]:
    if not isinstance(value, list):
        raise CaptureIngestionContractError(f"{field} must be an array")
    seen: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            raise CaptureIngestionContractError(
                f"{field}[{index}] must be a non-empty string"
            )
        if item in seen:
            raise CaptureIngestionContractError(f"{field} contains duplicate: {item!r}")
        seen.add(item)
    return value


def _require_member(value, members: set, field: str) -> None:
    if value not in members:
        raise CaptureIngestionContractError(f"{field} is not a manifest member: {value!r}")


_UTC_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$"
)


def _validate_utc_timestamp(value, field: str) -> None:
    if not isinstance(value, str) or not _UTC_TIMESTAMP_RE.fullmatch(
        value
    ):
        raise CaptureIngestionContractError(
            f"{field} must be canonical UTC RFC3339 text"
        )


def _validate_matrix(
    value,
    field: str,
    representation: str,
    count: int,
) -> None:
    if not isinstance(value, dict):
        raise CaptureIngestionContractError(f"{field} must be an object")
    if value.get("representation") != representation:
        raise CaptureIngestionContractError(f"unsupported {field} representation")
    values = value.get("values")
    if not isinstance(values, list) or len(values) != count:
        raise CaptureIngestionContractError(
            f"{field}.values must contain {count} numbers"
        )
    for index, component in enumerate(values):
        if (
            not isinstance(component, (int, float))
            or isinstance(component, bool)
            or not math.isfinite(component)
        ):
            raise CaptureIngestionContractError(f"{field}.values[{index}] must be finite")


def _validate_transform(value, field: str) -> None:
    _validate_matrix(value, field, "column_major_4x4_f32", 16)
    _validate_rigid_pose(value["values"], field)


# A Capture v1 pose is a finite homogeneous rigid transform: no
# perspective row, orthonormal rotation block, unit determinant with
# proper handedness (no reflection, scale or shear). HTDT independently
# re-enforces this on imported bytes because producer-side checks may
# regress (HTDT-Capture #158). Tolerance is absolute on the f32 payload.
_RIGID_TOL = 1e-3


def _validate_rigid_pose(values: list, field: str) -> None:
    """Require a column-major 4x4 to be a proper rigid pose within
    tolerance (HTDT-Capture #158 consumer-side policy)."""
    # Column-major layout: the bottom row gathers element 3 of each
    # 4-element column (indices 3, 7, 11, 15).
    bottom = [values[3], values[7], values[11], values[15]]
    if bottom != [0, 0, 0, 1]:
        raise CaptureIngestionContractError(
            f"{field} must be a homogeneous rigid pose: "
            f"bottom row {bottom!r} != [0, 0, 0, 1] (no perspective term)"
        )
    # Rotation block columns: (0,1,2), (4,5,6), (8,9,10).
    columns = (
        (values[0], values[1], values[2]),
        (values[4], values[5], values[6]),
        (values[8], values[9], values[10]),
    )
    norms = []
    for column in columns:
        norm = math.sqrt(sum(component * component for component in column))
        norms.append(norm)
        if abs(norm - 1.0) > _RIGID_TOL:
            raise CaptureIngestionContractError(
                f"{field} rotation column norm {norm} deviates from 1 "
                f"(scale/shear semantics are not a rigid pose)"
            )
    for left in range(3):
        for right in range(left + 1, 3):
            dot = sum(
                a * b
                for a, b in zip(columns[left], columns[right])
            )
            if abs(dot) > _RIGID_TOL:
                raise CaptureIngestionContractError(
                    f"{field} rotation columns are not orthogonal "
                    f"(dot={dot})"
                )
    col0, col1, col2 = columns
    cross = (
        col0[1] * col1[2] - col0[2] * col1[1],
        col0[2] * col1[0] - col0[0] * col1[2],
        col0[0] * col1[1] - col0[1] * col1[0],
    )
    determinant = sum(a * b for a, b in zip(cross, col2))
    if not (1.0 - _RIGID_TOL) < determinant < (1.0 + _RIGID_TOL):
        raise CaptureIngestionContractError(
            f"{field} rotation determinant {determinant} is not +1 "
            f"(reflection/improper rotation rejected)"
        )


def _validate_camera_intrinsics(value, field: str) -> None:
    """Structural check for the column-major 3x3 pinhole intrinsics
    matrix (HTDT-Capture #158 consumer-side policy)."""
    _validate_matrix(value, field, "column_major_3x3_f32", 9)
    v = value["values"]
    # Column-major K = [[fx, s, cx], [0, fy, cy], [0, 0, 1]].
    if v[6] != 0 or v[7] != 0 or v[8] != 1:
        raise CaptureIngestionContractError(
            f"{field} must be a homogeneous pinhole intrinsics matrix "
            f"(bottom row [0, 0, 1])"
        )
    if v[0] <= 0 or v[4] <= 0:
        raise CaptureIngestionContractError(
            f"{field} focal lengths must be positive"
        )


def _validate_completeness_status(value, field: str) -> None:
    if not isinstance(value, dict):
        raise CaptureIngestionContractError(f"{field} must be an object")
    _require_document_keys(
        value,
        {"required", "present", "missing"},
        set(),
        field,
    )
    for key in ("required", "present", "missing"):
        _require_unique_text_list(value[key], f"{field}.{key}")


def _validate_quality_document(document: dict, field: str) -> None:
    """Schema/semantic validation of ``htdt.capture.quality`` v1.

    Mirrors ``schemas/capture-bundle-v1/quality.schema.json``; kept local
    because the ingestor must not trust a payload it has not checked.
    """
    _require_schema(document, QUALITY_SCHEMA)
    _require_document_keys(
        document,
        required={
            "schema",
            "schema_version",
            "ruleset_version",
            "ready_for_htdt_ingestion",
            "tracking_events",
            "roomplan_status",
            "active_mesh_anchor_count",
            "evidence_frame_count",
            "depth_evidence_count",
            "annotation_completeness",
            "measurement_completeness",
            "resource_events",
            "integrity_status",
            "benchmark_refs",
            "diagnostics",
        },
        optional={
            "usable_mesh_anchor_count",
            "usable_depth_sample_count",
        },
        field=field,
    )

    ruleset = document["ruleset_version"]
    if not isinstance(ruleset, str) or not ruleset:
        raise CaptureIngestionContractError(f"{field}.ruleset_version must be a string")
    if ruleset not in SUPPORTED_QUALITY_RULESETS:
        raise CaptureIngestionContractError(
            f"unsupported quality ruleset_version: {ruleset!r}"
        )

    if not isinstance(document["ready_for_htdt_ingestion"], bool):
        raise CaptureIngestionContractError(
            f"{field}.ready_for_htdt_ingestion must be a boolean"
        )

    if document["roomplan_status"] not in {
        "not_started",
        "running",
        "completed",
        "failed",
        "unavailable",
    }:
        raise CaptureIngestionContractError(f"{field}.roomplan_status is invalid")

    for key in (
        "active_mesh_anchor_count",
        "evidence_frame_count",
        "depth_evidence_count",
        "usable_mesh_anchor_count",
        "usable_depth_sample_count",
    ):
        if key in document:
            _require_non_negative_int(document[key], f"{field}.{key}")

    for key in ("annotation_completeness", "measurement_completeness"):
        _validate_completeness_status(document[key], f"{field}.{key}")

    tracking_events = document["tracking_events"]
    if not isinstance(tracking_events, list):
        raise CaptureIngestionContractError(f"{field}.tracking_events must be an array")
    for index, event in enumerate(tracking_events):
        event_field = f"{field}.tracking_events[{index}]"
        if not isinstance(event, dict):
            raise CaptureIngestionContractError(f"{event_field} must be an object")
        _require_document_keys(
            event,
            {"session_timestamp_s", "state"},
            {"reason"},
            event_field,
        )
        _require_finite_number(
            event["session_timestamp_s"],
            f"{event_field}.session_timestamp_s",
            minimum=0,
        )
        if event["state"] not in {"normal", "limited", "unavailable"}:
            raise CaptureIngestionContractError(f"{event_field}.state is invalid")
        reason = event.get("reason")
        if reason is not None and not isinstance(reason, str):
            raise CaptureIngestionContractError(
                f"{event_field}.reason must be a string or null"
            )

    resource_events = document["resource_events"]
    if not isinstance(resource_events, list):
        raise CaptureIngestionContractError(f"{field}.resource_events must be an array")
    for index, event in enumerate(resource_events):
        event_field = f"{field}.resource_events[{index}]"
        if not isinstance(event, dict):
            raise CaptureIngestionContractError(f"{event_field} must be an object")
        _require_document_keys(
            event,
            {"kind", "severity", "detail"},
            set(),
            event_field,
        )
        if event["kind"] not in {
            "thermal_pressure",
            "memory_pressure",
            "storage_pressure",
            "persistence_backlog",
            "persistence_failure",
            "interruption",
        }:
            raise CaptureIngestionContractError(f"{event_field}.kind is invalid")
        if event["severity"] not in {"info", "warning", "error"}:
            raise CaptureIngestionContractError(f"{event_field}.severity is invalid")
        if not isinstance(event["detail"], str):
            raise CaptureIngestionContractError(f"{event_field}.detail must be a string")

    if document["integrity_status"] not in {"not_checked", "pass", "fail"}:
        raise CaptureIngestionContractError(f"{field}.integrity_status is invalid")

    _require_unique_text_list(
        document["benchmark_refs"], f"{field}.benchmark_refs"
    )

    diagnostics = document["diagnostics"]
    if not isinstance(diagnostics, list):
        raise CaptureIngestionContractError(f"{field}.diagnostics must be an array")
    for index, diagnostic in enumerate(diagnostics):
        diagnostic_field = f"{field}.diagnostics[{index}]"
        if not isinstance(diagnostic, dict):
            raise CaptureIngestionContractError(f"{diagnostic_field} must be an object")
        _require_document_keys(
            diagnostic,
            {"code", "severity", "message", "evidence_refs"},
            set(),
            diagnostic_field,
        )
        for key in ("code", "message"):
            if not isinstance(diagnostic[key], str) or not diagnostic[key]:
                raise CaptureIngestionContractError(
                    f"{diagnostic_field}.{key} must be a non-empty string"
                )
        if diagnostic["severity"] not in {"info", "warning", "error"}:
            raise CaptureIngestionContractError(f"{diagnostic_field}.severity is invalid")
        _require_unique_text_list(
            diagnostic["evidence_refs"],
            f"{diagnostic_field}.evidence_refs",
        )


def _enforce_quality_gate(
    reader: FrozenBundle,
    manifest: dict,
) -> None:
    """Enforce the finalized-capture quality gate before any promotion.

    The canonical quality authority ``quality/capture-quality.json`` must be
    manifest-declared (therefore present in the frozen reader), must carry
    the JSON media type, must validate against the ``htdt.capture.quality``
    v1 schema, must name a supported ruleset, and must assert
    ``ready_for_htdt_ingestion``.

    Explicit consistency policy for ``ready_for_htdt_ingestion == true``:
    the report must assert ``integrity_status == "pass"`` and carry no
    error-severity diagnostic or resource event. Bundle integrity itself is
    never taken from the report: ``FrozenBundle`` independently
    re-verified every manifest byte count and SHA-256 before this gate runs.
    """
    entries = {entry["path"]: entry for entry in manifest["files"]}
    entry = entries.get(QUALITY_PATH)
    if entry is None:
        raise CaptureIngestionContractError(
            f"canonical quality payload missing from manifest: {QUALITY_PATH}"
        )
    if entry["media_type"] != JSON_MEDIA_TYPE:
        raise CaptureIngestionContractError(
            f"{QUALITY_PATH} must declare media_type {JSON_MEDIA_TYPE!r}"
        )

    document = parse_json_bytes(reader.read(QUALITY_PATH))
    _validate_quality_document(document, QUALITY_PATH)

    if document["ready_for_htdt_ingestion"] is not True:
        raise CaptureIngestionContractError(
            "quality report does not assert ready_for_htdt_ingestion"
        )
    if document["integrity_status"] != "pass":
        raise CaptureIngestionContractError(
            "contradictory quality report: ready_for_htdt_ingestion is "
            f"true but integrity_status is "
            f"{document['integrity_status']!r}"
        )
    error_diagnostics = [
        diagnostic["code"]
        for diagnostic in document["diagnostics"]
        if diagnostic["severity"] == "error"
    ]
    if error_diagnostics:
        raise CaptureIngestionContractError(
            "contradictory quality report: ready_for_htdt_ingestion is "
            f"true with error diagnostics {sorted(error_diagnostics)}"
        )
    error_events = [
        event["kind"]
        for event in document["resource_events"]
        if event["severity"] == "error"
    ]
    if error_events:
        raise CaptureIngestionContractError(
            "contradictory quality report: ready_for_htdt_ingestion is "
            f"true with error resource events {sorted(error_events)}"
        )
    return document


def _validate_session_document(
    document: dict,
    manifest: dict,
    declared: dict[str, dict],
) -> None:
    """Bind ``session/capture-session.json`` to the manifest identity set."""
    _require_schema(document, SESSION_SCHEMA)
    field = SESSION_PATH
    _require_document_keys(
        document,
        required={
            "schema",
            "schema_version",
            "capture_session_id",
            "coordinate_space_id",
        },
        optional={
            "capture_mode",
            "started_at",
            "ended_at",
            "configuration_ref",
            "timing_ref",
        },
        field=field,
    )

    session_ids = set(manifest["capture_session_ids"])
    coordinate_ids = set(manifest["coordinate_space_ids"])

    capture_session_id = document["capture_session_id"]
    validate_uuid4(capture_session_id, f"{field}.capture_session_id")
    _require_member(
        capture_session_id,
        session_ids,
        f"{field}.capture_session_id",
    )
    coordinate_space_id = document["coordinate_space_id"]
    validate_uuid4(coordinate_space_id, f"{field}.coordinate_space_id")
    _require_member(
        coordinate_space_id,
        coordinate_ids,
        f"{field}.coordinate_space_id",
    )

    capture_mode = document.get("capture_mode")
    if capture_mode is not None and capture_mode not in {
        "roomplan_mesh",
        "evidence_depth",
        "degraded_no_depth",
    }:
        raise CaptureIngestionContractError(f"{field}.capture_mode is invalid")

    for key in ("started_at", "ended_at"):
        value = document.get(key)
        if value is not None and not isinstance(value, str):
            raise CaptureIngestionContractError(f"{field}.{key} must be a string or null")

    # Configuration/timing references must resolve to the canonical
    # session payloads declared in this bundle.
    for key, canonical in (
        ("configuration_ref", SESSION_CONFIGURATION_PATH),
        ("timing_ref", SESSION_TIMING_PATH),
    ):
        reference = document.get(key)
        if reference is None:
            continue
        if not isinstance(reference, str) or reference != canonical:
            raise CaptureIngestionContractError(
                f"{field}.{key} must be {canonical!r}, got {reference!r}"
            )
        if canonical not in declared:
            raise CaptureIngestionContractError(
                f"{field}.{key} resolves to undeclared payload: "
                f"{canonical}"
            )


def _validate_frame_descriptor(
    document: dict,
    path: str,
    manifest: dict,
    declared: dict[str, dict],
) -> str:
    """Validate one ``evidence/frames/*.json`` descriptor and its links.

    Returns the validated ``frame_id`` for the identity registry.
    """
    _require_document_keys(
        document,
        required={
            "frame_id",
            "capture_session_id",
            "coordinate_space_id",
            "session_timestamp_s",
            "T_world_from_camera",
            "intrinsics",
            "image_width",
            "image_height",
            "pixel_format_fourcc",
            "pixel_relative_path",
            "pixel_byte_count",
            "pixel_sha256",
            "exif_allowlisted",
            "depth_status",
        },
        optional={"depth"},
        field=path,
    )

    frame_id = document["frame_id"]
    validate_uuid4(frame_id, f"{path}.frame_id")

    session_ids = set(manifest["capture_session_ids"])
    coordinate_ids = set(manifest["coordinate_space_ids"])
    validate_uuid4(
        document["capture_session_id"], f"{path}.capture_session_id"
    )
    _require_member(
        document["capture_session_id"],
        session_ids,
        f"{path}.capture_session_id",
    )
    validate_uuid4(
        document["coordinate_space_id"], f"{path}.coordinate_space_id"
    )
    _require_member(
        document["coordinate_space_id"],
        coordinate_ids,
        f"{path}.coordinate_space_id",
    )

    _require_finite_number(
        document["session_timestamp_s"],
        f"{path}.session_timestamp_s",
        minimum=0,
    )
    _validate_transform(
        document["T_world_from_camera"],
        f"{path}.T_world_from_camera",
    )
    _validate_camera_intrinsics(
        document["intrinsics"],
        f"{path}.intrinsics",
    )
    for key in ("image_width", "image_height"):
        value = document[key]
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise CaptureIngestionContractError(f"{path}.{key} must be a positive integer")
    pixel_format = document["pixel_format_fourcc"]
    if (
        not isinstance(pixel_format, int)
        or isinstance(pixel_format, bool)
        or not 0 <= pixel_format <= 0xFFFFFFFF
    ):
        raise CaptureIngestionContractError(f"{path}.pixel_format_fourcc is invalid")

    def _resolve_declared_payload(
        relative_path, byte_count, sha256, ref_field
    ) -> None:
        if not isinstance(relative_path, str) or not relative_path:
            raise CaptureIngestionContractError(
                f"{path}.{ref_field} must be a non-empty string"
            )
        if (
            not isinstance(byte_count, int)
            or isinstance(byte_count, bool)
            or byte_count < 1
        ):
            raise CaptureIngestionContractError(
                f"{path}.{ref_field} byte count must be positive"
            )
        target = declared.get(relative_path)
        if target is None:
            raise CaptureIngestionContractError(
                f"{path}.{ref_field} resolves to undeclared payload: "
                f"{relative_path!r}"
            )
        if target["sha256"] != sha256 or target["bytes"] != byte_count:
            raise CaptureIngestionContractError(
                f"{path}.{ref_field} is inconsistent with the declared "
                f"payload at {relative_path!r}"
            )

    _resolve_declared_payload(
        document["pixel_relative_path"],
        document["pixel_byte_count"],
        _require_sha256_text(
            document["pixel_sha256"], f"{path}.pixel_sha256"
        ),
        "pixel_relative_path",
    )

    exif = document["exif_allowlisted"]
    if not isinstance(exif, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in exif.items()
    ):
        raise CaptureIngestionContractError(
            f"{path}.exif_allowlisted must map strings to strings"
        )

    depth_status = document["depth_status"]
    if depth_status not in {
        "not_requested",
        "unavailable",
        "captured_scene_depth",
        "captured_smoothed_scene_depth",
    }:
        raise CaptureIngestionContractError(f"{path}.depth_status is invalid")

    depth = document.get("depth")
    if depth is not None:
        depth_field = f"{path}.depth"
        if not isinstance(depth, dict):
            raise CaptureIngestionContractError(f"{depth_field} must be an object")
        _require_document_keys(
            depth,
            required={
                "kind",
                "depth_relative_path",
                "depth_byte_count",
                "depth_sha256",
            },
            optional={
                "confidence_relative_path",
                "confidence_byte_count",
                "confidence_sha256",
            },
            field=depth_field,
        )
        if depth["kind"] not in {"scene_depth", "smoothed_scene_depth"}:
            raise CaptureIngestionContractError(f"{depth_field}.kind is invalid")
        _resolve_declared_payload(
            depth["depth_relative_path"],
            depth["depth_byte_count"],
            _require_sha256_text(
                depth["depth_sha256"], f"{depth_field}.depth_sha256"
            ),
            "depth.depth_relative_path",
        )
        confidence_values = (
            depth.get("confidence_relative_path"),
            depth.get("confidence_byte_count"),
            depth.get("confidence_sha256"),
        )
        if any(value is not None for value in confidence_values):
            if not all(value is not None for value in confidence_values):
                raise CaptureIngestionContractError(
                    f"{depth_field} confidence reference is incomplete"
                )
            _resolve_declared_payload(
                depth["confidence_relative_path"],
                depth["confidence_byte_count"],
                _require_sha256_text(
                    depth["confidence_sha256"],
                    f"{depth_field}.confidence_sha256",
                ),
                "depth.confidence_relative_path",
            )

    # The discrete depth status flag and the depth reference are one
    # authority; disagreeing halves are an identity contradiction.
    expected_kind = {
        "captured_scene_depth": "scene_depth",
        "captured_smoothed_scene_depth": "smoothed_scene_depth",
    }.get(depth_status)
    if expected_kind is None:
        if depth is not None:
            raise CaptureIngestionContractError(
                f"{path}.depth_status {depth_status!r} contradicts the "
                "present depth reference"
            )
    elif depth is None or depth["kind"] != expected_kind:
        raise CaptureIngestionContractError(
            f"{path}.depth_status {depth_status!r} requires a "
            f"{expected_kind!r} depth reference"
        )

    return frame_id


def _validate_identity_membership(
    reader: FrozenBundle,
    manifest: dict,
) -> dict[str, dict]:
    """Cross-payload identity pass before any source promotion (#153).

    Validates the canonical session authority and every frame descriptor
    against the manifest's ``capture_session_ids``/``coordinate_space_ids``
    registry, and resolves each frame's pixel/depth/confidence payload
    references to declared, hash-consistent bundle files.

    Returns the frame registry ``{frame_id: {"path", "coordinate_space_id"}}``
    for later evidence-reference resolution.
    """
    declared = {entry["path"]: entry for entry in manifest["files"]}

    session_entry = declared.get(SESSION_PATH)
    if session_entry is not None:
        if session_entry["media_type"] != JSON_MEDIA_TYPE:
            raise CaptureIngestionContractError(
                f"{SESSION_PATH} must declare media_type "
                f"{JSON_MEDIA_TYPE!r}"
            )
        document = parse_json_bytes(reader.read(SESSION_PATH))
        _validate_session_document(document, manifest, declared)

    frame_registry: dict[str, dict] = {}
    for path, entry in declared.items():
        if not (
            path.startswith(FRAME_DESCRIPTOR_PREFIX)
            and path.endswith(FRAME_DESCRIPTOR_SUFFIX)
            and path != FRAME_DESCRIPTOR_PREFIX + FRAME_DESCRIPTOR_SUFFIX
        ):
            continue
        if entry["media_type"] != JSON_MEDIA_TYPE:
            raise CaptureIngestionContractError(
                f"{path} must declare media_type {JSON_MEDIA_TYPE!r}"
            )
        document = parse_json_bytes(reader.read(path))
        if not isinstance(document, dict):
            raise CaptureIngestionContractError(f"{path} must be a JSON object")
        frame_id = _validate_frame_descriptor(
            document, path, manifest, declared
        )
        if frame_id in frame_registry:
            raise CaptureIngestionContractError(f"duplicate frame identity: {frame_id}")
        frame_registry[frame_id] = {
            "path": path,
            "coordinate_space_id": document["coordinate_space_id"],
        }
    return frame_registry


def _build_source_registry(
    manifest: dict,
    bundle_digest: str,
) -> tuple[list[dict], dict[str, dict]]:
    records: list[dict] = []
    by_path: dict[str, dict] = {}
    # Source-lookup indexes are built once (#195): ref resolution is
    # O(files + refs), never per-ref manifest scans.
    paths = {entry["path"] for entry in manifest["files"]}
    entries_by_sha256: dict[str, list[dict]] = {}
    for entry in manifest["files"]:
        entries_by_sha256.setdefault(
            entry["sha256"], []
        ).append(entry)
    raw_roomplan_hashes = {
        entry["sha256"]
        for entry in manifest["files"]
        if entry["provenance_class"] == "apple_roomplan_raw_scan"
    }
    session_ids = set(manifest["capture_session_ids"])

    total_refs = 0
    for entry in manifest["files"]:
        path = entry["path"]
        refs = entry.get("source_refs", [])
        if len(refs) > MAX_SOURCE_REFS_PER_ENTRY:
            raise CaptureIngestionContractError(
                f"too many source_refs for {path} "
                f"(max {MAX_SOURCE_REFS_PER_ENTRY})"
            )
        total_refs += len(refs)
        if total_refs > MAX_SOURCE_REFS_TOTAL:
            raise CaptureIngestionContractError(
                "manifest exceeds the aggregate source_ref budget "
                f"({MAX_SOURCE_REFS_TOTAL})"
            )
        resolved_sha_refs: list[str] = []

        for source_ref in refs:
            if len(source_ref.encode("utf-8")) > MAX_SOURCE_REF_BYTES:
                raise CaptureIngestionContractError(
                    f"oversized source_ref for {path}"
                )
            if source_ref.startswith("sha256:"):
                target_hash = source_ref.removeprefix("sha256:")
                # #193: a SHA-256 ref must name exactly one payload
                # authority. Identical bytes under different paths are
                # distinct authorities; bind them with a path: ref.
                if target_hash == entry["sha256"]:
                    raise CaptureIngestionContractError(
                        f"self-referential sha256 source_ref for {path}: "
                        f"{source_ref}"
                    )
                matches = entries_by_sha256.get(target_hash, [])
                if not matches:
                    raise CaptureIngestionContractError(
                        f"unresolved SHA-256 source_ref for {path}: "
                        f"{source_ref}"
                    )
                if len(matches) > 1:
                    raise CaptureIngestionContractError(
                        f"ambiguous SHA-256 source_ref for {path}: "
                        f"{source_ref} names {len(matches)} payload "
                        f"authorities; use a path: reference to bind "
                        f"exactly one"
                    )
                resolved_sha_refs.append(target_hash)
            elif source_ref in SOURCE_REF_SENTINELS:
                # Enumerated sentinel refs carry no resolvable target.
                pass
            elif source_ref.startswith("path:"):
                target_path = source_ref.removeprefix("path:")
                target_path = validate_relative_path(target_path)
                if target_path == path:
                    raise CaptureIngestionContractError(
                        f"self-referential path source_ref for {path}: "
                        f"{source_ref}"
                    )
                if target_path not in paths:
                    raise CaptureIngestionContractError(
                        f"unresolved path source_ref for {path}: "
                        f"{source_ref}"
                    )
            elif source_ref.startswith("capture_session:"):
                session_ref = source_ref.removeprefix("capture_session:")
                validate_uuid4(session_ref, f"{path} source_ref")
                if session_ref not in session_ids:
                    raise CaptureIngestionContractError(
                        f"capture_session source_ref names an unknown "
                        f"session for {path}: {source_ref}"
                    )
            else:
                raise CaptureIngestionContractError(
                    f"unsupported source_ref for {path}: {source_ref}"
                )

        if entry["provenance_class"] == "apple_roomplan_inference":
            raw_refs = [
                value
                for value in resolved_sha_refs
                if value in raw_roomplan_hashes
            ]
            if len(raw_refs) != 1:
                raise CaptureIngestionContractError(
                    "processed RoomPlan must reference exactly one raw "
                    "RoomPlan payload SHA-256"
                )

        record = {
            "source_evidence_id": _source_evidence_id(
                bundle_digest,
                path,
                entry["sha256"],
            ),
            "bundle_digest": bundle_digest,
            "capture_revision_id": manifest["capture_revision_id"],
            "path": path,
            "payload_sha256": entry["sha256"],
            "bytes": entry["bytes"],
            "media_type": entry["media_type"],
            "producer": entry["producer"],
            "provenance_class": entry["provenance_class"],
            "role": entry["role"],
            "source_refs": entry.get("source_refs", []),
        }
        records.append(record)
        by_path[path] = record

    records.sort(key=lambda item: item["path"].encode("utf-8"))
    return records, by_path


# Reserved-path metadata contract for canonical RoomPlan payloads (#187):
# each canonical path binds exactly one RoomPlan semantic role.
ROOMPLAN_PATH_CONTRACT = {
    ROOMPLAN_RAW_PATH: {
        "kind": "raw_scan",
        "provenance_class": "apple_roomplan_raw_scan",
        "producer": "roomplan_capture",
    },
    ROOMPLAN_PROCESSED_PATH: {
        "kind": "postprocessed_inference",
        "provenance_class": "apple_roomplan_inference",
        "producer": "roomplan_builder",
    },
}
ROOMPLAN_PROVENANCE = {
    contract["provenance_class"] for contract in ROOMPLAN_PATH_CONTRACT.values()
}


def _roomplan_record(entry: dict, kind: str, source_by_path) -> dict:
    return {
        "kind": kind,
        "source_evidence_id": source_by_path[entry["path"]][
            "source_evidence_id"
        ],
        "path": entry["path"],
        "payload_sha256": entry["sha256"],
        "provenance_class": entry["provenance_class"],
        "source_refs": entry.get("source_refs", []),
    }


def _build_roomplan_records(
    manifest: dict,
    source_by_path: dict[str, dict],
) -> list[dict]:
    """Select RoomPlan handoff records via the canonical path contract.

    When the manifest declares the reserved RoomPlan paths, they are the
    sole RoomPlan authorities: each must carry its bound media type,
    producer, provenance class and canonical role, and no other payload may
    claim RoomPlan provenance. Only when no canonical RoomPlan path is
    declared at all (legacy bundles) does selection fall back to
    provenance-class membership.
    """
    declared = {entry["path"]: entry for entry in manifest["files"]}
    canonical_declared = [
        path for path in ROOMPLAN_PATH_CONTRACT if path in declared
    ]

    result: list[dict] = []
    if canonical_declared:
        for path in canonical_declared:
            entry = declared[path]
            contract = ROOMPLAN_PATH_CONTRACT[path]
            if entry["media_type"] != JSON_MEDIA_TYPE:
                raise CaptureIngestionContractError(
                    f"{path} must declare media_type {JSON_MEDIA_TYPE!r}"
                )
            if entry["producer"] != contract["producer"]:
                raise CaptureIngestionContractError(
                    f"{path} must declare producer "
                    f"{contract['producer']!r}"
                )
            if entry["provenance_class"] != contract["provenance_class"]:
                raise CaptureIngestionContractError(
                    f"{path} must declare provenance_class "
                    f"{contract['provenance_class']!r}"
                )
            if entry["role"] != "canonical":
                raise CaptureIngestionContractError(
                    f"{path} must declare canonical role"
                )
            result.append(
                _roomplan_record(entry, contract["kind"], source_by_path)
            )

        stray = sorted(
            entry["path"]
            for entry in manifest["files"]
            if entry["provenance_class"] in ROOMPLAN_PROVENANCE
            and entry["path"] not in ROOMPLAN_PATH_CONTRACT
        )
        if stray:
            raise CaptureIngestionContractError(
                "RoomPlan provenance declared outside the canonical "
                f"RoomPlan paths: {stray}"
            )
    else:
        for entry in manifest["files"]:
            provenance = entry["provenance_class"]
            if provenance not in ROOMPLAN_PROVENANCE:
                continue
            result.append(
                _roomplan_record(
                    entry,
                    (
                        "raw_scan"
                        if provenance == "apple_roomplan_raw_scan"
                        else "postprocessed_inference"
                    ),
                    source_by_path,
                )
            )

    result.sort(key=lambda item: item["path"].encode("utf-8"))
    return result


def _load_roomplan_capture_metadata(
    reader: FrozenBundle,
    manifest: dict,
    source_by_path: dict[str, dict],
    roomplan_records: list[dict],
) -> dict | None:
    """Validate and carry ``roomplan/captured-room-metadata.json`` (#152).

    The canonical metadata payload binds the raw and processed RoomPlan
    artifacts to the manifest identity registry. It is optional evidence:
    an undeclared path yields ``None``; a declared but malformed or
    identity-conflicting document fails closed.
    """
    entry = source_by_path.get(ROOMPLAN_METADATA_PATH)
    if entry is None:
        return None
    if entry["media_type"] != JSON_MEDIA_TYPE:
        raise CaptureIngestionContractError(
            f"{ROOMPLAN_METADATA_PATH} must declare media_type "
            f"{JSON_MEDIA_TYPE!r}"
        )

    document = parse_json_bytes(reader.read(ROOMPLAN_METADATA_PATH))
    _require_schema(document, ROOMPLAN_METADATA_SCHEMA)
    field = ROOMPLAN_METADATA_PATH
    _require_document_keys(
        document,
        required={
            "schema",
            "schema_version",
            "capture_revision_id",
            "capture_session_id",
            "coordinate_space_id",
            "raw_payload_path",
            "raw_sha256",
        },
        # The captured-room-metadata payload is an external
        # RoomPlan-lineage family: emitters append lineage fields
        # (byte counts, serialization formats, runtime) that the
        # receiver accepts but does not require.
        optional={
            "processed_payload_path",
            "processed_sha256",
            "processed_byte_count",
            "processed_serialization_format",
            "raw_byte_count",
            "raw_serialization_format",
            "captured_room_version",
            "runtime",
            "summary",
            "surface_count",
            "object_count",
            "dimensions",
        },
        field=field,
    )
    for key in ("raw_byte_count", "processed_byte_count"):
        if key in document:
            _require_non_negative_int(document[key], f"{field}.{key}")
    for key in (
        "raw_serialization_format",
        "processed_serialization_format",
    ):
        if key in document and not isinstance(document[key], str):
            raise CaptureIngestionContractError(
                f"{field}.{key} must be a string"
            )
    if "runtime" in document and not isinstance(
        document["runtime"], dict
    ):
        raise CaptureIngestionContractError(
            f"{field}.runtime must be an object"
        )

    validate_uuid4(
        document["capture_revision_id"], f"{field}.capture_revision_id"
    )
    if document["capture_revision_id"] != manifest["capture_revision_id"]:
        raise CaptureIngestionContractError(
            f"{field}.capture_revision_id conflicts with the manifest"
        )
    validate_uuid4(
        document["capture_session_id"], f"{field}.capture_session_id"
    )
    _require_member(
        document["capture_session_id"],
        set(manifest["capture_session_ids"]),
        f"{field}.capture_session_id",
    )
    validate_uuid4(
        document["coordinate_space_id"], f"{field}.coordinate_space_id"
    )
    _require_member(
        document["coordinate_space_id"],
        set(manifest["coordinate_space_ids"]),
        f"{field}.coordinate_space_id",
    )

    declared = {entry["path"]: entry for entry in manifest["files"]}
    raw_paths = {
        record["path"]
        for record in roomplan_records
        if record["kind"] == "raw_scan"
    }
    processed_paths = {
        record["path"]
        for record in roomplan_records
        if record["kind"] == "postprocessed_inference"
    }

    raw_payload_path = document["raw_payload_path"]
    if not isinstance(raw_payload_path, str) or not raw_payload_path:
        raise CaptureIngestionContractError(
            f"{field}.raw_payload_path must be a non-empty string"
        )
    _require_sha256_text(document["raw_sha256"], f"{field}.raw_sha256")
    if raw_payload_path not in raw_paths:
        raise CaptureIngestionContractError(
            f"{field}.raw_payload_path does not name the selected raw "
            f"RoomPlan record: {raw_payload_path!r}"
        )
    if declared[raw_payload_path]["sha256"] != document["raw_sha256"]:
        raise CaptureIngestionContractError(
            f"{field}.raw_sha256 conflicts with the manifest"
        )
    if (
        "raw_byte_count" in document
        and document["raw_byte_count"] != declared[raw_payload_path]["bytes"]
    ):
        raise CaptureIngestionContractError(
            f"{field}.raw_byte_count conflicts with the manifest"
        )

    processed_payload_path = document.get("processed_payload_path")
    processed_sha256 = document.get("processed_sha256")
    if (processed_payload_path is None) != (processed_sha256 is None):
        raise CaptureIngestionContractError(
            f"{field} processed payload reference is incomplete"
        )
    if processed_payload_path is not None:
        if (
            not isinstance(processed_payload_path, str)
            or not processed_payload_path
        ):
            raise CaptureIngestionContractError(
                f"{field}.processed_payload_path must be a non-empty "
                "string"
            )
        _require_sha256_text(
            processed_sha256, f"{field}.processed_sha256"
        )
        if processed_payload_path not in processed_paths:
            raise CaptureIngestionContractError(
                f"{field}.processed_payload_path does not name the "
                f"selected processed RoomPlan record: "
                f"{processed_payload_path!r}"
            )
        if (
            declared[processed_payload_path]["sha256"]
            != processed_sha256
        ):
            raise CaptureIngestionContractError(
                f"{field}.processed_sha256 conflicts with the manifest"
            )
        if (
            "processed_byte_count" in document
            and document["processed_byte_count"] != declared[processed_payload_path]["bytes"]
        ):
            raise CaptureIngestionContractError(
                f"{field}.processed_byte_count conflicts with the manifest"
            )

    for key in ("surface_count", "object_count"):
        value = document.get(key)
        if value is not None:
            _require_non_negative_int(value, f"{field}.{key}")

    dimensions = document.get("dimensions")
    if dimensions is not None:
        if not isinstance(dimensions, dict):
            raise CaptureIngestionContractError(f"{field}.dimensions must be an object")
        for name, value in dimensions.items():
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(value)
            ):
                raise CaptureIngestionContractError(
                    f"{field}.dimensions[{name!r}] must be finite"
                )

    captured_room_version = document.get("captured_room_version")
    if (
        captured_room_version is not None
        and not isinstance(captured_room_version, str)
    ):
        raise CaptureIngestionContractError(
            f"{field}.captured_room_version must be a string"
        )

    summary = document.get("summary")
    if summary is not None:
        if not isinstance(summary, dict):
            raise CaptureIngestionContractError(
                f"{field}.summary must be an object"
            )
        _require_document_keys(
            summary,
            required=set(),
            optional={"surface_count", "object_count", "dimensions_m"},
            field=f"{field}.summary",
        )
        for key in ("surface_count", "object_count"):
            value = summary.get(key)
            if value is not None:
                _require_non_negative_int(
                    value, f"{field}.summary.{key}"
                )
        summary_dimensions = summary.get("dimensions_m")
        if summary_dimensions is not None:
            if not isinstance(summary_dimensions, dict):
                raise CaptureIngestionContractError(
                    f"{field}.summary.dimensions_m must be an object"
                )
            _require_document_keys(
                summary_dimensions,
                required={"x_m", "y_m", "z_m"},
                optional=set(),
                field=f"{field}.summary.dimensions_m",
            )
            for name, value in summary_dimensions.items():
                if (
                    not isinstance(value, (int, float))
                    or isinstance(value, bool)
                    or not math.isfinite(value)
                    or value < 0
                ):
                    raise CaptureIngestionContractError(
                        f"{field}.summary.dimensions_m[{name!r}] "
                        "must be a non-negative finite number"
                    )

    return document


def _load_mesh_anchor_index(
    reader: FrozenBundle,
    manifest: dict,
    source_by_path: dict[str, dict],
) -> dict[str, dict]:
    """Parse and validate ``mesh/anchors.json`` once for all consumers."""
    index_path = MESH_ANCHORS_PATH
    if index_path not in source_by_path:
        return {}

    index_source = source_by_path[index_path]
    if index_source["provenance_class"] != "arkit_mesh_reconstruction":
        raise CaptureIngestionContractError(
            "mesh/anchors.json must retain arkit_mesh_reconstruction provenance"
        )

    document = parse_json_bytes(reader.read(index_path))
    _require_schema(document, "htdt.capture.mesh-anchors")
    anchors = document.get("anchors")
    if not isinstance(anchors, list):
        raise CaptureIngestionContractError("mesh anchors must be an array")

    session_ids = set(manifest["capture_session_ids"])
    coordinate_ids = set(manifest["coordinate_space_ids"])
    result: dict[str, dict] = {}

    for index, anchor in enumerate(anchors):
        if not isinstance(anchor, dict):
            raise CaptureIngestionContractError(f"anchors[{index}] must be an object")
        anchor_id = anchor.get("anchor_id")
        validate_uuid4(anchor_id, f"anchors[{index}].anchor_id")
        if anchor_id in result:
            raise CaptureIngestionContractError(f"duplicate mesh anchor ID: {anchor_id}")

        capture_session_id = anchor.get("capture_session_id")
        coordinate_space_id = anchor.get("coordinate_space_id")
        validate_uuid4(
            capture_session_id,
            f"anchors[{index}].capture_session_id",
        )
        validate_uuid4(
            coordinate_space_id,
            f"anchors[{index}].coordinate_space_id",
        )
        if capture_session_id not in session_ids:
            raise CaptureIngestionContractError(
                f"mesh anchor references unknown capture_session_id: "
                f"{capture_session_id}"
            )
        if coordinate_space_id not in coordinate_ids:
            raise CaptureIngestionContractError(
                f"mesh anchor references unknown coordinate_space_id: "
                f"{coordinate_space_id}"
            )

        geometry_path = anchor.get("geometry_path")
        geometry_sha256 = anchor.get("geometry_sha256")
        if (
            not isinstance(geometry_path, str)
            or geometry_path not in source_by_path
        ):
            raise CaptureIngestionContractError(
                f"mesh anchor geometry payload missing: {geometry_path!r}"
            )
        geometry_source = source_by_path[geometry_path]
        if geometry_source["provenance_class"] != "arkit_mesh_reconstruction":
            raise CaptureIngestionContractError(
                f"mesh geometry provenance is not ARKit reconstruction: "
                f"{geometry_path}"
            )
        if geometry_source["payload_sha256"] != geometry_sha256:
            raise CaptureIngestionContractError(
                f"mesh anchor geometry hash mismatch: {geometry_path}"
            )

        _validate_transform(
            anchor.get("T_world_from_mesh_anchor"),
            f"anchors[{index}].T_world_from_mesh_anchor",
        )
        vertex_count = anchor.get("vertex_count")
        face_count = anchor.get("face_count")
        if (
            not isinstance(vertex_count, int)
            or isinstance(vertex_count, bool)
            or vertex_count < 0
            or not isinstance(face_count, int)
            or isinstance(face_count, bool)
            or face_count < 0
        ):
            raise CaptureIngestionContractError("mesh anchor counts must be non-negative integers")
        timestamp = anchor.get("session_timestamp_s")
        if timestamp is not None and (
            not isinstance(timestamp, (int, float))
            or isinstance(timestamp, bool)
            or not math.isfinite(timestamp)
        ):
            raise CaptureIngestionContractError("mesh anchor timestamp must be finite")

        result[anchor_id] = anchor
    return result


def _build_raw_visual_mesh_handoffs(
    manifest: dict,
    bundle_digest: str,
    source_by_path: dict[str, dict],
    anchor_index: dict[str, dict],
) -> list[dict]:
    index_path = MESH_ANCHORS_PATH
    if not anchor_index:
        return []
    index_source = source_by_path[index_path]

    result: list[dict] = []
    for anchor_id, anchor in anchor_index.items():
        capture_session_id = anchor["capture_session_id"]
        coordinate_space_id = anchor["coordinate_space_id"]
        geometry_path = anchor["geometry_path"]
        geometry_sha256 = anchor["geometry_sha256"]
        geometry_source = source_by_path[geometry_path]
        timestamp = anchor.get("session_timestamp_s")

        result.append(
            {
                "raw_visual_mesh_handoff_id": _raw_visual_mesh_handoff_id(
                    bundle_digest,
                    anchor_id,
                    geometry_sha256,
                ),
                "bundle_digest": bundle_digest,
                "anchor_id": anchor_id,
                "anchor_record_locator": (
                    f"{index_path}#anchor:{anchor_id}"
                ),
                "anchor_index_source_evidence_id": index_source[
                    "source_evidence_id"
                ],
                "geometry_source_evidence_id": geometry_source[
                    "source_evidence_id"
                ],
                "geometry_path": geometry_path,
                "geometry_sha256": geometry_sha256,
                "capture_session_id": capture_session_id,
                "coordinate_space_id": coordinate_space_id,
                "T_world_from_mesh_anchor": anchor[
                    "T_world_from_mesh_anchor"
                ],
                "session_timestamp_s": timestamp,
                "vertex_count": anchor["vertex_count"],
                "face_count": anchor["face_count"],
            }
        )

    result.sort(key=lambda item: item["anchor_id"])
    return result


class _EvidenceRefContext:
    """Bundle-scoped targets an authority-record reference may resolve to."""

    def __init__(
        self,
        bundle_digest: str,
        source_by_path: dict[str, dict],
        anchor_index: dict[str, dict],
        mesh_handoff_by_anchor: dict[str, str],
        frame_registry: dict[str, dict],
    ):
        self.bundle_digest = bundle_digest
        self.source_by_path = source_by_path
        self.anchor_index = anchor_index
        self.mesh_handoff_by_anchor = mesh_handoff_by_anchor
        self.frame_registry = frame_registry
        self.frame_coordinate_by_path = {
            frame["path"]: frame["coordinate_space_id"]
            for frame in frame_registry.values()
        }
        self.entity_ids: set[str] = set()
        self.measurement_ids: set[str] = set()
        self.entity_source_sha256: str | None = None
        self.measurement_source_sha256: str | None = None

    def _authority_handoff(self, record_kind: str, record_id: str) -> str:
        source_sha256 = (
            self.entity_source_sha256
            if record_kind == "annotation"
            else self.measurement_source_sha256
        )
        return _authority_record_handoff_id(
            self.bundle_digest, source_sha256, record_kind, record_id
        )

    def resolve(self, ref, field: str, coordinate_space_id) -> dict:
        """Resolve one v1 evidence reference or fail closed.

        Grammar: ``path:<bundle-path>``, ``mesh_anchor:<uuid4>``,
        ``frame:<uuid4>``, ``entity:<uuid4>``, ``measurement:<uuid4>`` and
        the annotation-authored ``user:<token>`` marker. Any other form is
        unsupported evidence grammar and rejects the record.
        """
        if not isinstance(ref, str) or not ref:
            raise CaptureIngestionContractError(f"{field} must be a non-empty string")
        prefix, separator, value = ref.partition(":")
        if not separator or not value:
            raise CaptureIngestionContractError(
                f"{field} uses unsupported reference grammar: {ref!r}"
            )

        if prefix in {"user", "instrument_reading"}:
            # ``instrument_reading:<id>`` names an external instrument
            # reading the adapter reported; like ``user:`` it is an
            # authored token with no in-bundle target.
            return {"ref": ref, "kind": "annotation_authored", "target": None}

        if prefix == "path":
            target = self.source_by_path.get(value)
            if target is None:
                raise CaptureIngestionContractError(
                    f"{field} resolves to undeclared bundle path: {ref!r}"
                )
            self._require_coordinate_compatible(
                self.frame_coordinate_by_path.get(value),
                coordinate_space_id,
                field,
                ref,
            )
            return {
                "ref": ref,
                "kind": "source_evidence",
                "target": target["source_evidence_id"],
            }

        if prefix in {"mesh_anchor", "frame", "entity", "measurement"}:
            validate_uuid4(value, field)
            if prefix == "mesh_anchor":
                anchor = self.anchor_index.get(value)
                if anchor is None:
                    raise CaptureIngestionContractError(
                        f"{field} references unknown mesh anchor: {ref!r}"
                    )
                self._require_coordinate_compatible(
                    anchor["coordinate_space_id"],
                    coordinate_space_id,
                    field,
                    ref,
                )
                return {
                    "ref": ref,
                    "kind": "raw_visual_mesh_handoff",
                    "target": self.mesh_handoff_by_anchor[value],
                }
            if prefix == "frame":
                frame = self.frame_registry.get(value)
                if frame is None:
                    raise CaptureIngestionContractError(
                        f"{field} references unknown frame: {ref!r}"
                    )
                self._require_coordinate_compatible(
                    frame["coordinate_space_id"],
                    coordinate_space_id,
                    field,
                    ref,
                )
                return {
                    "ref": ref,
                    "kind": "source_evidence",
                    "target": self.source_by_path[frame["path"]][
                        "source_evidence_id"
                    ],
                }
            record_kind = "annotation" if prefix == "entity" else "measurement"
            id_set = (
                self.entity_ids
                if prefix == "entity"
                else self.measurement_ids
            )
            if value not in id_set:
                raise CaptureIngestionContractError(
                    f"{field} references unknown {prefix}: {ref!r}"
                )
            return {
                "ref": ref,
                "kind": "authority_record",
                "target": self._authority_handoff(record_kind, value),
            }

        raise CaptureIngestionContractError(
            f"{field} uses unsupported reference grammar: {ref!r}"
        )

    @staticmethod
    def _require_coordinate_compatible(
        target_coordinate_space_id,
        record_coordinate_space_id,
        field: str,
        ref: str,
    ) -> None:
        if (
            target_coordinate_space_id is not None
            and record_coordinate_space_id is not None
            and target_coordinate_space_id != record_coordinate_space_id
        ):
            raise CaptureIngestionContractError(
                f"{field} crosses coordinate spaces: {ref!r} binds "
                f"{target_coordinate_space_id} but the record lives in "
                f"{record_coordinate_space_id}"
            )


def _resolve_ref_list(
    refs,
    field: str,
    context: _EvidenceRefContext,
    coordinate_space_id,
) -> list[dict]:
    _require_unique_text_list(refs, field)
    return [
        context.resolve(ref, f"{field}[{index}]", coordinate_space_id)
        for index, ref in enumerate(refs)
    ]


def _validate_entity_placement(
    placement,
    field: str,
    context: _EvidenceRefContext,
    coordinate_space_id,
) -> list[dict]:
    if not isinstance(placement, dict):
        raise CaptureIngestionContractError(f"{field} must be an object")
    _require_document_keys(
        placement,
        required={"method", "source_evidence_refs"},
        optional={
            "source_semantic_entity_id",
            "source_mesh_anchor_id",
            "source_roomplan_object_id",
            "raycast",
        },
        field=field,
    )
    raycast = placement.get("raycast")
    if raycast is not None:
        if not isinstance(raycast, dict):
            raise CaptureIngestionContractError(
                f"{field}.raycast must be an object or null"
            )
        _require_document_keys(
            raycast,
            required={"target_type"},
            optional={
                "hit_distance_m",
                "hit_anchor_id",
                "T_world_from_hit",
            },
            field=f"{field}.raycast",
        )
        if (
            not isinstance(raycast["target_type"], str)
            or not raycast["target_type"]
        ):
            raise CaptureIngestionContractError(
                f"{field}.raycast.target_type must be a non-empty string"
            )
        hit_distance_m = raycast.get("hit_distance_m")
        if hit_distance_m is not None and (
            not isinstance(hit_distance_m, (int, float))
            or isinstance(hit_distance_m, bool)
            or not math.isfinite(hit_distance_m)
            or hit_distance_m < 0
        ):
            raise CaptureIngestionContractError(
                f"{field}.raycast.hit_distance_m must be a "
                "non-negative finite number or null"
            )
        hit_anchor_id = raycast.get("hit_anchor_id")
        if hit_anchor_id is not None and (
            not isinstance(hit_anchor_id, str) or not hit_anchor_id
        ):
            raise CaptureIngestionContractError(
                f"{field}.raycast.hit_anchor_id must be a non-empty "
                "string or null"
            )
        world_from_hit = raycast.get("T_world_from_hit")
        if world_from_hit is not None:
            if not isinstance(world_from_hit, dict):
                raise CaptureIngestionContractError(
                    f"{field}.raycast.T_world_from_hit must be a "
                    "matrix4f object or null"
                )
            _require_document_keys(
                world_from_hit,
                required={"representation", "values"},
                optional=set(),
                field=f"{field}.raycast.T_world_from_hit",
            )
            if (
                world_from_hit["representation"]
                != "column_major_4x4_f32"
            ):
                raise CaptureIngestionContractError(
                    f"{field}.raycast.T_world_from_hit.representation "
                    "must be 'column_major_4x4_f32'"
                )
            values = world_from_hit["values"]
            if (
                not isinstance(values, list)
                or len(values) != 16
                or any(
                    not isinstance(component, (int, float))
                    or isinstance(component, bool)
                    or not math.isfinite(component)
                    for component in values
                )
            ):
                raise CaptureIngestionContractError(
                    f"{field}.raycast.T_world_from_hit.values must "
                    "be an array of 16 finite numbers"
                )
    method = placement["method"]
    if method not in {
        "manual_numeric",
        "raycast",
        "mesh_hit_test",
        "roomplan_binding",
        "imported_reference",
        "other",
    }:
        raise CaptureIngestionContractError(f"{field}.method is invalid")

    for key in ("source_semantic_entity_id", "source_roomplan_object_id"):
        value = placement.get(key)
        if value is not None and (
            not isinstance(value, str) or not value
        ):
            raise CaptureIngestionContractError(
                f"{field}.{key} must be a non-empty string or null"
            )

    source_mesh_anchor_id = placement.get("source_mesh_anchor_id")
    resolutions: list[dict] = []
    if source_mesh_anchor_id is not None:
        resolutions.append(
            context.resolve(
                f"mesh_anchor:{source_mesh_anchor_id}",
                f"{field}.source_mesh_anchor_id",
                coordinate_space_id,
            )
        )

    resolutions.extend(
        _resolve_ref_list(
            placement["source_evidence_refs"],
            f"{field}.source_evidence_refs",
            context,
            coordinate_space_id,
        )
    )

    # The producer requires at least one supporting source for spatial
    # placements; the ingestor enforces the same coherence.
    if method in {"raycast", "mesh_hit_test"} and not (
        source_mesh_anchor_id
        or placement.get("source_semantic_entity_id")
        or placement["source_evidence_refs"]
    ):
        raise CaptureIngestionContractError(
            f"{field}.method {method!r} requires supporting source evidence"
        )
    if method == "roomplan_binding" and not (
        placement.get("source_roomplan_object_id")
        or placement.get("source_semantic_entity_id")
    ):
        raise CaptureIngestionContractError(
            f"{field}.method 'roomplan_binding' requires a RoomPlan or "
            "semantic source identity"
        )

    raycast = placement.get("raycast")
    if raycast is not None:
        if not isinstance(raycast, dict):
            raise CaptureIngestionContractError(f"{field}.raycast must be an object")
        _require_document_keys(
            raycast,
            required={"target_type"},
            optional={
                "hit_distance_m",
                "hit_anchor_id",
                "T_world_from_hit",
            },
            field=f"{field}.raycast",
        )
        target_type = raycast["target_type"]
        if not isinstance(target_type, str) or not target_type:
            raise CaptureIngestionContractError(
                f"{field}.raycast.target_type must be a non-empty string"
            )
        hit_distance = raycast.get("hit_distance_m")
        if hit_distance is not None and (
            not isinstance(hit_distance, (int, float))
            or isinstance(hit_distance, bool)
            or not math.isfinite(hit_distance)
            or hit_distance < 0
        ):
            raise CaptureIngestionContractError(
                f"{field}.raycast.hit_distance_m must be a number >= 0"
            )
        hit_anchor_id = raycast.get("hit_anchor_id")
        if hit_anchor_id is not None:
            # The producer serializes UUIDs with Foundation's Codable,
            # which preserves case — accept either and normalize to the
            # canonical lowercase form the mesh index uses.
            if not isinstance(hit_anchor_id, str) or not hit_anchor_id:
                raise CaptureIngestionContractError(
                    f"{field}.raycast.hit_anchor_id must be a "
                    "non-empty string or null"
                )
            try:
                UUID(hit_anchor_id)
            except (ValueError, AttributeError) as exc:
                raise CaptureIngestionContractError(
                    f"{field}.raycast.hit_anchor_id is not a UUID: "
                    f"{hit_anchor_id!r}"
                ) from exc
            resolutions.append(
                context.resolve(
                    f"mesh_anchor:{str(UUID(hit_anchor_id))}",
                    f"{field}.raycast.hit_anchor_id",
                    coordinate_space_id,
                )
            )
        hit_transform = raycast.get("T_world_from_hit")
        if hit_transform is not None:
            _validate_transform(
                hit_transform,
                f"{field}.raycast.T_world_from_hit",
            )
    return resolutions


def _validate_entity_extensions(
    record: dict,
    field: str,
    context: _EvidenceRefContext,
    coordinate_space_id,
) -> list[dict]:
    """Validate v1.1 annotation contract fields added for the
    physical-entity / authority-granularity cluster: optional
    ``physical_envelope``, ``uncertainty``, ``authority``,
    ``lifecycle``, ``reference_point``, ``listening_role`` and
    ``equipment_ref.authority_version``. Each carries its own
    evidence claims that must resolve against committed authority.
    """
    resolutions: list[dict] = []
    entity_type = record.get("type")

    listening_role = record.get("listening_role")
    if listening_role is not None:
        if listening_role not in {
            "primary",
            "secondary",
            "measurement_reference",
        }:
            raise CaptureIngestionContractError(f"{field}.listening_role is invalid")
        if entity_type != "listening_position":
            raise CaptureIngestionContractError(
                f"{field}.listening_role requires "
                "type 'listening_position'"
            )

    equipment_ref = record.get("equipment_ref")
    if equipment_ref is not None:
        if not isinstance(equipment_ref, dict):
            raise CaptureIngestionContractError(
                f"{field}.equipment_ref must be an object"
            )
        authority_version = equipment_ref.get("authority_version")
        if authority_version is not None and (
            not isinstance(authority_version, str)
            or not authority_version
        ):
            raise CaptureIngestionContractError(
                f"{field}.equipment_ref.authority_version must be a "
                "non-empty string or null"
            )

    envelope = record.get("physical_envelope")
    if envelope is not None:
        if not isinstance(envelope, dict):
            raise CaptureIngestionContractError(
                f"{field}.physical_envelope must be an object"
            )
        _require_document_keys(
            envelope,
            required={"provenance", "source_evidence_refs"},
            optional={"width_m", "height_m", "depth_m"},
            field=f"{field}.physical_envelope",
        )
        dimensions = [
            envelope.get(key)
            for key in ("width_m", "height_m", "depth_m")
        ]
        if all(value is None for value in dimensions):
            raise CaptureIngestionContractError(
                f"{field}.physical_envelope requires at least one "
                "dimension"
            )
        for index, value in enumerate(dimensions):
            if value is not None and (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(value)
                or value <= 0
            ):
                raise CaptureIngestionContractError(
                    f"{field}.physical_envelope dimension must be a "
                    "number > 0"
                )
        if envelope["provenance"] not in {
            "user_measured",
            "equipment_catalog_derived",
            "roomplan_derived",
            "imported_reference",
            "other",
        }:
            raise CaptureIngestionContractError(
                f"{field}.physical_envelope.provenance is invalid"
            )
        resolutions.extend(
            _resolve_ref_list(
                envelope["source_evidence_refs"],
                f"{field}.physical_envelope.source_evidence_refs",
                context,
                coordinate_space_id,
            )
        )

    uncertainty = record.get("uncertainty")
    if uncertainty is not None:
        if not isinstance(uncertainty, dict):
            raise CaptureIngestionContractError(
                f"{field}.uncertainty must be an object"
            )
        _require_document_keys(
            uncertainty,
            required={"basis"},
            optional={
                "isotropic_m",
                "per_axis_m",
                "angular_rad",
                "source_evidence_refs",
            },
            field=f"{field}.uncertainty",
        )
        if uncertainty["basis"] not in {
            "user_stated",
            "instrument_stated",
            "app_estimated",
            "other",
        }:
            raise CaptureIngestionContractError(
                f"{field}.uncertainty.basis is invalid"
            )
        isotropic = uncertainty.get("isotropic_m")
        per_axis = uncertainty.get("per_axis_m")
        angular = uncertainty.get("angular_rad")
        if isotropic is None and per_axis is None and angular is None:
            raise CaptureIngestionContractError(
                f"{field}.uncertainty requires at least one numeric "
                "component"
            )
        for component_field, value in (
            ("isotropic_m", isotropic),
            ("angular_rad", angular),
        ):
            if value is not None and (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(value)
                or value < 0
            ):
                raise CaptureIngestionContractError(
                    f"{field}.uncertainty.{component_field} must be a "
                    "number >= 0"
                )
        if per_axis is not None:
            if not isinstance(per_axis, list) or len(per_axis) != 3:
                raise CaptureIngestionContractError(
                    f"{field}.uncertainty.per_axis_m must contain "
                    "3 numbers"
                )
            for component in per_axis:
                if (
                    not isinstance(component, (int, float))
                    or isinstance(component, bool)
                    or not math.isfinite(component)
                    or component < 0
                ):
                    raise CaptureIngestionContractError(
                        f"{field}.uncertainty.per_axis_m components "
                        "must be numbers >= 0"
                    )
        resolutions.extend(
            _resolve_ref_list(
                uncertainty.get("source_evidence_refs") or [],
                f"{field}.uncertainty.source_evidence_refs",
                context,
                coordinate_space_id,
            )
        )

    authority = record.get("authority")
    if authority is not None:
        if not isinstance(authority, dict):
            raise CaptureIngestionContractError(
                f"{field}.authority must be an object"
            )
        _require_document_keys(
            authority,
            required={"placement"},
            optional={
                "orientation",
                "equipment",
                "reference_point",
                "semantic_role",
            },
            field=f"{field}.authority",
        )
        for component_name in (
            "placement",
            "orientation",
            "equipment",
            "reference_point",
            "semantic_role",
        ):
            component = authority.get(component_name)
            if component is None:
                continue
            if not isinstance(component, dict):
                raise CaptureIngestionContractError(
                    f"{field}.authority.{component_name} must be an "
                    "object"
                )
            _require_document_keys(
                component,
                required={"state", "evidence_refs"},
                optional={"source_ref"},
                field=f"{field}.authority.{component_name}",
            )
            if component["state"] not in {
                "unverified",
                "user_attested",
                "evidence_linked",
            }:
                raise CaptureIngestionContractError(
                    f"{field}.authority.{component_name}.state is "
                    "invalid"
                )
            if component["state"] == "evidence_linked" and not (
                component["evidence_refs"] or component.get("source_ref")
            ):
                raise CaptureIngestionContractError(
                    f"{field}.authority.{component_name} claims "
                    "evidence_linked without a reference"
                )
            resolutions.extend(
                _resolve_ref_list(
                    component["evidence_refs"],
                    f"{field}.authority.{component_name}.evidence_refs",
                    context,
                    coordinate_space_id,
                )
            )

    lifecycle = record.get("lifecycle")
    if lifecycle is not None:
        if not isinstance(lifecycle, dict):
            raise CaptureIngestionContractError(
                f"{field}.lifecycle must be an object"
            )
        _require_document_keys(
            lifecycle,
            required={"created_at_utc"},
            optional={
                "updated_at_utc",
                "observed_at_utc",
                "source_created_at_utc",
                "supersedes_entity_id",
            },
            field=f"{field}.lifecycle",
        )
        for key in (
            "created_at_utc",
            "updated_at_utc",
            "observed_at_utc",
            "source_created_at_utc",
        ):
            value = lifecycle.get(key)
            if value is not None:
                _validate_utc_timestamp(
                    value, f"{field}.lifecycle.{key}"
                )
        supersedes = lifecycle.get("supersedes_entity_id")
        if supersedes is not None:
            validate_uuid4(
                supersedes,
                f"{field}.lifecycle.supersedes_entity_id",
            )

    reference_point = record.get("reference_point")
    if reference_point is not None:
        if not isinstance(reference_point, dict):
            raise CaptureIngestionContractError(
                f"{field}.reference_point must be an object"
            )
        _require_document_keys(
            reference_point,
            required={"construction", "source_evidence_refs"},
            optional={"offset_m"},
            field=f"{field}.reference_point",
        )
        construction = reference_point["construction"]
        if construction not in {
            "direct_placement",
            "surface_hit_confirmed",
            "offset_from_surface",
            "imported_reference",
        }:
            raise CaptureIngestionContractError(
                f"{field}.reference_point.construction is invalid"
            )
        offset = reference_point.get("offset_m")
        if construction == "offset_from_surface":
            if (
                not isinstance(offset, list)
                or len(offset) != 3
                or not all(
                    isinstance(component, (int, float))
                    and not isinstance(component, bool)
                    and math.isfinite(component)
                    for component in offset
                )
            ):
                raise CaptureIngestionContractError(
                    f"{field}.reference_point.offset_m must contain "
                    "3 numbers"
                )
        elif offset is not None:
            raise CaptureIngestionContractError(
                f"{field}.reference_point.offset_m requires "
                "construction 'offset_from_surface'"
            )
        # Construction must agree with the placement method that
        # produced the position.
        method = record["placement"]["method"]
        surface_derived = method in {"raycast", "mesh_hit_test"}
        if construction in {
            "surface_hit_confirmed",
            "offset_from_surface",
        } and not surface_derived:
            raise CaptureIngestionContractError(
                f"{field}.reference_point.construction "
                f"{construction!r} requires a surface-derived "
                "placement method"
            )
        if construction == "direct_placement" and surface_derived:
            raise CaptureIngestionContractError(
                f"{field}.reference_point.construction "
                "'direct_placement' cannot claim a surface-derived "
                "placement"
            )
        resolutions.extend(
            _resolve_ref_list(
                reference_point["source_evidence_refs"],
                f"{field}.reference_point.source_evidence_refs",
                context,
                coordinate_space_id,
            )
        )
    return resolutions


def _validate_acoustic_center(
    acoustic_center,
    field: str,
    context: _EvidenceRefContext,
    coordinate_space_id,
) -> list[dict]:
    if acoustic_center is None:
        return []
    if not isinstance(acoustic_center, dict):
        raise CaptureIngestionContractError(f"{field} must be an object")
    _require_document_keys(
        acoustic_center,
        required={"offset_local_m", "authority_ref"},
        optional=set(),
        field=field,
    )
    offset = acoustic_center["offset_local_m"]
    if not isinstance(offset, list) or len(offset) != 3:
        raise CaptureIngestionContractError(f"{field}.offset_local_m must contain 3 numbers")
    for index, component in enumerate(offset):
        if (
            not isinstance(component, (int, float))
            or isinstance(component, bool)
            or not math.isfinite(component)
        ):
            raise CaptureIngestionContractError(
                f"{field}.offset_local_m[{index}] must be finite"
            )
    authority_ref = acoustic_center["authority_ref"]
    if not isinstance(authority_ref, str) or not authority_ref:
        raise CaptureIngestionContractError(
            f"{field}.authority_ref must be a non-empty string"
        )
    prefix, separator, _ = authority_ref.partition(":")
    if separator and prefix in {"path", "mesh_anchor", "frame", "entity", "measurement"}:
        return [
            context.resolve(
                authority_ref, f"{field}.authority_ref", coordinate_space_id
            )
        ]
    # Otherwise the authority token is authored by the annotation itself.
    return [
        {
            "ref": authority_ref,
            "kind": "annotation_authored",
            "target": None,
        }
    ]


def _dedupe_resolutions(resolutions: list[dict]) -> list[dict]:
    by_ref: dict[str, dict] = {}
    for resolution in resolutions:
        by_ref.setdefault(resolution["ref"], resolution)
    return [by_ref[ref] for ref in sorted(by_ref)]


def _build_authority_records(
    reader: FrozenBundle,
    manifest: dict,
    bundle_digest: str,
    source_by_path: dict[str, dict],
    anchor_index: dict[str, dict],
    mesh_handoff_by_anchor: dict[str, str],
    frame_registry: dict[str, dict],
) -> list[dict]:
    coordinate_ids = set(manifest["coordinate_space_ids"])
    result: list[dict] = []

    definitions = [
        (
            ENTITIES_PATH,
            "htdt.capture.entities",
            "entities",
            "entity_id",
            "annotation",
        ),
        (
            MEASUREMENTS_PATH,
            "htdt.capture.measurements",
            "measurements",
            "measurement_id",
            "measurement",
        ),
    ]

    context = _EvidenceRefContext(
        bundle_digest,
        source_by_path,
        anchor_index,
        mesh_handoff_by_anchor,
        frame_registry,
    )

    # First pass: parse every authority container and register record IDs so
    # cross-record entity:/measurement: references resolve against the same
    # validated bundle.
    parsed: dict[str, tuple[str, str, str, list]] = {}
    for path, schema, array_key, id_key, record_kind in definitions:
        if path not in source_by_path:
            continue
        document = parse_json_bytes(reader.read(path))
        _require_schema(document, schema)
        records = document.get(array_key)
        if not isinstance(records, list):
            raise CaptureIngestionContractError(f"{path}:{array_key} must be an array")
        seen: set[str] = set()
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                raise CaptureIngestionContractError(
                    f"{path}:{array_key}[{index}] must be an object"
                )
            record_id = record.get(id_key)
            validate_uuid4(
                record_id,
                f"{path}:{array_key}[{index}].{id_key}",
            )
            if record_id in seen:
                raise CaptureIngestionContractError(
                    f"duplicate {record_kind} record ID: {record_id}"
                )
            seen.add(record_id)
        parsed[path] = (array_key, id_key, record_kind, records)
        if record_kind == "annotation":
            context.entity_ids = seen
            context.entity_source_sha256 = source_by_path[path][
                "payload_sha256"
            ]
        else:
            context.measurement_ids = seen
            context.measurement_source_sha256 = source_by_path[path][
                "payload_sha256"
            ]

    for path, (array_key, id_key, record_kind, records) in parsed.items():
        source = source_by_path[path]
        for index, record in enumerate(records):
            record_field = f"{path}:{array_key}[{index}]"
            record_id = record[id_key]

            provenance = record.get("provenance_class")
            if provenance not in PROVENANCE:
                raise CaptureIngestionContractError(
                    f"invalid record provenance: {provenance!r}"
                )

            coordinate_space_id = record.get("coordinate_space_id")
            if coordinate_space_id is not None:
                validate_uuid4(
                    coordinate_space_id,
                    f"{record_field}.coordinate_space_id",
                )
                if coordinate_space_id not in coordinate_ids:
                    raise CaptureIngestionContractError(
                        f"{record_kind} references unknown coordinate space: "
                        f"{coordinate_space_id}"
                    )
            elif record_kind == "annotation":
                raise CaptureIngestionContractError(
                    f"{record_field}.coordinate_space_id is required"
                )

            evidence_refs = record.get("evidence_refs")
            if evidence_refs is None:
                raise CaptureIngestionContractError(
                    f"{record_field}.evidence_refs is required"
                )
            resolutions = _resolve_ref_list(
                evidence_refs,
                f"{record_field}.evidence_refs",
                context,
                coordinate_space_id,
            )

            endpoint_refs: list[str] = []
            endpoint_resolutions: list[dict] = []
            if record_kind == "measurement":
                endpoint_refs = record.get("endpoint_refs")
                if endpoint_refs is None:
                    raise CaptureIngestionContractError(
                        f"{record_field}.endpoint_refs is required"
                    )
                endpoint_resolutions = _resolve_ref_list(
                    endpoint_refs,
                    f"{record_field}.endpoint_refs",
                    context,
                    coordinate_space_id,
                )
                if endpoint_refs and coordinate_space_id is None:
                    raise CaptureIngestionContractError(
                        f"{record_field} uses spatial endpoint_refs "
                        "without a coordinate_space_id"
                    )
            else:
                placement = record.get("placement")
                if placement is None:
                    raise CaptureIngestionContractError(
                        f"{record_field}.placement is required"
                    )
                resolutions.extend(
                    _validate_entity_placement(
                        placement,
                        f"{record_field}.placement",
                        context,
                        coordinate_space_id,
                    )
                )
                resolutions.extend(
                    _validate_acoustic_center(
                        record.get("acoustic_center"),
                        f"{record_field}.acoustic_center",
                        context,
                        coordinate_space_id,
                    )
                )
                resolutions.extend(
                    _validate_entity_extensions(
                        record,
                        record_field,
                        context,
                        coordinate_space_id,
                    )
                )

            result.append(
                {
                    "authority_record_handoff_id":
                        _authority_record_handoff_id(
                            bundle_digest,
                            source["payload_sha256"],
                            record_kind,
                            record_id,
                        ),
                    "record_kind": record_kind,
                    "record_id": record_id,
                    "record_locator": (
                        f"{path}#{record_kind}:{record_id}"
                    ),
                    "provenance_class": provenance,
                    "coordinate_space_id": coordinate_space_id,
                    "source_evidence_id": source["source_evidence_id"],
                    "source_payload_sha256": source["payload_sha256"],
                    "evidence_refs": list(evidence_refs),
                    "endpoint_refs": list(endpoint_refs),
                    "resolved_evidence": _dedupe_resolutions(resolutions),
                    "resolved_endpoints": _dedupe_resolutions(
                        endpoint_resolutions
                    ),
                }
            )

    result.sort(
        key=lambda item: (
            item["record_kind"],
            item["record_id"],
        )
    )
    return result


def _derive_sections(
    reader,
    manifest: dict,
    bundle_digest: str,
) -> dict:
    """Derive every ingestion-plan section from exact frozen bytes.

    The finalized-capture quality gate runs before any source evidence or
    downstream handoff is produced (#146), and the cross-payload identity
    pass (#153) registers frames before authority records resolve refs.
    """
    quality_document = _enforce_quality_gate(reader, manifest)

    # Cross-payload identity pass: session and frame identities must be
    # members of the manifest registry before promotion (#153).
    frame_registry = _validate_identity_membership(reader, manifest)

    source_records, source_by_path = _build_source_registry(
        manifest,
        bundle_digest,
    )
    roomplan_records = _build_roomplan_records(
        manifest,
        source_by_path,
    )
    roomplan_metadata = _load_roomplan_capture_metadata(
        reader,
        manifest,
        source_by_path,
        roomplan_records,
    )
    metadata_paths = (
        {
            roomplan_metadata["raw_payload_path"],
            roomplan_metadata.get("processed_payload_path"),
        }
        if roomplan_metadata is not None
        else set()
    )
    for record in roomplan_records:
        record["roomplan_capture_metadata"] = (
            roomplan_metadata
            if record["path"] in metadata_paths
            else None
        )
    anchor_index = _load_mesh_anchor_index(
        reader,
        manifest,
        source_by_path,
    )
    raw_mesh_handoffs = _build_raw_visual_mesh_handoffs(
        manifest,
        bundle_digest,
        source_by_path,
        anchor_index,
    )
    authority_records = _build_authority_records(
        reader,
        manifest,
        bundle_digest,
        source_by_path,
        anchor_index,
        {
            handoff["anchor_id"]: handoff["raw_visual_mesh_handoff_id"]
            for handoff in raw_mesh_handoffs
        },
        frame_registry,
    )

    return {
        "source_records": source_records,
        "roomplan_records": roomplan_records,
        "roomplan_capture_metadata": roomplan_metadata,
        "raw_visual_mesh_handoffs": raw_mesh_handoffs,
        "authority_records": authority_records,
        "quality_document": quality_document,
    }


def build_ingestion_plan(reader: FrozenBundle) -> dict:
    manifest = parse_json_bytes(reader.read("manifest.json"))
    bundle_digest = reader.report["bundle_digest"]

    sections = _derive_sections(reader, manifest, bundle_digest)
    source_records = sections["source_records"]
    roomplan_records = sections["roomplan_records"]
    roomplan_metadata = sections["roomplan_capture_metadata"]
    raw_mesh_handoffs = sections["raw_visual_mesh_handoffs"]
    authority_records = sections["authority_records"]

    configuration_digest = hashlib.sha256(
        canonical_json_bytes(CONFIGURATION)
    ).hexdigest()

    lineage_projection = {
        "bundle_digest": bundle_digest,
        "source_evidence_ids": sorted(
            record["source_evidence_id"]
            for record in source_records
        ),
        "raw_visual_mesh_ids": sorted(
            record["raw_visual_mesh_handoff_id"]
            for record in raw_mesh_handoffs
        ),
        "authority_record_ids": sorted(
            record["authority_record_handoff_id"]
            for record in authority_records
        ),
    }
    lineage_digest = hashlib.sha256(
        canonical_json_bytes(lineage_projection)
    ).hexdigest()

    plan = {
        "schema": PLAN_SCHEMA,
        "schema_version": PLAN_SCHEMA_VERSION,
        "ingestor": {
            "name": INGESTOR_NAME,
            "version": INGESTOR_VERSION,
            "configuration_digest": configuration_digest,
        },
        "bundle": {
            "bundle_digest": bundle_digest,
            "capture_schema": manifest["schema"],
            "capture_schema_version": manifest["schema_version"],
            "capture_series_id": manifest["capture_series_id"],
            "capture_revision_id": manifest["capture_revision_id"],
            "parent_revision_id": manifest["parent_revision_id"],
            "capture_session_ids": manifest["capture_session_ids"],
            "coordinate_space_ids": manifest["coordinate_space_ids"],
        },
        "source_evidence": source_records,
        "roomplan_records": roomplan_records,
        "roomplan_capture_metadata": roomplan_metadata,
        "raw_visual_mesh_handoffs": raw_mesh_handoffs,
        "authority_records": authority_records,
        "lineage_digest": lineage_digest,
    }
    canonical_plan_bytes(plan)
    return plan




class _MappingReader:
    """FrozenBundle-compatible reader over an in-memory payload mapping."""

    def __init__(self, payloads: dict):
        self._payloads = payloads

    def read(self, logical_path: str) -> bytes:
        try:
            return self._payloads[logical_path]
        except KeyError as exc:
            raise CaptureIngestionContractError(
                f"payload unexpectedly missing: {logical_path}"
            ) from exc


def rederive_plan_sections(
    manifest: dict,
    payloads: dict,
) -> dict:
    """Schema-validate then semantically rederive every plan section from
    exact payload bytes.

    ``manifest`` is the plan-projected manifest: capture identity arrays
    plus ``files`` entries in manifest-entry shape. This is the shared
    bounded rederivation path used by the production ingestion boundary:
    the common schema/binary/cross-document layer runs first, then the
    quality gate, identity membership and all handoff derivations. Any
    contract failure raises ``CaptureIngestionContractError`` (or
    ``CaptureBundleError`` from the schema layer) before a caller can
    commit authority.
    """
    from htdt.capture_bundle import (
        CaptureBundleError,
        validate_payload_set,
    )

    try:
        validate_payload_set(manifest, payloads)
    except CaptureBundleError as exc:
        raise CaptureIngestionContractError(str(exc)) from exc

    reader = _MappingReader(payloads)
    bundle_digest = manifest["bundle_digest"]
    return _derive_sections(reader, manifest, bundle_digest)
