"""Validated JSON taxonomies and optional ground-truth CVE cases."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any


_CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")


class FixtureError(ValueError):
    """A selected taxonomy or benchmark cannot be used safely."""


def normalize_cve_id(value: str) -> str:
    if not isinstance(value, str):
        raise FixtureError("CVE ID must be a string")
    cve_id = value.strip().upper()
    if not _CVE_ID_PATTERN.fullmatch(cve_id):
        raise FixtureError(f"Invalid CVE ID: {value!r}")
    return cve_id


def _canonical_fingerprint(value: object) -> str:
    serialized = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _load_json(path: Path, kind: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise FixtureError(f"Cannot read {kind} JSON from {path}: {error}") from error


@dataclass(frozen=True)
class TaxonomyLabel:
    id: str
    name: str
    description: str
    parent: str | None = None


@dataclass(frozen=True)
class Taxonomy:
    name: str
    labels: tuple[TaxonomyLabel, ...]
    fingerprint: str
    source_path: Path

    @property
    def by_id(self) -> dict[str, TaxonomyLabel]:
        return {label.id: label for label in self.labels}

    @property
    def all_labels(self) -> list[str]:
        return [label.id for label in self.labels] + ["NONE"]

    @property
    def descriptions(self) -> dict[str, str]:
        return {
            label.id: f"{label.name}: {label.description}"
            for label in self.labels
        }

    @property
    def root_descriptions(self) -> dict[str, str]:
        return {
            label.id: f"{label.name}: {label.description}"
            for label in self.labels
            if label.parent is None
        }

    def ancestors_of(self, label_id: str) -> tuple[str, ...]:
        by_id = self.by_id
        ancestors: list[str] = []
        current = by_id[label_id].parent
        while current is not None:
            ancestors.append(current)
            current = by_id[current].parent
        return tuple(reversed(ancestors))


@dataclass(frozen=True)
class BenchmarkCase:
    cve_id: str
    labels: tuple[str, ...]
    rationale: str
    sources: tuple[str, ...]


@dataclass(frozen=True)
class Benchmark:
    cases: tuple[BenchmarkCase, ...]
    source_path: Path
    taxonomy_sha256: str


def load_taxonomy(path: str | Path) -> Taxonomy:
    source_path = Path(path)
    raw = _load_json(source_path, "taxonomy")
    if not isinstance(raw, dict):
        raise FixtureError("Taxonomy JSON must be an object")
    if raw.get("hierarchy_policy") != "most_specific":
        raise FixtureError("Taxonomy hierarchy_policy must be 'most_specific'")
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        raise FixtureError("Taxonomy name must be a non-empty string")
    entries = raw.get("labels")
    if not isinstance(entries, list) or not entries:
        raise FixtureError("Taxonomy labels must be a non-empty array")

    labels: list[TaxonomyLabel] = []
    ids: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise FixtureError(f"Taxonomy label {index} must be an object")
        values = (entry.get("id"), entry.get("name"), entry.get("description"))
        if any(not isinstance(value, str) or not value.strip() for value in values):
            raise FixtureError(f"Taxonomy label {index} requires id, name, and description")
        label_id, display_name, description = (value.strip() for value in values)
        if label_id == "NONE":
            raise FixtureError("NONE is reserved for classifications without a matching label")
        if label_id in ids:
            raise FixtureError(f"Duplicate taxonomy ID: {label_id}")
        parent = entry.get("parent")
        if parent is not None and (not isinstance(parent, str) or not parent.strip()):
            raise FixtureError(f"Invalid parent for taxonomy label {label_id}")
        parent = parent.strip() if isinstance(parent, str) else None
        ids.add(label_id)
        labels.append(TaxonomyLabel(label_id, display_name, description, parent))

    by_id = {label.id: label for label in labels}
    for label in labels:
        if label.parent is not None and label.parent not in by_id:
            raise FixtureError(f"Unknown parent {label.parent!r} for {label.id!r}")
        seen: set[str] = set()
        current = label.id
        while current is not None:
            if current in seen:
                raise FixtureError(f"Cyclic taxonomy hierarchy involving {current!r}")
            seen.add(current)
            current = by_id[current].parent

    return Taxonomy(
        name=name.strip(),
        labels=tuple(labels),
        fingerprint=_canonical_fingerprint(raw),
        source_path=source_path.resolve(),
    )


def load_benchmark(path: str | Path, taxonomy: Taxonomy) -> Benchmark:
    source_path = Path(path)
    raw = _load_json(source_path, "expected classification")
    if not isinstance(raw, dict) or type(raw.get("schema_version")) is not int:
        raise FixtureError("Expected classifications require schema_version 1")
    if raw["schema_version"] != 1:
        raise FixtureError("Expected classifications require schema_version 1")
    if raw.get("taxonomy_sha256") != taxonomy.fingerprint:
        raise FixtureError("Expected classifications do not match the selected taxonomy")
    entries = raw.get("cases")
    if not isinstance(entries, list) or not entries:
        raise FixtureError("Expected classifications must contain cases")

    cases: list[BenchmarkCase] = []
    seen_cves: set[str] = set()
    allowed_labels = set(taxonomy.all_labels)
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise FixtureError(f"Expected case {index} must be an object")
        cve_id = normalize_cve_id(entry.get("cve_id"))
        if cve_id in seen_cves:
            raise FixtureError(f"Duplicate expected CVE ID: {cve_id}")
        labels = entry.get("labels")
        if (
            not isinstance(labels, list)
            or not labels
            or any(not isinstance(label, str) or not label for label in labels)
        ):
            raise FixtureError(f"Expected case {cve_id} requires non-empty labels")
        if len(labels) != len(set(labels)):
            raise FixtureError(f"Expected case {cve_id} contains duplicate labels")
        if not set(labels) <= allowed_labels:
            raise FixtureError(f"Expected case {cve_id} contains unsupported labels")
        if "NONE" in labels and len(labels) != 1:
            raise FixtureError(f"Expected case {cve_id} combines NONE with labels")
        for label_id in labels:
            if label_id != "NONE" and any(
                ancestor in labels for ancestor in taxonomy.ancestors_of(label_id)
            ):
                raise FixtureError(f"Expected case {cve_id} combines ancestor and descendant")
        rationale = entry.get("rationale", "")
        sources = entry.get("sources", [])
        if not isinstance(rationale, str) or not isinstance(sources, list) or any(
            not isinstance(source, str) or not source.strip() for source in sources
        ):
            raise FixtureError(f"Expected case {cve_id} has invalid rationale or sources")
        seen_cves.add(cve_id)
        cases.append(BenchmarkCase(cve_id, tuple(labels), rationale, tuple(sources)))

    return Benchmark(tuple(cases), source_path.resolve(), taxonomy.fingerprint)
