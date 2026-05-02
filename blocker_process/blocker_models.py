from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class MissingEvidenceTag(str, Enum):
    NEED_ASSIGNMENT_SITE = "need_assignment_site"
    NEED_ENUM_DEFINITION = "need_enum_definition"
    NEED_MACRO_DEFINITION = "need_macro_definition"
    NEED_HEADER_DEFINITION = "need_header_definition"
    NEED_CALLSITE_CONFIRMATION = "need_callsite_confirmation"
    NEED_MORE_FUZZ_TARGET_CONTEXT = "need_more_fuzz_target_context"

    @classmethod
    def from_raw(cls, value: str) -> "MissingEvidenceTag | None":
        try:
            return cls(value)
        except ValueError:
            return None


EVIDENCE_FIELDS: set[str] = {
    "branch_snippet",
    "blocked_snippet",
    "function_source",
    "fuzz_target_source",
    "branch_hit_count",
    "sides_hitcount_diff",
    "blocked_unique_funcs",
    "supplemental",
}


class ClassifierLabel(str, Enum):
    INPUT_DEPENDENT = "INPUT_DEPENDENT"
    INPUT_INDEPENDENT = "INPUT_INDEPENDENT"
    AMBIGUOUS = "AMBIGUOUS"


class ConfidenceLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(slots=True)
class BlockerSpec:
    project_name: str
    fuzzer_name: str
    function_name: str
    source_file: str
    branch_line_number: int
    blocked_side_line_number: int
    blocker_id: str = ""

    def __post_init__(self) -> None:
        if not self.blocker_id:
            self.blocker_id = self.make_blocker_id(
                project_name=self.project_name,
                fuzzer_name=self.fuzzer_name,
                source_file=self.source_file,
                branch_line_number=self.branch_line_number,
                blocked_side_line_number=self.blocked_side_line_number,
            )

    @staticmethod
    def make_blocker_id(
        project_name: str,
        fuzzer_name: str,
        source_file: str,
        branch_line_number: int,
        blocked_side_line_number: int,
    ) -> str:
        return (
            f"{project_name}:{fuzzer_name}:{source_file}:"
            f"{branch_line_number}:{blocked_side_line_number}"
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class BlockerEvidence:
    branch_snippet: str = ""
    blocked_snippet: str = ""
    function_source: str = ""
    fuzz_target_source: str = ""
    branch_hit_count: str = ""
    sides_hitcount_diff: str = ""
    blocked_unique_funcs: list[str] = field(default_factory=list)
    supplemental: dict[str, str | list[str]] = field(default_factory=dict)

    def has_field(self, field_name: str) -> bool:
        if field_name not in EVIDENCE_FIELDS:
            return False

        value = getattr(self, field_name)
        if isinstance(value, str):
            return bool(value.strip())
        if isinstance(value, list):
            return bool(value)
        if isinstance(value, dict):
            return bool(value)
        return value is not None

    def available_fields(self) -> list[str]:
        return sorted(field_name for field_name in EVIDENCE_FIELDS if self.has_field(field_name))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ClassifierResult:
    label: ClassifierLabel
    confidence: ConfidenceLevel
    reason: str
    missing_evidence: list[MissingEvidenceTag] = field(default_factory=list)
    evidence_used: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.evidence_used = self.sanitize_evidence_used(self.evidence_used)

    @staticmethod
    def sanitize_missing_evidence(values: list[str]) -> list[MissingEvidenceTag]:
        normalized: list[MissingEvidenceTag] = []
        seen: set[MissingEvidenceTag] = set()
        for value in values:
            tag = MissingEvidenceTag.from_raw(value)
            if tag is None or tag in seen:
                continue
            seen.add(tag)
            normalized.append(tag)
        return normalized

    @staticmethod
    def sanitize_evidence_used(values: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for value in values:
            if value not in EVIDENCE_FIELDS or value in seen:
                continue
            seen.add(value)
            normalized.append(value)
        return normalized

    @classmethod
    def from_raw(
        cls,
        *,
        label: str,
        confidence: str,
        reason: str,
        missing_evidence: list[str] | None = None,
        evidence_used: list[str] | None = None,
    ) -> "ClassifierResult":
        return cls(
            label=ClassifierLabel(label),
            confidence=ConfidenceLevel(confidence),
            reason=reason,
            missing_evidence=cls.sanitize_missing_evidence(missing_evidence or []),
            evidence_used=cls.sanitize_evidence_used(evidence_used or []),
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["label"] = self.label.value
        data["confidence"] = self.confidence.value
        data["missing_evidence"] = [tag.value for tag in self.missing_evidence]
        return data
