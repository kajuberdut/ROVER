"""src/rover/db/types.py — Enums for SBOM, VEX, and Triage database fields."""

from enum import StrEnum


class SbomFormat(StrEnum):
    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"


class SbomComponentType(StrEnum):
    LIBRARY = "library"
    CONTAINER = "container"
    OPERATING_SYSTEM = "operating-system"
    APPLICATION = "application"
    FILE = "file"


class VulnerabilitySeverity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class FindingStatus(StrEnum):
    OPEN = "open"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"


class VexJustification(StrEnum):
    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = (
        "vulnerable_code_cannot_be_controlled_by_adversary"
    )
    VULNERABLE_CODE_CANNOT_BE_TRIGGERED = "vulnerable_code_cannot_be_triggered"
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"


class VexSpecType(StrEnum):
    OPENVEX = "openvex"
    CYCLONEDX_VEX = "cyclonedx_vex"


class TriageState(StrEnum):
    PENDING_APPROVAL = "pending_approval"
    ACTIVE = "active"
    REJECTED = "rejected"
    REVOKED = "revoked"
    EXPIRED = "expired"
