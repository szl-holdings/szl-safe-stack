"""Offline restricted-English to inert-IR evidence adapter.

Pipeline: rights-admitted manifest -> typed input contract -> restricted
deterministic parser -> inert intermediate representation -> independent
validator -> evidence report in the gateway's existing vocabulary.

This package is not imported by the gateway server or CLI. It reads no file,
clock, environment variable or network, starts no process, and performs no
declared effect. Its output is a proposal for the existing SZL authority
boundary, never an authorization. Original SZL design from the public mission
description; no third-party compiler source was consulted or copied.
"""

from __future__ import annotations

from .contract import (
    CONTRACT_SCHEMA,
    IR_SCHEMA,
    OPERATION_EFFECTS,
    PERMITTED_EFFECTS,
    ContractError,
    contract_sha256,
    default_contract,
    validate_contract,
)
from .manifest import MANIFEST_SCHEMA, ManifestError, build_manifest, parse_manifest
from .parser import parse, tokenize
from .report import REPORT_SCHEMA, TRANSLATED, assess, gateway_artifacts, gateway_request
from .validator import ValidationResult, validate_ir

__all__ = [
    "CONTRACT_SCHEMA",
    "IR_SCHEMA",
    "MANIFEST_SCHEMA",
    "OPERATION_EFFECTS",
    "PERMITTED_EFFECTS",
    "REPORT_SCHEMA",
    "TRANSLATED",
    "ContractError",
    "ManifestError",
    "ValidationResult",
    "assess",
    "build_manifest",
    "contract_sha256",
    "default_contract",
    "gateway_artifacts",
    "gateway_request",
    "parse",
    "parse_manifest",
    "tokenize",
    "validate_contract",
    "validate_ir",
]
