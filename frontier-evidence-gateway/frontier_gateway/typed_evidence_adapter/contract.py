"""Typed input contract for the restricted English adapter.

The contract is data. It names the closed literal lexicon, the units and their
dimensions, numeric ranges, size bounds, the enabled operations, and the
questions this adapter leaves explicitly unknown. A contract can disable an
operation or narrow a bound. It cannot add an operation, rename one, attach a
different effect class to one, or raise a bound above the hard ceilings below.
"""

from __future__ import annotations

import copy
import re
from types import MappingProxyType
from typing import Any

from ..lattice_adapter import EvidenceError, sha256_json

CONTRACT_SCHEMA = "szl.typed-evidence-adapter.contract.v1"
IR_SCHEMA = "szl.typed-evidence-adapter.ir.v1"

# Closed operation table. The effect class is fixed by this source, not by the
# caller's contract; a contract that declares a different class is invalid.
OPERATION_EFFECTS = MappingProxyType(
    {
        "add": "NONE",
        "print": "DECLARED_OUTPUT_TEXT",
        "repeat": "DECLARED_OUTPUT_TEXT",
    }
)
# DECLARED_OUTPUT_TEXT names an effect the IR asks for. The adapter never
# performs it; any later effect is decided by the existing authority boundary.
PERMITTED_EFFECTS = frozenset({"NONE", "DECLARED_OUTPUT_TEXT"})
CONNECTOR = "and"
REPEAT_SUFFIX = "times"
STRUCTURAL_WORDS = frozenset({CONNECTOR, REPEAT_SUFFIX})
REQUIRED_UNKNOWNS = frozenset(
    {
        "runtime_performance",
        "semantic_equivalence",
        "token_or_cost_savings",
        "unrestricted_english_coverage",
    }
)

HARD_MAX_INPUT_BYTES = 4096
HARD_MAX_TOKENS = 64
HARD_MAX_COMMANDS = 8
HARD_MAX_LEXICON = 256
HARD_MAX_UNITS = 16
HARD_MAX_UNKNOWNS = 32
# Number tokens are at most seven decimal digits (see parser grammar).
HARD_MAX_QUANTITY = 9_999_999
HARD_MAX_REPEAT = 64

_WORD = re.compile(r"[a-z]{1,16}")
_CONTRACT_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_DIMENSION = re.compile(r"[a-z][a-z_]{0,31}")
_UNKNOWN_KEY = re.compile(r"[a-z][a-z0-9_]{0,63}")
_CONTRACT_KEYS = frozenset(
    {
        "schema",
        "contract_id",
        "max_input_bytes",
        "max_tokens",
        "max_commands",
        "literal_lexicon",
        "units",
        "quantity_range",
        "repeat_range",
        "operations",
        "explicit_unknowns",
    }
)


class ContractError(EvidenceError):
    """The typed input contract violates its own schema."""


def default_contract() -> dict[str, Any]:
    """Return a fresh copy of the SZL-original default contract.

    No operation word is in the default literal lexicon, so every default
    sentence has at most one derivation. A contract that admits an operation
    word as a literal (for example `print`) makes "print salt and print pepper"
    either one literal or two commands; the parser then abstains as AMBIGUOUS.
    """
    return {
        "schema": CONTRACT_SCHEMA,
        "contract_id": "szl-restricted-english-v1",
        "max_input_bytes": 256,
        "max_tokens": 32,
        "max_commands": 4,
        "literal_lexicon": [
            "and",
            "bye",
            "hello",
            "pepper",
            "ready",
            "salt",
            "tribe",
            "world",
        ],
        "units": {
            "bytes": {"dimension": "information"},
            "count": {"dimension": "dimensionless"},
            "seconds": {"dimension": "time"},
        },
        "quantity_range": {"min": 0, "max": 1_000_000},
        "repeat_range": {"min": 1, "max": 8},
        "operations": {
            name: {"effect": effect} for name, effect in sorted(OPERATION_EFFECTS.items())
        },
        "explicit_unknowns": sorted(REQUIRED_UNKNOWNS),
    }


def _exact(value: Any, keys: frozenset[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{path}: expected an object")
    if set(value) != keys:
        raise ContractError(f"{path}: expected exactly the keys {', '.join(sorted(keys))}")
    return value


def _bounded_int(value: Any, low: int, high: int, path: str) -> int:
    # `type(...) is int` refuses bool, which is an int subclass.
    if type(value) is not int or not low <= value <= high:
        raise ContractError(f"{path}: expected an integer from {low} through {high}")
    return value


def _range(value: Any, ceiling: int, path: str, *, floor: int = 0) -> dict[str, int]:
    item = _exact(value, frozenset({"min", "max"}), path)
    low = _bounded_int(item["min"], floor, ceiling, f"{path}.min")
    high = _bounded_int(item["max"], floor, ceiling, f"{path}.max")
    if low > high:
        raise ContractError(f"{path}: min exceeds max")
    return {"min": low, "max": high}


def _word_list(value: Any, limit: int, path: str, pattern: re.Pattern[str]) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= limit:
        raise ContractError(f"{path}: expected a list of 1 through {limit} entries")
    for item in value:
        if not isinstance(item, str) or not pattern.fullmatch(item):
            raise ContractError(f"{path}: entry does not match the allowed grammar")
    if len(set(value)) != len(value):
        raise ContractError(f"{path}: entries must be unique")
    return sorted(value)


def validate_contract(value: Any) -> dict[str, Any]:
    """Return a normalized deep copy of a valid contract or raise ContractError."""
    contract = _exact(value, _CONTRACT_KEYS, "contract")
    if contract["schema"] != CONTRACT_SCHEMA:
        raise ContractError("contract.schema: unsupported schema")
    contract_id = contract["contract_id"]
    if not isinstance(contract_id, str) or not _CONTRACT_ID.fullmatch(contract_id):
        raise ContractError("contract.contract_id: does not match the safe identifier grammar")
    max_input_bytes = _bounded_int(contract["max_input_bytes"], 1, HARD_MAX_INPUT_BYTES, "contract.max_input_bytes")
    max_tokens = _bounded_int(contract["max_tokens"], 1, HARD_MAX_TOKENS, "contract.max_tokens")
    max_commands = _bounded_int(contract["max_commands"], 1, HARD_MAX_COMMANDS, "contract.max_commands")
    lexicon = _word_list(contract["literal_lexicon"], HARD_MAX_LEXICON, "contract.literal_lexicon", _WORD)

    raw_operations = contract["operations"]
    if not isinstance(raw_operations, dict) or not raw_operations:
        raise ContractError("contract.operations: expected a non-empty object")
    operations: dict[str, dict[str, str]] = {}
    for name, spec in raw_operations.items():
        if name not in OPERATION_EFFECTS:
            raise ContractError("contract.operations: operation is outside the closed operation table")
        item = _exact(spec, frozenset({"effect"}), f"contract.operations.{name}")
        if item["effect"] not in PERMITTED_EFFECTS or item["effect"] != OPERATION_EFFECTS[name]:
            raise ContractError(f"contract.operations.{name}.effect: effect class is not the fixed class")
        operations[name] = {"effect": item["effect"]}

    raw_units = contract["units"]
    if not isinstance(raw_units, dict) or not 1 <= len(raw_units) <= HARD_MAX_UNITS:
        raise ContractError(f"contract.units: expected an object of 1 through {HARD_MAX_UNITS} units")
    reserved = frozenset(OPERATION_EFFECTS) | STRUCTURAL_WORDS
    units: dict[str, dict[str, str]] = {}
    for name, spec in raw_units.items():
        if not isinstance(name, str) or not _WORD.fullmatch(name) or name in reserved:
            raise ContractError("contract.units: unit name is not an allowed non-reserved word")
        item = _exact(spec, frozenset({"dimension"}), "contract.units.<unit>")
        dimension = item["dimension"]
        if not isinstance(dimension, str) or not _DIMENSION.fullmatch(dimension):
            raise ContractError("contract.units.<unit>.dimension: does not match the dimension grammar")
        units[name] = {"dimension": dimension}

    unknowns = _word_list(contract["explicit_unknowns"], HARD_MAX_UNKNOWNS, "contract.explicit_unknowns", _UNKNOWN_KEY)
    if not REQUIRED_UNKNOWNS <= set(unknowns):
        raise ContractError("contract.explicit_unknowns: the required unknowns may not be removed")

    normalized = {
        "schema": CONTRACT_SCHEMA,
        "contract_id": contract_id,
        "max_input_bytes": max_input_bytes,
        "max_tokens": max_tokens,
        "max_commands": max_commands,
        "literal_lexicon": lexicon,
        "units": {name: units[name] for name in sorted(units)},
        "quantity_range": _range(contract["quantity_range"], HARD_MAX_QUANTITY, "contract.quantity_range"),
        "repeat_range": _range(contract["repeat_range"], HARD_MAX_REPEAT, "contract.repeat_range", floor=1),
        "operations": {name: operations[name] for name in sorted(operations)},
        "explicit_unknowns": unknowns,
    }
    try:
        sha256_json(normalized)
    except EvidenceError as exc:
        raise ContractError(f"contract: {exc}") from exc
    return copy.deepcopy(normalized)


def contract_sha256(contract: Any) -> str:
    """SHA-256 of the normalized contract under the lattice compact JSON profile."""
    return sha256_json(validate_contract(contract))


def command_words(contract: dict[str, Any]) -> frozenset[str]:
    """Words with grammatical meaning under an already validated contract."""
    words = set(contract["operations"]) | {CONNECTOR}
    if "repeat" in contract["operations"]:
        words.add(REPEAT_SUFFIX)
    return frozenset(words)
