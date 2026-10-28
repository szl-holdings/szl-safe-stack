"""Independent schema, type, range and effect validation for adapter IR.

This module does not import the parser. It accepts IR from any producer, the
parser included, and checks it only against the validated contract. Error
strings name a path and a rule; they never echo an untrusted value.

No unit conversion is performed: both operands of `add` must carry the same
contract unit. A program whose declared effects fall outside the permitted
effect classes is refused; permitted effects are declared, never performed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..lattice_adapter import EvidenceError, canonical_json
from .contract import IR_SCHEMA, OPERATION_EFFECTS, PERMITTED_EFFECTS

_MAX_DEPTH = 6
_MAX_NODES = 2048
_NODE_KEYS = {
    "print": frozenset({"op", "text"}),
    "add": frozenset({"op", "operands"}),
    "repeat": frozenset({"op", "text", "count"}),
}


@dataclass(frozen=True)
class ValidationResult:
    errors: tuple[str, ...]
    declared_effects: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.errors


class _Inert:
    """Refuse anything outside dict/list/str/int, including bool and float."""

    def __init__(self) -> None:
        self.nodes = 0
        self.errors: list[str] = []

    def walk(self, value: Any, path: str, depth: int) -> None:
        self.nodes += 1
        if self.nodes > _MAX_NODES:
            if not self.errors or self.errors[-1] != "$: IR exceeds the node bound":
                self.errors.append("$: IR exceeds the node bound")
            return
        if depth > _MAX_DEPTH:
            self.errors.append(f"{path}: IR exceeds the depth bound")
            return
        kind = type(value)
        if kind is dict:
            for key, item in value.items():
                if type(key) is not str:
                    self.errors.append(f"{path}: object keys must be strings")
                    continue
                self.walk(item, f"{path}.<key>", depth + 1)
        elif kind is list:
            for index, item in enumerate(value):
                self.walk(item, f"{path}[{index}]", depth + 1)
        elif kind not in (str, int):
            self.errors.append(f"{path}: value is not an inert IR value")


def _exact(value: Any, keys: frozenset[str], path: str, errors: list[str]) -> bool:
    if type(value) is not dict:
        errors.append(f"{path}: expected an object")
        return False
    if set(value) != keys:
        errors.append(f"{path}: unexpected or missing keys")
        return False
    return True


def _literal(value: Any, path: str, contract: dict[str, Any], errors: list[str]) -> None:
    if not _exact(value, frozenset({"type", "words"}), path, errors):
        return
    if value["type"] != "text_literal":
        errors.append(f"{path}.type: expected text_literal")
    words = value["words"]
    if type(words) is not list or not 1 <= len(words) <= contract["max_tokens"]:
        errors.append(f"{path}.words: expected 1 through max_tokens words")
        return
    lexicon = frozenset(contract["literal_lexicon"])
    for index, word in enumerate(words):
        if type(word) is not str or word not in lexicon:
            errors.append(f"{path}.words[{index}]: word is not in the literal lexicon")


def _integer(value: Any, bounds: dict[str, int], path: str, errors: list[str]) -> None:
    if type(value) is not int:
        errors.append(f"{path}: expected an integer")
    elif not bounds["min"] <= value <= bounds["max"]:
        errors.append(f"{path}: integer is outside the contract range")


def _quantity(value: Any, path: str, contract: dict[str, Any], errors: list[str]) -> str | None:
    if not _exact(value, frozenset({"type", "value", "unit"}), path, errors):
        return None
    if value["type"] != "quantity":
        errors.append(f"{path}.type: expected quantity")
    _integer(value["value"], contract["quantity_range"], f"{path}.value", errors)
    unit = value["unit"]
    if type(unit) is not str or unit not in contract["units"]:
        errors.append(f"{path}.unit: unit is not in the contract")
        return None
    return unit


def validate_ir(ir: Any, contract: dict[str, Any], contract_digest: str) -> ValidationResult:
    """Validate IR against an already validated contract and its digest."""
    inert = _Inert()
    inert.walk(ir, "$", 0)
    if inert.errors:
        return ValidationResult(tuple(inert.errors), ())
    errors: list[str] = []
    if not _exact(ir, frozenset({"schema", "contract_sha256", "program"}), "$", errors):
        return ValidationResult(tuple(errors), ())
    if ir["schema"] != IR_SCHEMA:
        errors.append("$.schema: unsupported IR schema")
    if ir["contract_sha256"] != contract_digest:
        errors.append("$.contract_sha256: IR is not bound to this contract")
    program = ir["program"]
    if type(program) is not list or not 1 <= len(program) <= contract["max_commands"]:
        errors.append("$.program: expected 1 through max_commands commands")
        return ValidationResult(tuple(errors), ())

    effects: set[str] = set()
    for index, node in enumerate(program):
        path = f"$.program[{index}]"
        if type(node) is not dict or type(node.get("op")) is not str:
            errors.append(f"{path}: expected an operation object")
            continue
        op = node["op"]
        if op not in _NODE_KEYS or op not in contract["operations"]:
            errors.append(f"{path}.op: operation is not enabled by the contract")
            continue
        if not _exact(node, _NODE_KEYS[op], path, errors):
            continue
        effect = OPERATION_EFFECTS.get(op)
        if effect not in PERMITTED_EFFECTS or contract["operations"][op]["effect"] != effect:
            errors.append(f"{path}.op: effect class is not permitted")
            continue
        effects.add(effect)
        if op in ("print", "repeat"):
            _literal(node["text"], f"{path}.text", contract, errors)
        if op == "repeat":
            count = node["count"]
            if _exact(count, frozenset({"type", "value"}), f"{path}.count", errors):
                if count["type"] != "integer":
                    errors.append(f"{path}.count.type: expected integer")
                _integer(count["value"], contract["repeat_range"], f"{path}.count.value", errors)
        if op == "add":
            operands = node["operands"]
            if type(operands) is not list or len(operands) != 2:
                errors.append(f"{path}.operands: expected exactly two quantities")
                continue
            units = [
                _quantity(item, f"{path}.operands[{position}]", contract, errors)
                for position, item in enumerate(operands)
            ]
            if None not in units and units[0] != units[1]:
                errors.append(f"{path}.operands: unit mismatch; no unit conversion is performed")
    if not errors:
        try:
            canonical_json(ir)
        except EvidenceError:
            errors.append("$: IR is not canonical JSON")
    return ValidationResult(tuple(errors), tuple(sorted(effects)) if not errors else ())
