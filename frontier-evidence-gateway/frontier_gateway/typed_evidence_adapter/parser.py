"""Restricted deterministic parser from a closed English subset to inert IR.

Grammar, after ASCII lower-casing and collapsing runs of spaces:

    program  := command ("and" command)*
    command  := "print" literal
              | "add" quantity "and" quantity
              | "repeat" literal number "times"
    literal  := word+            each word is in the contract literal lexicon
    quantity := number unit      unit is a contract unit name
    number   := "0" | [1-9][0-9]{0,6}

Checks run in this order and the first failure decides the result:
type, size, character set, token count, token shape, vocabulary, derivation.
Every derivation of the token sequence is counted (saturating at two). Zero
derivations abstain with NO_DERIVATION; two or more abstain with AMBIGUOUS; the
parser never picks one reading. Ranges, units and effects are not checked here:
the independent validator does that.

The parser returns data only: dicts, lists, strings and integers. It has no
eval, exec, compile, import machinery, file, network or process access, and it
does not copy unsupported input into its result.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any

from .contract import CONNECTOR, IR_SCHEMA, REPEAT_SUFFIX, command_words

_CHARSET = re.compile(r"[A-Za-z0-9 ]*")
_WORD = re.compile(r"[a-z]+")
_NUMBER = re.compile(r"0|[1-9][0-9]{0,6}")

CANDIDATE = "CANDIDATE"
UNTRANSLATED = "UNTRANSLATED"
ABSTAIN = "ABSTAIN"


@dataclass(frozen=True)
class ParseResult:
    status: str
    reason: str | None
    token_count: int
    derivation_count: int
    unsupported_token_positions: tuple[int, ...]
    ir: dict[str, Any] | None

    def summary(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "token_count": self.token_count,
            "derivation_count": self.derivation_count,
            "derivation_count_saturates_at": 2,
            "unsupported_token_positions": list(self.unsupported_token_positions),
        }


def _result(status: str, reason: str | None, tokens: int = 0, derivations: int = 0,
            positions: tuple[int, ...] = (), ir: dict[str, Any] | None = None) -> ParseResult:
    return ParseResult(status, reason, tokens, derivations, positions, ir)


def tokenize(text: str) -> list[str]:
    """Deterministic normalization shared by the parser and its callers."""
    return [token for token in text.lower().split(" ") if token]


def _literal(words: list[str]) -> dict[str, Any]:
    return {"type": "text_literal", "words": list(words)}


def _quantity(number: str, unit: str) -> dict[str, Any]:
    return {"type": "quantity", "value": int(number), "unit": unit}


def _command(tokens: list[str], start: int, end: int, contract: dict[str, Any]) -> dict[str, Any] | None:
    head = tokens[start]
    body = tokens[start + 1:end]
    operations = contract["operations"]
    lexicon = contract["_lexicon"]
    units = contract["units"]
    if head == "print" and "print" in operations:
        if body and all(word in lexicon for word in body):
            return {"op": "print", "text": _literal(body)}
    elif head == "add" and "add" in operations:
        if (
            len(body) == 5
            and body[2] == CONNECTOR
            and _NUMBER.fullmatch(body[0])
            and body[1] in units
            and _NUMBER.fullmatch(body[3])
            and body[4] in units
        ):
            return {"op": "add", "operands": [_quantity(body[0], body[1]), _quantity(body[3], body[4])]}
    elif head == "repeat" and "repeat" in operations:
        if (
            len(body) >= 3
            and body[-1] == REPEAT_SUFFIX
            and _NUMBER.fullmatch(body[-2])
            and all(word in lexicon for word in body[:-2])
        ):
            return {
                "op": "repeat",
                "text": _literal(body[:-2]),
                "count": {"type": "integer", "value": int(body[-2])},
            }
    return None


def _derivations(tokens: list[str], contract: dict[str, Any]) -> list[list[dict[str, Any]]]:
    """All programs covering `tokens`, saturating at two distinct programs."""
    count = len(tokens)
    ending: list[list[list[dict[str, Any]]]] = [[] for _ in range(count + 1)]
    for end in range(1, count + 1):
        found: list[list[dict[str, Any]]] = []
        for start in range(end):
            if start == 0:
                prefixes: list[list[dict[str, Any]]] = [[]]
            elif start >= 2 and tokens[start - 1] == CONNECTOR:
                prefixes = ending[start - 1]
            else:
                continue
            if not prefixes:
                continue
            node = _command(tokens, start, end, contract)
            if node is None:
                continue
            for prefix in prefixes:
                found.append([*prefix, node])
                if len(found) >= 2:
                    break
            if len(found) >= 2:
                break
        ending[end] = found
    return ending[count]


def parse(text: Any, contract: dict[str, Any], contract_digest: str) -> ParseResult:
    """Parse `text` under an already validated contract.

    `contract_digest` is bound into the IR so a validator can refuse IR that was
    produced under a different contract.
    """
    if not isinstance(text, str):
        return _result(ABSTAIN, "INPUT_NOT_TEXT")
    limit = contract["max_input_bytes"]
    if len(text) > limit:
        return _result(ABSTAIN, "INPUT_TOO_LARGE")
    try:
        size = len(text.encode("utf-8"))
    except UnicodeEncodeError:
        return _result(ABSTAIN, "DISALLOWED_CHARACTER")
    if size > limit:
        return _result(ABSTAIN, "INPUT_TOO_LARGE")
    if not _CHARSET.fullmatch(text):
        return _result(ABSTAIN, "DISALLOWED_CHARACTER")
    tokens = tokenize(text)
    if not tokens:
        return _result(ABSTAIN, "EMPTY_INPUT")
    if len(tokens) > contract["max_tokens"]:
        return _result(ABSTAIN, "TOO_MANY_TOKENS", len(tokens))
    if any(not (_WORD.fullmatch(token) or _NUMBER.fullmatch(token)) for token in tokens):
        return _result(ABSTAIN, "MALFORMED_TOKEN", len(tokens))

    view = dict(contract)
    view["_lexicon"] = frozenset(contract["literal_lexicon"])
    known = command_words(contract) | view["_lexicon"] | frozenset(contract["units"])
    unsupported = tuple(
        index for index, token in enumerate(tokens) if _WORD.fullmatch(token) and token not in known
    )
    if unsupported:
        return _result(UNTRANSLATED, "UNSUPPORTED_VOCABULARY", len(tokens), 0, unsupported)

    programs = _derivations(tokens, view)
    if not programs:
        return _result(ABSTAIN, "NO_DERIVATION", len(tokens))
    if len(programs) > 1:
        return _result(ABSTAIN, "AMBIGUOUS", len(tokens), 2)
    ir = {
        "schema": IR_SCHEMA,
        "contract_sha256": contract_digest,
        "program": copy.deepcopy(programs[0]),
    }
    return _result(CANDIDATE, None, len(tokens), 1, (), ir)
