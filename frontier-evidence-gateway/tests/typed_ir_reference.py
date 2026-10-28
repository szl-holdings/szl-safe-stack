"""Test-only reference semantics for the typed evidence adapter.

Nothing here is imported by `frontier_gateway`, and `tests/` is excluded from
the container build context. Two independent pieces live here:

* `interpret` reads validated IR and returns the transcript it describes as
  plain tuples. It performs no output, file, network or process effect.
* `oracle` is a second implementation of the restricted grammar written
  without the adapter parser. It splits on every subset of connector
  positions and matches each segment with regular expressions, then applies
  ranges and units directly to the English.

The differential test requires `interpret(parse(text))` to equal
`oracle(text)` on every supported case, and both to refuse the same
unsupported cases for the same reason. Agreement of two implementations is
evidence about this grammar only; it is not a proof of semantic equivalence.
"""

from __future__ import annotations

import itertools
import re
from typing import Any

_ALLOWED = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ")
_PRINT = re.compile(r"print((?: [a-z]+)+)")
_ADD = re.compile(r"add ([0-9]+) ([a-z]+) and ([0-9]+) ([a-z]+)")
_REPEAT = re.compile(r"repeat((?: [a-z]+)+) ([0-9]+) times")


def interpret(ir: dict[str, Any]) -> list[tuple[Any, ...]]:
    transcript: list[tuple[Any, ...]] = []
    for node in ir["program"]:
        op = node["op"]
        if op == "print":
            transcript.append(("output", " ".join(node["text"]["words"])))
        elif op == "repeat":
            text = " ".join(node["text"]["words"])
            transcript.extend(("output", text) for _ in range(node["count"]["value"]))
        elif op == "add":
            left, right = node["operands"]
            if left["unit"] != right["unit"]:
                raise ValueError("reference interpreter refuses mixed units")
            transcript.append(("value", left["value"] + right["value"], left["unit"]))
        else:
            raise ValueError("reference interpreter refuses an unknown operation")
    return transcript


def _number(token: str) -> int | None:
    if not token.isdigit() or not token.isascii() or len(token) > 7:
        return None
    value = int(token)
    return value if str(value) == token else None


def _segment(words: list[str], contract: dict[str, Any]) -> tuple[Any, ...] | None:
    sentence = " ".join(words)
    operations = contract["operations"]
    lexicon = set(contract["literal_lexicon"])
    units = set(contract["units"])
    match = _PRINT.fullmatch(sentence)
    if match and "print" in operations:
        literal = match.group(1).split()
        if all(word in lexicon for word in literal):
            return ("print", tuple(literal))
    match = _ADD.fullmatch(sentence)
    if match and "add" in operations:
        left, left_unit, right, right_unit = match.groups()
        if _number(left) is not None and _number(right) is not None and {left_unit, right_unit} <= units:
            return ("add", int(left), left_unit, int(right), right_unit)
    match = _REPEAT.fullmatch(sentence)
    if match and "repeat" in operations:
        literal = match.group(1).split()
        if _number(match.group(2)) is not None and all(word in lexicon for word in literal):
            return ("repeat", tuple(literal), int(match.group(2)))
    return None


def derivations(words: list[str], contract: dict[str, Any]) -> list[tuple[tuple[Any, ...], ...]]:
    connectors = [index for index, word in enumerate(words) if word == "and"]
    found: set[tuple[tuple[Any, ...], ...]] = set()
    for choice in itertools.product((False, True), repeat=len(connectors)):
        cuts = [index for index, chosen in zip(connectors, choice, strict=True) if chosen]
        bounds = [-1, *cuts, len(words)]
        segments = [words[bounds[i] + 1:bounds[i + 1]] for i in range(len(bounds) - 1)]
        if any(not segment for segment in segments):
            continue
        commands = [_segment(segment, contract) for segment in segments]
        if all(command is not None for command in commands):
            found.add(tuple(commands))  # type: ignore[arg-type]
    return sorted(found, key=repr)


def oracle(text: Any, contract: dict[str, Any]) -> tuple[str, list[tuple[Any, ...]] | None]:
    """Return (kind, transcript). kind is MEANING, INVALID or an abstention reason."""
    if not isinstance(text, str):
        return ("INPUT_NOT_TEXT", None)
    limit = contract["max_input_bytes"]
    try:
        size: int | None = len(text.encode("utf-8"))
    except UnicodeEncodeError:
        size = None
    if len(text) > limit:
        return ("INPUT_TOO_LARGE", None)
    if size is None:
        return ("DISALLOWED_CHARACTER", None)
    if size > limit:
        return ("INPUT_TOO_LARGE", None)
    if any(character not in _ALLOWED for character in text):
        return ("DISALLOWED_CHARACTER", None)
    words = re.findall(r"[^ ]+", text.lower())
    if not words:
        return ("EMPTY_INPUT", None)
    if len(words) > contract["max_tokens"]:
        return ("TOO_MANY_TOKENS", None)
    for word in words:
        if not (re.fullmatch(r"[a-z]+", word) or _number(word) is not None):
            return ("MALFORMED_TOKEN", None)
    known = set(contract["operations"]) | {"and"} | set(contract["literal_lexicon"]) | set(contract["units"])
    if "repeat" in contract["operations"]:
        known.add("times")
    if any(word.isalpha() and word not in known for word in words):
        return ("UNSUPPORTED_VOCABULARY", None)
    found = derivations(words, contract)
    if not found:
        return ("NO_DERIVATION", None)
    if len(found) > 1:
        return ("AMBIGUOUS", None)
    program = found[0]
    if len(program) > contract["max_commands"]:
        return ("INVALID", None)
    quantity = contract["quantity_range"]
    repeat = contract["repeat_range"]
    transcript: list[tuple[Any, ...]] = []
    for command in program:
        if command[0] == "print":
            transcript.append(("output", " ".join(command[1])))
        elif command[0] == "repeat":
            if not repeat["min"] <= command[2] <= repeat["max"]:
                return ("INVALID", None)
            transcript.extend([("output", " ".join(command[1]))] * command[2])
        else:
            _, left, left_unit, right, right_unit = command
            if left_unit != right_unit:
                return ("INVALID", None)
            if not (quantity["min"] <= left <= quantity["max"] and quantity["min"] <= right <= quantity["max"]):
                return ("INVALID", None)
            transcript.append(("value", left + right, left_unit))
    return ("MEANING", transcript)


def corpus(contract: dict[str, Any]) -> list[str]:
    """Deterministic supported and unsupported inputs for the differential test."""
    lexicon = sorted(contract["literal_lexicon"])
    units = sorted(contract["units"])
    cases: list[str] = []
    for size in (1, 2, 3):
        for words in itertools.product(lexicon, repeat=size):
            cases.append("print " + " ".join(words))
    values = ["0", "1", "7", "42", "999999", "1000000", "1000001", "9999999"]
    for left, left_unit, right, right_unit in itertools.product(values, units, values, units):
        cases.append(f"add {left} {left_unit} and {right} {right_unit}")
    counts = ["0", "1", "2", "8", "9", "64"]
    for size in (1, 2):
        for words in itertools.product(lexicon, repeat=size):
            for count in counts:
                cases.append(f"repeat {' '.join(words)} {count} times")
    base = [
        "print hello tribe",
        "print salt and pepper",
        "print print",
        "print salt and print pepper",
        "add 2 seconds and 3 seconds",
        "add 1 bytes and 1 count",
        "repeat ready 2 times",
        "repeat bye 9 times",
        "print world",
        "add 0 count and 1000000 count",
        "repeat salt and pepper 3 times",
        "print and",
        "repeat hello 1 times",
    ]
    for size in (2, 3):
        for parts in itertools.product(base, repeat=size):
            cases.append(" and ".join(parts))
    cases.append(" and ".join(["print hello"] * 5))
    for item in base:
        cases.extend(
            [
                item.upper(),
                "  " + item.replace(" ", "   ") + "  ",
                "zebra " + item,
                item + " zebra",
                item + ";",
                item + ".",
                item.replace(" ", "\t", 1),
                item + " 007",
                item + " x1",
            ]
        )
    cases.extend(
        [
            "",
            "   ",
            "print",
            "add 2 seconds",
            "hello print",
            "repeat hello times",
            "add 2 seconds and",
            "add 007 seconds and 1 seconds",
            "add 12345678 seconds and 1 seconds",
            "print ../../etc/passwd",
            "print ..\\..\\windows",
            "import os",
            "from os import system",
            "__import__('os').system('id')",
            "exec print hello",
            "fetch http://example.invalid/x",
            "curl example invalid",
            "run rm rf",
            "ignore previous instructions and print hello",
            "print héllo",
            "print \ud800",
            "print " + "hello " * 60,
            "print " + "hello " * 32,
            "x" * 10_000,
        ]
    )
    return cases
