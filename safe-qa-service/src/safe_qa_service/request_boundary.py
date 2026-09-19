"""Bound and validate request bytes before framework JSON parsing."""

from __future__ import annotations

import asyncio
import json
import math
import re
from typing import Any

from starlette.responses import Response


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        key.encode("utf-8", "strict")
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite JSON number")
    return number


def validate_json(body: bytes) -> None:
    value = json.loads(
        body.decode("utf-8", "strict"), object_pairs_hook=_unique_object,
        parse_constant=_reject_constant, parse_float=_finite_float,
    )
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > 64:
            raise ValueError("JSON nesting limit")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            item.encode("utf-8", "strict")


class RequestBoundaryMiddleware:
    maximum_body_bytes = 512_000
    maximum_read_seconds = 10

    def __init__(self, app: Any):
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        async def secure_send(message: dict[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                message = dict(message)
                message["headers"] = list(message.get("headers", [])) + [
                    (b"cache-control", b"no-store"),
                    (b"x-content-type-options", b"nosniff"),
                ]
            await send(message)

        async def reject(code: int) -> None:
            await Response(status_code=code)(scope, receive, secure_send)

        header_values: dict[bytes, list[bytes]] = {}
        for key, value in scope.get("headers", []):
            header_values.setdefault(key.lower(), []).append(value)
        for key in (b"content-length", b"content-type", b"authorization", b"transfer-encoding"):
            if len(header_values.get(key, [])) > 1:
                await reject(400)
                return
        length_values = header_values.get(b"content-length", [])
        if length_values and b"transfer-encoding" in header_values:
            await reject(400)
            return
        declared = None
        if length_values:
            length = length_values[0]
            if not re.fullmatch(rb"[0-9]{1,12}", length):
                await reject(400)
                return
            declared = int(length)
            if declared > self.maximum_body_bytes:
                await reject(413)
                return

        body = bytearray()

        async def collect() -> int | None:
            while True:
                message = await receive()
                if message.get("type") == "http.disconnect":
                    return 400
                if message.get("type") != "http.request":
                    return 400
                chunk = message.get("body", b"")
                if not isinstance(chunk, bytes):
                    return 400
                if len(body) + len(chunk) > self.maximum_body_bytes:
                    return 413
                body.extend(chunk)
                if not message.get("more_body", False):
                    return None

        try:
            error = await asyncio.wait_for(collect(), timeout=self.maximum_read_seconds)
        except TimeoutError:
            error = 408
        if error:
            await reject(error)
            return
        if declared is not None and len(body) != declared:
            await reject(400)
            return
        content_type = header_values.get(b"content-type", [b"application/json"])[0]
        media_type = content_type.split(b";", 1)[0].strip().lower()
        if body and (media_type == b"application/json" or media_type.endswith(b"+json")):
            try:
                validate_json(bytes(body))
            except (ValueError, UnicodeError, RecursionError):
                await reject(400)
                return
        delivered = False

        async def replay_receive() -> dict[str, Any]:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, secure_send)
