from __future__ import annotations

import asyncio

import pytest

from safe_qa_service.request_boundary import RequestBoundaryMiddleware


def probe(headers=(), chunks=(b"{}",), timeout=False):
    messages = []
    called = []

    async def downstream(scope, receive, send):
        called.append(await receive())
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    pending = [
        {"type": "http.request", "body": chunk, "more_body": i < len(chunks) - 1}
        for i, chunk in enumerate(chunks)
    ]

    async def receive():
        if timeout:
            await asyncio.sleep(1)
        return pending.pop(0) if pending else {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    boundary = RequestBoundaryMiddleware(downstream)
    boundary.maximum_read_seconds = 0.01
    asyncio.run(boundary({"type": "http", "headers": list(headers)}, receive, send))
    return messages, called


@pytest.mark.parametrize("body", [
    b'{"x":1,"x":2}', b'{"x":{"a":1,"a":2}}',
    b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}',
    b'{"x":"\xff"}', b'{"x":"\\ud800"}', b'[' * 66 + b'0' + b']' * 66,
])
def test_ambiguous_or_invalid_json_never_reaches_application(body):
    messages, called = probe(chunks=(body,))
    assert messages[0]["status"] == 400
    assert not called
    assert (b"cache-control", b"no-store") in messages[0]["headers"]


@pytest.mark.parametrize("headers", [
    [(b"content-length", b"2"), (b"content-length", b"2")],
    [(b"content-length", b"2"), (b"transfer-encoding", b"chunked")],
    [(b"content-length", b"+2")], [(b"content-length", b"3")],
    [(b"authorization", b"Bearer one"), (b"authorization", b"Bearer two")],
])
def test_ambiguous_or_inconsistent_framing_rejected(headers):
    messages, called = probe(headers)
    assert messages[0]["status"] == 400
    assert not called


def test_streamed_body_bound_is_enforced_before_framework_parsing():
    messages, called = probe(chunks=(b" " * 300_000, b" " * 300_000))
    assert messages[0]["status"] == 413
    assert not called


def test_valid_chunked_input_delivered_once_without_byte_changes():
    body = b'{"x":[1,2,3]}'
    messages, called = probe(chunks=(body[:4], body[4:]))
    assert messages[0]["status"] == 204
    assert called == [{"type": "http.request", "body": body, "more_body": False}]


def test_slow_body_has_total_time_bound():
    messages, called = probe(timeout=True)
    assert messages[0]["status"] == 408
    assert not called


def test_api_rejects_duplicate_input_before_any_ledger_write(client, auth_headers, fake_ledger):
    response = client.post(
        "/api/v1/synthetic/evaluations", headers=auth_headers,
        content=b'{"kind":"synthetic_software_qa","sample_scores_ppm":[0],'
        b'"sample_scores_ppm":[1000000],"case_id":"one"}',
    )
    assert response.status_code == 400
    assert not fake_ledger.events
