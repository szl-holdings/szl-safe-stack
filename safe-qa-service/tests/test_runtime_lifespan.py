"""Verify local intake never starts a provider-control audit worker."""

from __future__ import annotations

import asyncio
import importlib

import pytest

from safe_qa_service.settings import ConfigurationError

application = importlib.import_module("safe_qa_service.app")


def test_local_lifespan_does_not_start_control_worker(monkeypatch):
    monkeypatch.setenv("SAFE_QA_PRODUCTION_MODE", "false")

    async def forbidden_worker(_stop):
        raise AssertionError("local intake must not access control leases")

    monkeypatch.setattr(application, "_audit_outbox_worker", forbidden_worker)

    async def exercise():
        async with application._lifespan(application.app):
            await asyncio.sleep(0)

    asyncio.run(exercise())


def test_production_lifespan_starts_and_joins_control_worker(monkeypatch):
    monkeypatch.setenv("SAFE_QA_PRODUCTION_MODE", "true")
    observations = []

    async def exercise():
        started = asyncio.Event()

        async def worker(stop):
            observations.append("started")
            started.set()
            await stop.wait()
            observations.append("stopped")

        monkeypatch.setattr(application, "_audit_outbox_worker", worker)
        async with application._lifespan(application.app):
            await asyncio.wait_for(started.wait(), timeout=1)
            assert observations == ["started"]
        assert observations == ["started", "stopped"]

    asyncio.run(exercise())


def test_invalid_runtime_mode_prevents_startup(monkeypatch):
    monkeypatch.setenv("SAFE_QA_PRODUCTION_MODE", "maybe")

    async def exercise():
        with pytest.raises(ConfigurationError, match="must be true or false"):
            async with application._lifespan(application.app):
                raise AssertionError("invalid configuration must not start")

    asyncio.run(exercise())
