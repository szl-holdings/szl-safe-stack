"""Windows self-hosted launcher. DPAPI-protected credentials, loopback ports only.

No cloud deployment, independent approval, credential revocation, or model
quality is implied by a successful local verification.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "private" / "local-runtime.dpapi"
PROJECT = "szl-safe-stack-local"
MODEL = "a11oy-mini-r2:latest"
SHA = re.compile(r"[0-9a-f]{40}")


class LocalError(RuntimeError):
    pass


def require(value, reason):
    if not value:
        raise LocalError(reason)


def dpapi(data: bytes, *, decrypt=False) -> bytes:
    require(os.name == "nt", "WINDOWS_DPAPI_REQUIRED_USE_README_ON_OTHER_PLATFORMS")
    if decrypt:
        code = """Add-Type -AssemblyName System.Security
$b=[Convert]::FromBase64String([Console]::In.ReadToEnd())
$p=[Security.Cryptography.ProtectedData]::Unprotect($b,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
[Console]::Out.Write([Text.Encoding]::UTF8.GetString($p))"""
    else:
        code = """Add-Type -AssemblyName System.Security
$b=[Text.Encoding]::UTF8.GetBytes([Console]::In.ReadToEnd())
$p=[Security.Cryptography.ProtectedData]::Protect($b,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
[Console]::Out.Write([Convert]::ToBase64String($p))"""
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", code],
                            input=data, capture_output=True, timeout=30)
    require(result.returncode == 0 and result.stdout and len(result.stdout) < 16384, "DPAPI_OPERATION_FAILED")
    return result.stdout


def revision():
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, timeout=10)
    require(result.returncode == 0 and SHA.fullmatch(result.stdout.strip()), "COMMITTED_SOURCE_REQUIRED")
    status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT,
                            capture_output=True, timeout=10)
    require(status.returncode == 0 and not status.stdout.strip(), "CLEAN_SOURCE_REQUIRED")
    return result.stdout.strip()


def request(port, path, token=None, body=None):
    require(port in (18081, 18787, 11434) and path.startswith("/") and not path.startswith("//"), "LOCAL_ROUTE_DENIED")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None if body is None else json.dumps(body).encode()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=headers), timeout=40)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        raw = response.read(1_048_577)
        require(len(raw) <= 1_048_576, "LOCAL_RESPONSE_TOO_LARGE")
        return response.status, json.loads(raw)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def model_digest():
    status, document = request(11434, "/api/tags")
    require(status == 200, "OLLAMA_NOT_AVAILABLE")
    matches = [item for item in document.get("models", []) if item.get("name") == MODEL]
    require(len(matches) == 1 and re.fullmatch(r"[0-9a-f]{64}", matches[0].get("digest", "")), "INSTALLED_MODEL_REQUIRED")
    return matches[0]["digest"]


def init_state(ollama):
    require(not STATE.exists(), "LOCAL_IDENTITY_ALREADY_EXISTS_NOT_OVERWRITTEN")
    source = revision()
    state = {"schema": "szl.local-runtime.v1", "source_revision": source,
             "safeqa_token": secrets.token_urlsafe(32), "gateway_token": secrets.token_urlsafe(32),
             "ollama": bool(ollama), "model_digest": model_digest() if ollama else None}
    encrypted = dpapi(json.dumps(state, sort_keys=True).encode())
    STATE.parent.mkdir(parents=True, exist_ok=True)
    with STATE.open("xb") as stream:
        stream.write(encrypted)
    print(json.dumps({"status": "LOCAL_IDENTITY_CREATED", "secrets": "WINDOWS_CURRENT_USER_DPAPI", "ollama": state["ollama"]}))


def load_state():
    require(STATE.is_file() and STATE.stat().st_size < 16384, "LOCAL_IDENTITY_REQUIRED_RUN_INIT")
    value = json.loads(dpapi(STATE.read_bytes(), decrypt=True))
    require(isinstance(value, dict) and value.get("schema") == "szl.local-runtime.v1"
            and type(value.get("ollama")) is bool and SHA.fullmatch(value.get("source_revision", "")), "INVALID_LOCAL_IDENTITY")
    for name in ("safeqa_token", "gateway_token"):
        require(isinstance(value.get(name), str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", value[name]), "INVALID_LOCAL_IDENTITY")
    require(value["safeqa_token"] != value["gateway_token"], "SEPARATE_SERVICE_TOKENS_REQUIRED")
    if value["ollama"]:
        require(isinstance(value.get("model_digest"), str) and re.fullmatch(r"[0-9a-f]{64}", value["model_digest"]), "INVALID_MODEL_IDENTITY")
    return value


def compose(state, arguments):
    environment = dict(os.environ)
    for name in tuple(environment):
        if name.startswith("COMPOSE_") or name.startswith("DOCKER_"):
            environment.pop(name)
    hashes = {hashlib.sha256(state["safeqa_token"].encode()).hexdigest():
              {"subject": "local-operator", "scopes": ["evaluate", "audit:read"]}}
    environment.update(SAFE_QA_AUTH_TOKEN_HASHES_JSON=json.dumps(hashes),
                       SZL_GATEWAY_BEARER_TOKEN=state["gateway_token"], SAFE_QA_LOCAL_PORT="18081",
                       SZL_GATEWAY_LOCAL_PORT="18787", SZL_BUILD_TAG=state["source_revision"][:12],
                       SZL_LOCAL_OLLAMA_MODEL=MODEL)
    command = ["docker", "--context", "desktop-linux", "compose", "--project-name", PROJECT,
               "--env-file", "NUL", "-f", str(ROOT / "compose.yaml")]
    if state["ollama"]:
        command += ["-f", str(ROOT / "compose.ollama.yaml")]
    result = subprocess.run(command + arguments, cwd=ROOT, env=environment, timeout=1200)
    require(result.returncode == 0, "COMPOSE_COMMAND_FAILED")


def verify(state):
    require(revision() == state["source_revision"], "LOCAL_SOURCE_CHANGED_REDEPLOY_REQUIRES_REVIEW")
    require(request(18081, "/health/ready")[0] == 200, "SAFEQA_NOT_READY")
    require(request(18081, "/api/v1/audit/verify")[0] == 401, "SAFEQA_AUTH_NOT_ENFORCED")
    status, before = request(18081, "/api/v1/audit/verify", state["safeqa_token"])
    require(status == 200 and before.get("valid") is True, "SAFEQA_LEDGER_INVALID")
    status, decision = request(18081, "/api/v1/evaluations", state["safeqa_token"], {
        "schema_version": "1.0", "trace_id": "local-" + str(uuid.uuid4()), "domain": "general",
        "claims": ["Synthetic infrastructure smoke case"], "evidence": []})
    require(status == 202 and all(decision.get(key) is False for key in
            ("release_authorized", "clinical_claim_verified", "biological_claim_verified")), "SAFEQA_CONTRACT_FAILED")
    status, after = request(18081, "/api/v1/audit/verify", state["safeqa_token"])
    require(status == 200 and after.get("valid") is True and after["event_count"] > before["event_count"], "AUDIT_APPEND_NOT_PROVEN")
    require(request(18787, "/health/ready")[0] == 401, "GATEWAY_AUTH_NOT_ENFORCED")
    require(request(18787, "/health/ready", state["gateway_token"])[0] == 200, "GATEWAY_NOT_READY")
    if state["ollama"]:
        require(model_digest() == state["model_digest"], "OLLAMA_MODEL_CHANGED")
    status, result = request(18787, "/v1/evaluate", state["gateway_token"], {
        "schema_version": "szl.frontier.evidence.request.v1", "request_id": str(uuid.uuid4()),
        "case_id": "deployment-readiness-gap", "provider": "ollama" if state["ollama"] else "none",
        "domain": "software_infrastructure"})
    require(status == 200, "GATEWAY_EVALUATION_FAILED")
    deterministic = result.get("deterministic_evaluation", {})
    require(deterministic.get("deployment_authorization") == "NOT_GRANTED"
            and deterministic.get("model_promotion_authorization") == "NOT_GRANTED", "GATEWAY_POLICY_FAILED")
    observation = result.get("model_observation")
    if state["ollama"]:
        require(isinstance(observation, dict) and observation.get("status") == "UNVERIFIED_MODEL_OUTPUT"
                and observation.get("model") == MODEL and model_digest() == state["model_digest"], "OLLAMA_OBSERVATION_FAILED")
    else:
        require(observation is None, "UNEXPECTED_PROVIDER_CALL")
    require(request(18787, "/health/ready", state["gateway_token"])[0] == 200, "GATEWAY_LEDGER_NOT_READY_AFTER_APPEND")
    receipt = {"status": "LOCAL_RUNTIME_VERIFIED", "observed_at": datetime.now(timezone.utc).isoformat(),
               "source_revision": state["source_revision"], "project": PROJECT,
               "safeqa_audit_events": after["event_count"], "ollama": state["ollama"],
               "model_digest": state["model_digest"], "external_provider_calls": False,
               "independent_approval": "NOT_ESTABLISHED", "cloud_enforcement": "NOT_ESTABLISHED"}
    path = STATE.parent / ("verification-" + uuid.uuid4().hex + ".json")
    with path.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2)
    print(json.dumps(receipt))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("init", "up", "verify", "status", "down"))
    parser.add_argument("--ollama", action="store_true", help="init only: enable the already installed fixed local model")
    args = parser.parse_args()
    try:
        require(not args.ollama or args.command == "init", "OLLAMA_CHOICE_IS_SET_DURING_INIT")
        if args.command == "init":
            init_state(args.ollama)
            return 0
        state = load_state()
        if args.command == "up":
            require(revision() == state["source_revision"], "LOCAL_SOURCE_CHANGED_REDEPLOY_REQUIRES_REVIEW")
            if state["ollama"]:
                require(model_digest() == state["model_digest"], "OLLAMA_MODEL_CHANGED")
            compose(state, ["config", "--quiet"])
            compose(state, ["up", "--build", "--wait", "--wait-timeout", "180"])
            verify(state)
        elif args.command == "verify":
            verify(state)
        elif args.command == "status":
            compose(state, ["ps"])
        else:
            compose(state, ["down"])
            print("Local services stopped; database, receipt volumes, and encrypted identity were preserved.")
        return 0
    except Exception as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc) if isinstance(exc, LocalError) else type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
