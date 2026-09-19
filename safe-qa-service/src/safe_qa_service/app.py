"""FastAPI entry point."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Annotated, Any
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Response, status

from .approval_verification import ApprovalVerificationError
from .auth import Principal, require_human_scopes, require_scopes, require_workload_scopes
from .aws_control import AwsControlError, AwsControlProvider, load_aws_target_policy
from .aws_evidence import AwsEvidenceRouter
from .control_plane import (
    ControlPlane,
    ControlPlaneError,
    ControlRepository,
    PlanReplayError,
    PostgresControlRepository,
    audit_outbox_readiness,
    flush_audit_outbox,
)
from .ledger import AuditLedger, LedgerUnavailable, PostgresAuditLedger
from .policy import evaluate
from .production_settings import load_approval_runtime_config, load_aws_evidence_routes
from .request_boundary import RequestBoundaryMiddleware
from .schemas.v1 import (
    ApprovalStatus,
    Disposition,
    EvaluationRequest,
    EvaluationResponse,
    LedgerVerificationResponse,
)
from .schemas.v2 import (
    ApprovalBundleV2,
    ControlExecutionResponseV2,
    DeploymentPlanV2,
    UnsignedPlanRequestV2,
    UnsignedPlanResponseV2,
)
from .settings import ConfigurationError, database_url, production_mode
from .synthetic_kernel import SyntheticRequest, SyntheticResponse, evaluate_synthetic

OUTBOX_DRAIN_INTERVAL_SECONDS = 5
OUTBOX_DRAIN_BATCH_SIZE = 25
OUTBOX_LEASE_SECONDS = 30
logger = logging.getLogger(__name__)


async def _audit_outbox_worker(stop: asyncio.Event) -> None:
    worker_id = uuid4()
    while not stop.is_set():
        try:
            connection_url = database_url()
            repository = PostgresControlRepository(connection_url)
            ledger = PostgresAuditLedger(connection_url)
            await asyncio.to_thread(
                flush_audit_outbox,
                repository=repository,
                ledger=ledger,
                limit=OUTBOX_DRAIN_BATCH_SIZE,
                lease_seconds=OUTBOX_LEASE_SECONDS,
                worker_id=worker_id,
            )
        except (ConfigurationError, ControlPlaneError, LedgerUnavailable) as exc:
            logger.warning("bounded audit outbox drain deferred: %s", type(exc).__name__)
        try:
            await asyncio.wait_for(stop.wait(), timeout=OUTBOX_DRAIN_INTERVAL_SECONDS)
        except TimeoutError:
            continue


@asynccontextmanager
async def _lifespan(_application: FastAPI):
    if not production_mode():
        # Local synthetic intake creates no provider-control outbox events and
        # uses an append-only runtime DB role, without control lease privileges.
        yield
        return
    stop = asyncio.Event()
    worker = asyncio.create_task(_audit_outbox_worker(stop))
    try:
        yield
    finally:
        stop.set()
        await worker

app = FastAPI(
    title="Safe QA Governed Evidence and Provider Control Service",
    version="0.2.1",
    description=(
        "Production-oriented, fail-closed evidence and AWS/EKS control infrastructure. Live v2 "
        "provider control remains disabled unless production mode and every identity, approval, "
        "target, evidence-route, database, and provider boundary are configured. It does not "
        "validate clinical or biological claims and cannot authorize release."
    ),
    lifespan=_lifespan,
)


app.add_middleware(RequestBoundaryMiddleware)


def get_ledger() -> AuditLedger:
    try:
        return PostgresAuditLedger(database_url())
    except ConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="audit ledger is not configured",
        ) from exc


def get_control_repository() -> ControlRepository:
    try:
        return PostgresControlRepository(database_url())
    except ConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="control repository is not configured",
        ) from exc


def get_control_plane(
    ledger: Annotated[AuditLedger, Depends(get_ledger)],
    repository: Annotated[ControlRepository, Depends(get_control_repository)],
) -> ControlPlane:
    try:
        if not production_mode():
            raise ConfigurationError("production control boundary is explicitly disabled")
        target_policy = load_aws_target_policy()
        approval = load_approval_runtime_config()
        if target_policy.account_id != approval.production_account_id:
            raise ConfigurationError("approval and provider production accounts differ")
        routes = load_aws_evidence_routes(approval.key_arns)
        return ControlPlane(
            provider=AwsControlProvider.from_runtime(target_policy),
            evidence=AwsEvidenceRouter.from_boto3(routes),
            repository=repository,
            ledger=ledger,
            approver_policies=approval.approvers,
            witness_policy=approval.witness,
            production_account_id=approval.production_account_id,
        )
    except (
        ConfigurationError,
        AwsControlError,
        ApprovalVerificationError,
        ControlPlaneError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="production control boundary is not completely configured",
        ) from exc


@app.get("/health/live", tags=["health"])
async def live() -> dict[str, str]:
    return {"status": "live"}


@app.get("/health/ready", tags=["health"])
def ready(response: Response) -> dict[str, Any]:
    pending_exports = -1
    oldest_pending_age_seconds = -1.0
    try:
        connection_url = database_url()
        ledger = PostgresAuditLedger(connection_url)
        ledger_ready = ledger.healthcheck()
        head_valid = ledger.verify_head() if ledger_ready else False
        if ledger_ready and head_valid:
            outbox_ready, outbox_status = audit_outbox_readiness(
                repository=PostgresControlRepository(connection_url),
                maximum_pending_count=0,
                maximum_oldest_age_seconds=0,
            )
            pending_exports = outbox_status.pending_count
            oldest_pending_age_seconds = outbox_status.oldest_pending_age_seconds
        else:
            outbox_ready = False
    except (ConfigurationError, ControlPlaneError, LedgerUnavailable):
        ledger_ready = False
        head_valid = False
        outbox_ready = False
    all_ready = ledger_ready and head_valid and outbox_ready
    if not all_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ready" if all_ready else "not_ready",
        "checks": {
            "postgres_schema": ledger_ready,
            "postgres_audit_head": head_valid,
            "control_audit_outbox_drained": outbox_ready,
        },
        "audit_outbox": {
            "pending_count": pending_exports,
            "oldest_pending_age_seconds": oldest_pending_age_seconds,
        },
    }


@app.get("/api/v1/schemas/evaluation-request", tags=["schemas"])
async def evaluation_request_schema() -> dict[str, Any]:
    return EvaluationRequest.model_json_schema()


@app.get("/api/v1/schemas/synthetic-request", tags=["schemas"])
async def synthetic_request_schema() -> dict[str, Any]:
    return SyntheticRequest.model_json_schema()


@app.post(
    "/api/v1/synthetic/evaluations",
    response_model=SyntheticResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["synthetic-software-qa"],
)
def create_synthetic_evaluation(
    request: SyntheticRequest,
    principal: Annotated[Principal, Depends(require_scopes("evaluate"))],
    ledger: Annotated[AuditLedger, Depends(get_ledger)],
) -> SyntheticResponse:
    outcome = evaluate_synthetic(request)
    request_id = uuid4()
    try:
        receipt = ledger.append(
            actor_subject=principal.subject,
            action="synthetic-software-qa.routed",
            request_id=request_id,
            payload={
                "request": request.model_dump(mode="json"),
                "outcome": outcome.model_dump(mode="json"),
                "auth": {
                    "issuer": principal.issuer,
                    "subject": principal.subject,
                    "principal_type": principal.principal_type,
                    "token_fingerprint": principal.token_fingerprint,
                },
            },
        )
    except LedgerUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="synthetic result withheld because mandatory audit recording failed",
        ) from exc
    return SyntheticResponse(
        **outcome.model_dump(),
        request_id=request_id,
        audit_event_id=receipt.event_id,
        audit_sequence_id=receipt.sequence_id,
        audit_event_hash=receipt.event_hash,
    )


@app.get("/api/v1/schemas/evaluation-response", tags=["schemas"])
async def evaluation_response_schema() -> dict[str, Any]:
    return EvaluationResponse.model_json_schema()


@app.get("/api/v2/schemas/deployment-plan", tags=["schemas"])
async def deployment_plan_schema() -> dict[str, Any]:
    return DeploymentPlanV2.model_json_schema()


@app.get("/api/v2/schemas/approval-bundle", tags=["schemas"])
async def approval_bundle_schema() -> dict[str, Any]:
    return ApprovalBundleV2.model_json_schema()


@app.post(
    "/api/v2/control/plans",
    response_model=UnsignedPlanResponseV2,
    status_code=status.HTTP_201_CREATED,
    tags=["production-control"],
)
def create_unsigned_control_plan(
    request: UnsignedPlanRequestV2,
    principal: Annotated[Principal, Depends(require_human_scopes("control:plan"))],
    control: Annotated[ControlPlane, Depends(get_control_plane)],
) -> UnsignedPlanResponseV2:
    try:
        return control.create_unsigned_plan(request, requester=principal)
    except ControlPlaneError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="unsigned plan could not be issued with complete provider evidence",
        ) from exc


@app.post(
    "/api/v2/control/executions",
    response_model=ControlExecutionResponseV2,
    tags=["production-control"],
)
def execute_signed_control_plan(
    bundle: ApprovalBundleV2,
    principal: Annotated[Principal, Depends(require_workload_scopes("control:execute"))],
    control: Annotated[ControlPlane, Depends(get_control_plane)],
) -> ControlExecutionResponseV2:
    try:
        return control.execute(bundle, executor=principal)
    except PlanReplayError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="control plan was not issued here, expired, or was already consumed",
        ) from exc
    except ControlPlaneError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="control execution failed closed; inspect durable receipts",
        ) from exc


@app.post(
    "/api/v1/evaluations",
    response_model=EvaluationResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["evaluations"],
)
def create_evaluation(
    request: EvaluationRequest,
    principal: Annotated[Principal, Depends(require_scopes("evaluate"))],
    ledger: Annotated[AuditLedger, Depends(get_ledger)],
) -> EvaluationResponse:
    request_id = uuid4()
    outcome = evaluate(request)
    audit_payload = {
        "request": request.model_dump(mode="json"),
        "policy": {
            "disposition": Disposition.WITHHOLD_PENDING_EVIDENCE_AND_APPROVALS.value,
            "release_authorized": False,
            "simulation_only": True,
            "evidence_status": outcome.evidence_status.value,
            "approval_status": ApprovalStatus.NOT_GRANTED.value,
            "required_approvals": list(outcome.required_approvals),
            "unverified_claims": list(outcome.unverified_claims),
        },
        "auth": {"token_fingerprint": principal.token_fingerprint},
    }
    try:
        receipt = ledger.append(
            actor_subject=principal.subject,
            action="evaluation.withheld",
            request_id=request_id,
            payload=audit_payload,
        )
    except LedgerUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="evaluation withheld because mandatory audit recording failed",
        ) from exc

    return EvaluationResponse(
        request_id=request_id,
        trace_id=request.trace_id,
        disposition=Disposition.WITHHOLD_PENDING_EVIDENCE_AND_APPROVALS,
        evidence_status=outcome.evidence_status,
        required_approvals=list(outcome.required_approvals),
        unverified_claims=list(outcome.unverified_claims),
        decision_reason=outcome.decision_reason,
        audit_event_id=receipt.event_id,
        audit_sequence_id=receipt.sequence_id,
        audit_event_hash=receipt.event_hash,
    )


@app.get(
    "/api/v1/audit/verify",
    response_model=LedgerVerificationResponse,
    tags=["audit"],
)
def verify_audit_ledger(
    _principal: Annotated[Principal, Depends(require_scopes("audit:read"))],
    ledger: Annotated[AuditLedger, Depends(get_ledger)],
) -> LedgerVerificationResponse:
    try:
        verification = ledger.verify_chain()
    except LedgerUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="audit ledger verification failed",
        ) from exc
    return LedgerVerificationResponse(
        valid=verification.valid,
        event_count=verification.event_count,
        first_invalid_sequence=verification.first_invalid_sequence,
    )
