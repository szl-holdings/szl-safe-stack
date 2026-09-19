from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .config import ConfigurationError, GatewayConfig
from .evaluator import BUILTIN_CASES, EvaluationProviderError, EvidenceEvaluator
from .ledger import LedgerError, ReceiptLedger
from .providers import OllamaProvider, OpenRouterProvider
from .schemas import REQUEST_VERSION, EvidenceRequest
from .server import GatewayService, serve


def _components(*, for_serve: bool) -> tuple[GatewayConfig, ReceiptLedger, EvidenceEvaluator]:
    config = GatewayConfig.from_env(for_serve=for_serve)
    ledger = ReceiptLedger(config.database_path)
    providers = {}
    if config.ollama_enabled:
        providers["ollama"] = OllamaProvider(
            origin=config.ollama_origin,
            model=config.ollama_model,
            timeout_seconds=config.provider_timeout_seconds,
            max_response_bytes=config.max_provider_response_bytes,
            generation_token_cap=config.generation_token_cap,
        )
    if config.openrouter_enabled:
        assert config.openrouter_model is not None and config.openrouter_api_key is not None
        providers["openrouter"] = OpenRouterProvider(
            origin=config.openrouter_origin,
            model=config.openrouter_model,
            api_key=config.openrouter_api_key,
            timeout_seconds=config.provider_timeout_seconds,
            max_response_bytes=config.max_provider_response_bytes,
            generation_token_cap=config.generation_token_cap,
        )
    return config, ledger, EvidenceEvaluator(ledger, providers)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SZL local-first software evidence gateway")
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("serve", help="serve the authenticated HTTP API")
    subparsers.add_parser("verify-ledger", help="verify every receipt hash and link")
    subparsers.add_parser("self-check", help="check configuration and ledger without contacting providers")
    subparsers.add_parser("list-cases", help="list the built-in safe evaluation cases")
    evaluate = subparsers.add_parser("evaluate-case", help="evaluate one built-in safe case")
    evaluate.add_argument("case_id", choices=sorted(BUILTIN_CASES))
    evaluate.add_argument("--provider", choices=("none", "ollama", "openrouter"), default="none")
    args = parser.parse_args(argv)
    try:
        config, ledger, evaluator = _components(for_serve=args.command == "serve")
        if args.command == "serve":
            serve(GatewayService(config, ledger, evaluator))
            return 0
        if args.command == "verify-ledger":
            print(json.dumps(ledger.verify(), indent=2, sort_keys=True))
            return 0
        if args.command == "self-check":
            print(
                json.dumps(
                    {
                        "schema_version": "szl.frontier.self_check.v1",
                        "status": "PASS",
                        "ledger": ledger.verify(),
                        "capabilities": config.public_capabilities(),
                        "providers_contacted": False,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        if args.command == "list-cases":
            print("\n".join(sorted(BUILTIN_CASES)))
            return 0
        request = EvidenceRequest.parse(
            {
                "schema_version": REQUEST_VERSION,
                "request_id": str(__import__("uuid").uuid4()),
                "case_id": args.case_id,
                "provider": args.provider,
                "domain": "software_infrastructure",
            }
        )
        print(json.dumps(evaluator.evaluate(request), indent=2, sort_keys=True))
        return 0
    except EvaluationProviderError as exc:
        print(
            json.dumps(
                {
                    "schema_version": "szl.frontier.provider_failure.v1",
                    "status": "FAILED_CLOSED",
                    "error": str(exc),
                    "receipt": exc.receipt,
                },
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 3
    except (ConfigurationError, LedgerError) as exc:
        print(f"fatal: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
