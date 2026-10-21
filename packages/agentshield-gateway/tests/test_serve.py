from __future__ import annotations

from agentshield_gateway.serve import app, build_pipeline


def test_production_entrypoint_builds_a_fail_closed_pipeline() -> None:
    pipeline = build_pipeline()
    assert pipeline.tool_registry.get("anything") is None


def test_asgi_factory_returns_a_healthz_app() -> None:
    asgi = app()
    routes = {getattr(route, "path", "") for route in asgi.routes}
    assert "/healthz" in routes
