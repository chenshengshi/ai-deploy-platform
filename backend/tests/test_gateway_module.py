from app.deployment.gateway import reconcile_runtime_frontend_routes


def test_gateway_reconciliation_is_noop_without_route_evidence():
    assert reconcile_runtime_frontend_routes(None) == (None, None)
    routes = [{"name": "api", "paths": [{"path": "/api/"}], "targets": []}]
    assert reconcile_runtime_frontend_routes(routes) == (routes, None)
