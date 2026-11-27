from types import SimpleNamespace

from app.models import DeployStatus
from app.deployment.pipeline_view import render_pipeline_steps
from app.runtime_scaling import _next_service_instance_name, _service_instance_sequence
from app.runtime_topology import _route_groups_for_services, _runtime_entry_is_data, _service_role


def test_pipeline_renderer_keeps_explicit_stage_statuses():
    log = "[阶段开始] analyze\n[阶段完成] analyze\n[阶段开始] prepare\n"
    steps = render_pipeline_steps(log, DeployStatus.running)
    assert [step["status"] for step in steps[:3]] == ["success", "running", "waiting"]


def test_runtime_instance_naming_is_release_scoped():
    name = _next_service_instance_name("demo", "api", set(), release="20261127", namespace="yunzhou")
    assert _service_instance_sequence(name, "demo", "api", "20261127", "yunzhou") == 2


def test_runtime_topology_separates_data_from_scalable_apps():
    project = SimpleNamespace(integration_analysis_json="{}", load_balance_strategy="round_robin")
    assert _runtime_entry_is_data({"service": "mysql"}) is True
    assert _service_role(project, "api") == ("backend", True)
    groups = _route_groups_for_services(project, {"web": [("127.0.0.1", 10001)]})
    assert groups[0]["paths"] == [{"path": "/", "strip_prefix": False}]
