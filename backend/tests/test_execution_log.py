from types import SimpleNamespace
from unittest.mock import patch

from app.deployment.execution_log import _write_deployment_log


class FakeSession:
    def __init__(self):
        self.deployment = SimpleNamespace(log_text="before\n")
        self.executed = []
        self.committed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, statement):
        self.executed.append(statement)

    def get(self, _model, _deployment_id):
        return self.deployment

    def commit(self):
        self.committed = True


def test_compact_database_log_is_updated_after_file_append():
    session = FakeSession()
    with patch("app.deployment.execution_log.append_deployment_log"), patch(
        "app.deployment.execution_log.SessionLocal", return_value=session
    ):
        _write_deployment_log("deployment-id", "after\n")

    assert session.executed
    assert session.deployment.log_text == "before\nafter\n"
    assert session.committed
