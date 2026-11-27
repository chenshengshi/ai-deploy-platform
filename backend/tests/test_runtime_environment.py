from app.deployment.runtime_environment import application_environment


def test_user_environment_is_injected_into_application_service():
    values = {"ADMIN_OPEN": "1", "ALLOW_PLAIN_HTTP": "1"}
    result = application_environment(
        values, service_name="portal", service={"build": "."}, routed_services={"portal"},
    )
    assert result == values


def test_user_environment_is_not_leaked_to_dependency_service():
    result = application_environment(
        {"APP_SECRET": "secret"}, service_name="mysql", service={"image": "mysql:8.4"}, routed_services={"web"},
    )
    assert result == {}
