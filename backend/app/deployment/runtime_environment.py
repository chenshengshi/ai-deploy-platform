"""Rules for safely injecting project environment into application services."""


def application_environment(
    user_values: dict[str, str],
    *,
    service_name: str,
    service: dict,
    routed_services: set[str],
) -> dict[str, str]:
    """Return user variables only for application-facing services.

    Compose's project ``.env`` file performs interpolation but does not export
    arbitrary values into containers.  Application services therefore need an
    explicit environment overlay.  Data/dependency containers are excluded to
    avoid leaking unrelated application secrets.
    """
    if service_name not in routed_services and not service.get("build"):
        return {}
    return {str(key): str(value) for key, value in user_values.items() if str(key).strip()}
