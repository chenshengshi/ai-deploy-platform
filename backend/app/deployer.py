"""Compatibility facade for deployment domain services.

New code should import the owning module from ``app.deployment`` directly.
The facade keeps the worker, API and existing extensions stable while the
platform is migrated module by module.
"""

from .deployment.access_verification import verify_access
from .deployment.ai_plan import _complete_source_compose
from .deployment.analysis_preflight import preflight_ai_deployment_plan
from .deployment.architecture import analyze_repository_topology
from .deployment.build_preparation import prepare_build
from .deployment.compose_plan import (
    _compose_service_container_port,
    _dockerfile_exposed_port,
    compose_service_mapping as _compose_service_mapping,
    prepare_compose_image_override,
)
from .deployment.compose_split import split_compose_runtime
from .deployment.data_services import remove_project_managed_data_service, stop_project_data_services
from .deployment.gateway import configure_platform_gateway, platform_gateway_node, reconcile_runtime_frontend_routes
from .deployment.image_cleanup import cleanup_incomplete_release_images, cleanup_registry_versions
from .deployment.image_restore import restore_release_images
from .deployment.integration_reconcile import reconcile_managed_integrations
from .deployment.integrations import effective_project_environment, environment_values, external_integration_preflight
from .deployment.naming import compose_project_name, deployment_compose_project_name, project_directory
from .deployment.orchestrator import choose_node_port, execute
from .deployment.ports import choose_port
from .deployment.release_cleanup import delete_deployment_resources
from .deployment.release_runtime import start_deployment, stop_deployment
from .deployment.source_paths import git_source_location
from .deployment.source_repair import apply_safe_build_repairs
from .deployment.source_staging import stage_source
from .source_inspection import (
    _FRONTEND_API_ENV_KEYS,
    _executable_jar_score,
    _public_path_from_value,
    detect_frontend_api_routes,
)
