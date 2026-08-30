"""
API Routes Package
"""

from ulpf.apps.api.routes.auth_routes import router as auth_router
from ulpf.apps.api.routes.benchmark import router as benchmark_router
from ulpf.apps.api.routes.datalake import router as datalake_router
from ulpf.apps.api.routes.errors import router as errors_router
from ulpf.apps.api.routes.events import router as events_router
from ulpf.apps.api.routes.onboarding import router as onboarding_router
from ulpf.apps.api.routes.parsers import router as parsers_router
from ulpf.apps.api.routes.pipeline import router as pipeline_router

__all__ = [
    "auth_router",
    "benchmark_router",
    "datalake_router",
    "errors_router",
    "events_router",
    "onboarding_router",
    "parsers_router",
    "pipeline_router",
]
