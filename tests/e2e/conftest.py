"""
Fixtures for the e2e test suite.

Requires a real Descope backend reachable at DESCOPE_BASE_URI (defaults to
https://api.descope.com).  The suite fails at collection time when the required
env vars are absent.

Required env vars:
  DESCOPE_PROJECT_ID       — the project to run tests against
  DESCOPE_MANAGEMENT_KEY   — a management key for that project

Optional env vars:
  DESCOPE_BASE_URI         — override the API base URL (e.g. https://localhost:8000
                             when running against a local cluster); auto toggling skip_verify
"""

from __future__ import annotations

import os
import sys

import pytest

try:
    from dotenv import load_dotenv

    load_dotenv()  # populate env from .env before the env-var check below
except ImportError:  # python-dotenv is a dev-only extra; tolerate its absence
    pass

from descope import DescopeClient  # noqa: E402
from descope.descope_client_async import DescopeClientAsync  # noqa: E402
from tests._unified import UnifiedClientBase  # noqa: E402

if not os.environ.get("DESCOPE_PROJECT_ID") or not os.environ.get("DESCOPE_MANAGEMENT_KEY"):
    print(
        "ERROR: DESCOPE_PROJECT_ID and DESCOPE_MANAGEMENT_KEY must be set to run e2e tests",
        file=sys.stderr,
    )
    pytest.exit("Missing required e2e environment variables", returncode=1)


@pytest.fixture(params=["sync", "async"])
async def descope_client(request):  # type: ignore[misc]
    """
    Parametrized fixture — yields a UnifiedClientBase wrapping DescopeClient (sync)
    or DescopeClientAsync (async) against a real backend. Each consuming test runs twice.
    """
    project_id = os.environ["DESCOPE_PROJECT_ID"]
    management_key = os.environ["DESCOPE_MANAGEMENT_KEY"]

    skip_verify = "localhost" in os.environ.get("DESCOPE_BASE_URI", "")
    if request.param == "sync":
        yield UnifiedClientBase(
            "sync",
            DescopeClient(project_id=project_id, management_key=management_key, skip_verify=skip_verify),
        )
    else:
        raw = DescopeClientAsync(project_id=project_id, management_key=management_key, skip_verify=skip_verify)
        yield UnifiedClientBase("async", raw)
        await raw.aclose()
