"""
Fixtures for the e2e test suite.

Requires a real Descope backend reachable at DESCOPE_BASE_URI (defaults to
https://api.descope.com). When the required env vars are absent the e2e tests
are skipped (not errored), so a local `pytest tests/` still runs the unit suite
and fork PRs without repository secrets collect cleanly.

Required env vars:
  DESCOPE_PROJECT_ID       — the project to run tests against
  DESCOPE_MANAGEMENT_KEY   — a management key for that project

Optional env vars:
  DESCOPE_BASE_URI         — override the API base URL (e.g. https://localhost:8000
                             when running against a local cluster); auto toggling skip_verify
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

import pytest

if not os.environ.get("GITHUB_ACTIONS"):
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass

from descope import DescopeClient  # noqa: E402
from descope.descope_client_async import DescopeClientAsync  # noqa: E402
from tests._unified import UnifiedClientBase  # noqa: E402


@pytest.fixture(params=["sync", "async"])
async def descope_client(request):  # type: ignore[misc]
    """
    Parametrized fixture — yields a UnifiedClientBase wrapping DescopeClient (sync)
    or DescopeClientAsync (async) against a real backend. Each consuming test runs twice.
    """
    project_id = os.environ.get("DESCOPE_PROJECT_ID")
    management_key = os.environ.get("DESCOPE_MANAGEMENT_KEY")
    if not project_id or not management_key:
        pytest.skip("Missing required e2e environment variables: DESCOPE_PROJECT_ID and DESCOPE_MANAGEMENT_KEY")

    base_uri = os.environ.get("DESCOPE_BASE_URI", "")
    skip_verify = urlparse(base_uri).hostname in {"localhost", "127.0.0.1", "::1"}
    if base_uri and not skip_verify and urlparse(base_uri).scheme != "https":
        pytest.fail(f"DESCOPE_BASE_URI must use https for a remote target, got: {base_uri}")

    if request.param == "sync":
        yield UnifiedClientBase(
            "sync",
            DescopeClient(project_id=project_id, management_key=management_key, skip_verify=skip_verify),
        )
    else:
        raw = DescopeClientAsync(project_id=project_id, management_key=management_key, skip_verify=skip_verify)
        yield UnifiedClientBase("async", raw)
        await raw.aclose()
