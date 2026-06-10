from unittest import mock

import pytest

from descope import AuthException, DescopeClient
from descope.management.common import MgmtV1
from tests.common import DEFAULT_BASE_URL
from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.testutils import PUBLIC_KEY_DICT


# Infrastructure tests — sync only, test HTTP client internals directly
class TestLicenseInfra:
    def test_header_injected_after_handshake(self):
        client = DescopeClient(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")
        # Simulate a completed handshake by setting the cached tier directly.
        client._mgmt_http_client.rate_limit_tier = "tier2"
        headers = client._mgmt_http_client._get_default_headers()
        assert headers.get("x-descope-license") == "tier2"

    def test_header_absent_when_tier_not_cached(self):
        client = DescopeClient(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")
        # Default state has no rate limit tier yet.
        client._mgmt_http_client.rate_limit_tier = None
        headers = client._mgmt_http_client._get_default_headers()
        assert "x-descope-license" not in headers


# Parametrized async-style tests for management API behavior
@pytest.mark.asyncio
class TestLicense:
    async def test_get_failure(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")
        with client.mock_mgmt_get(make_response(status=400)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.license.get())

    async def test_get_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")
        with client.mock_mgmt_get(make_response({"rateLimitTier": "tier4"})) as mock_get:
            resp = await client.invoke(client.mgmt.license.get())
            assert resp == {"rateLimitTier": "tier4"}

            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.license_get_path}",
                headers=mock.ANY,
                params=None,
                follow_redirects=True,
            )
