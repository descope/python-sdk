import pytest

from descope import AuthException
from descope.management.common import MgmtV1
from tests.common import DEFAULT_BASE_URL, default_headers
from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.testutils import PUBLIC_KEY_DICT


@pytest.mark.asyncio
class TestPassword:
    async def test_get_settings(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed get_settings
        with client.mock_mgmt_get(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.password.get_settings())

        # Test success get_settings
        settings_resp = {
            "enabled": True,
            "minLength": 8,
            "lowercase": True,
            "uppercase": True,
            "number": True,
            "nonAlphanumeric": False,
            "expiration": False,
            "expirationWeeks": 0,
            "reuse": False,
            "reuseAmount": 0,
            "lock": True,
            "lockAttempts": 5,
        }
        with client.mock_mgmt_get(make_response(settings_resp)) as mock_get:
            resp = await client.invoke(client.mgmt.password.get_settings("tenant-id"))
            assert resp == settings_resp
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.password_settings_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params={"tenantId": "tenant-id"},
                follow_redirects=True,
            )

    async def test_configure_settings(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed configure_settings
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.password.configure_settings("", {}))

        # Test success configure_settings
        settings = {
            "enabled": True,
            "minLength": 10,
            "lowercase": True,
            "uppercase": True,
            "number": True,
            "nonAlphanumeric": True,
            "expiration": True,
            "expirationWeeks": 12,
            "reuse": True,
            "reuseAmount": 3,
            "lock": True,
            "lockAttempts": 5,
        }
        with client.mock_mgmt_post(make_response({})) as mock_post:
            await client.invoke(client.mgmt.password.configure_settings("tenant-id", settings))
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.password_settings_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "tenantId": "tenant-id",
                    **settings,
                },
                follow_redirects=False,
            )
