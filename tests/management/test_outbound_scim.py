import pytest

from descope import AuthException
from descope.management.common import MgmtV1
from descope.management.outbound_scim import OutboundSCIM
from tests.common import DEFAULT_BASE_URL, default_headers
from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.testutils import PUBLIC_KEY_DICT

CONFIG_RESPONSE = {
    "configuration": {
        "id": "scim1",
        "name": "Test SCIM",
        "appId": "app1",
        "configuration": {"baseUrl": "https://scim.example.com"},
        "enabled": True,
        "lastExportTime": 1719571200,
        "lastProcessingTime": 1719571300,
        "failures": 0,
        "version": 3,
    }
}

MGMT_HEADERS = {
    **default_headers,
    "Authorization": f"Bearer {PROJECT_ID}:key",
    "x-descope-project-id": PROJECT_ID,
}


class TestOutboundSCIM:
    async def test_create_configuration_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(CONFIG_RESPONSE)) as mock_post:
            response = await client.invoke(
                client.mgmt.outbound_scim.create_configuration(
                    "Test SCIM",
                    "app1",
                    {"baseUrl": "https://scim.example.com"},
                )
            )
            assert response == CONFIG_RESPONSE
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.outbound_scim_create_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={
                    "name": "Test SCIM",
                    "appId": "app1",
                    "configuration": {"baseUrl": "https://scim.example.com"},
                },
                follow_redirects=False,
            )

    async def test_create_configuration_minimal_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(CONFIG_RESPONSE)) as mock_post:
            response = await client.invoke(client.mgmt.outbound_scim.create_configuration("Test SCIM", "app1"))
            assert response == CONFIG_RESPONSE
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.outbound_scim_create_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={"name": "Test SCIM", "appId": "app1"},
                follow_redirects=False,
            )

    async def test_create_configuration_failure(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.outbound_scim.create_configuration("Test SCIM", "app1"))

    async def test_update_configuration_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(CONFIG_RESPONSE)) as mock_post:
            response = await client.invoke(
                client.mgmt.outbound_scim.update_configuration(
                    "scim1",
                    3,
                    {"baseUrl": "https://scim.example.com"},
                    "Updated Name",
                )
            )
            assert response == CONFIG_RESPONSE
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.outbound_scim_update_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={
                    "id": "scim1",
                    "version": 3,
                    "name": "Updated Name",
                    "configuration": {"baseUrl": "https://scim.example.com"},
                },
                follow_redirects=False,
            )

    async def test_update_configuration_without_name_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(CONFIG_RESPONSE)) as mock_post:
            await client.invoke(
                client.mgmt.outbound_scim.update_configuration("scim1", 3, {"baseUrl": "https://scim.example.com"})
            )
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.outbound_scim_update_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={
                    "id": "scim1",
                    "version": 3,
                    "configuration": {"baseUrl": "https://scim.example.com"},
                },
                follow_redirects=False,
            )

    async def test_update_configuration_failure(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.outbound_scim.update_configuration("scim1", 3, {}))

    async def test_delete_configuration_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response({})) as mock_post:
            await client.invoke(client.mgmt.outbound_scim.delete_configuration("scim1"))
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.outbound_scim_delete_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={"id": "scim1"},
                follow_redirects=False,
            )

    async def test_delete_configuration_failure(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.outbound_scim.delete_configuration("scim1"))

    async def test_load_configuration_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_get(make_response(CONFIG_RESPONSE)) as mock_get:
            response = await client.invoke(client.mgmt.outbound_scim.load_configuration("scim1"))
            assert response == CONFIG_RESPONSE
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.outbound_scim_load_path}/scim1",
                headers=MGMT_HEADERS,
                params=None,
                follow_redirects=True,
            )

    async def test_load_configuration_failure(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_get(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.outbound_scim.load_configuration("scim1"))

    async def test_set_enabled_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(CONFIG_RESPONSE)) as mock_post:
            response = await client.invoke(client.mgmt.outbound_scim.set_enabled("scim1", True))
            assert response == CONFIG_RESPONSE
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.outbound_scim_set_enabled_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={"id": "scim1", "enabled": True},
                follow_redirects=False,
            )

    async def test_set_enabled_false_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(CONFIG_RESPONSE)) as mock_post:
            await client.invoke(client.mgmt.outbound_scim.set_enabled("scim1", False))
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.outbound_scim_set_enabled_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={"id": "scim1", "enabled": False},
                follow_redirects=False,
            )

    async def test_set_enabled_failure(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.outbound_scim.set_enabled("scim1", True))

    def test_compose_create_body(self):
        body = OutboundSCIM._compose_create_body("Test SCIM", "app1", {"baseUrl": "https://scim.example.com"})
        assert body == {
            "name": "Test SCIM",
            "appId": "app1",
            "configuration": {"baseUrl": "https://scim.example.com"},
        }

    def test_compose_create_body_without_configuration(self):
        body = OutboundSCIM._compose_create_body("Test SCIM", "app1")
        assert body == {"name": "Test SCIM", "appId": "app1"}

    def test_compose_update_body(self):
        body = OutboundSCIM._compose_update_body(
            "scim1",
            5,
            {"baseUrl": "https://scim.example.com"},
            "New Name",
        )
        assert body == {
            "id": "scim1",
            "version": 5,
            "name": "New Name",
            "configuration": {"baseUrl": "https://scim.example.com"},
        }

    def test_compose_update_body_without_optionals(self):
        body = OutboundSCIM._compose_update_body("scim1", 5)
        assert body == {"id": "scim1", "version": 5}
