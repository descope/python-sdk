import pytest

from descope import AssociatedTenant, AuthException
from descope.management.common import MgmtV1
from tests.common import DEFAULT_BASE_URL, default_headers
from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.testutils import PUBLIC_KEY_DICT


class TestAccessKey:
    async def test_create(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.access_key.create("key-name"))

        # Test success flow
        with client.mock_mgmt_post(make_response({"key": {"id": "ak1"}, "cleartext": "abc"})) as mock_post:
            resp = await client.invoke(
                client.mgmt.access_key.create(
                    name="key-name",
                    expire_time=123456789,
                    key_tenants=[
                        AssociatedTenant("tenant1"),
                        AssociatedTenant("tenant2", ["role1", "role2"]),
                    ],
                    user_id="userid",
                    custom_claims={"k1": "v1"},
                    description="this is my access key",
                    permitted_ips=["10.0.0.1", "192.168.1.0/24"],
                    custom_attributes={"attr1": "value1"},
                )
            )
            access_key = resp["key"]
            assert access_key["id"] == "ak1"
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.access_key_create_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "name": "key-name",
                    "expireTime": 123456789,
                    "roleNames": [],
                    "keyTenants": [
                        {"tenantId": "tenant1", "roleNames": []},
                        {"tenantId": "tenant2", "roleNames": ["role1", "role2"]},
                    ],
                    "userId": "userid",
                    "customClaims": {"k1": "v1"},
                    "description": "this is my access key",
                    "permittedIps": ["10.0.0.1", "192.168.1.0/24"],
                    "customAttributes": {"attr1": "value1"},
                },
                follow_redirects=False,
            )

    async def test_load(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_get(make_response(status=500)) as mock_get:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.access_key.load("key-id"))

        # Test success flow
        with client.mock_mgmt_get(make_response({"key": {"id": "ak1"}})) as mock_get:
            resp = await client.invoke(client.mgmt.access_key.load("key-id"))
            access_key = resp["key"]
            assert access_key["id"] == "ak1"
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.access_key_load_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params={"id": "key-id"},
                follow_redirects=True,
            )

    async def test_search_all_users(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.access_key.search_all_access_keys(["t1, t2"]))

        # Test success flow
        with client.mock_mgmt_post(make_response({"keys": [{"id": "ak1"}, {"id": "ak2"}]})) as mock_post:
            resp = await client.invoke(
                client.mgmt.access_key.search_all_access_keys(
                    ["t1, t2"], "bound-user-id", "creator-user", {"attr1": "value1"}
                )
            )
            keys = resp["keys"]
            assert len(keys) == 2
            assert keys[0]["id"] == "ak1"
            assert keys[1]["id"] == "ak2"
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.access_keys_search_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "tenantIds": ["t1, t2"],
                    "boundUserId": "bound-user-id",
                    "creatingUser": "creator-user",
                    "customAttributes": {"attr1": "value1"},
                },
                follow_redirects=False,
            )

    async def test_update(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.access_key.update("key-id", "new-name"))

        # Test success flow
        with client.mock_mgmt_post(make_response({})) as mock_post:
            result = await client.invoke(
                client.mgmt.access_key.update(
                    "key-id",
                    name="new-name",
                    description="desc",
                    custom_claims={"k1": "v1"},
                    permitted_ips=["192.168.1.1"],
                    custom_attributes={"attr1": "value1"},
                )
            )
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.access_key_update_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "id": "key-id",
                    "name": "new-name",
                    "description": "desc",
                    "customClaims": {"k1": "v1"},
                    "permittedIps": ["192.168.1.1"],
                    "customAttributes": {"attr1": "value1"},
                },
                follow_redirects=False,
            )

    async def test_deactivate(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.access_key.deactivate("key-id"))

        # Test success flow
        with client.mock_mgmt_post(make_response({})) as mock_post:
            result = await client.invoke(client.mgmt.access_key.deactivate("ak1"))
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.access_key_deactivate_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "id": "ak1",
                },
                follow_redirects=False,
            )

    async def test_activate(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.access_key.activate("key-id"))

        # Test success flow
        with client.mock_mgmt_post(make_response({})) as mock_post:
            result = await client.invoke(client.mgmt.access_key.activate("ak1"))
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.access_key_activate_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "id": "ak1",
                },
                follow_redirects=False,
            )

    async def test_delete(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.access_key.delete("key-id"))

        # Test success flow
        with client.mock_mgmt_post(make_response({})) as mock_post:
            result = await client.invoke(client.mgmt.access_key.delete("ak1"))
            assert result is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.access_key_delete_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "id": "ak1",
                },
                follow_redirects=False,
            )
