import pytest

from descope import (
    MgmtKeyProjectRole,
    MgmtKeyReBac,
    MgmtKeyStatus,
    MgmtKeyTagRole,
)
from descope.management.common import MgmtV1
from tests.common import DEFAULT_BASE_URL, default_headers
from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.testutils import PUBLIC_KEY_DICT


class TestManagementKey:
    async def test_create_empty_name(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")
        with pytest.raises(ValueError) as exc_info:
            await client.invoke(
                client.mgmt.management_key.create(
                    name="",
                    rebac=MgmtKeyReBac(company_roles=["role1"]),
                )
            )
        assert str(exc_info.value) == "name cannot be empty"

    async def test_create_none_rebac(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")
        with pytest.raises(ValueError) as exc_info:
            await client.invoke(
                client.mgmt.management_key.create(
                    name="test-key",
                    rebac=None,
                )
            )
        assert str(exc_info.value) == "rebac cannot be empty"

    async def test_create(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test success flow
        with client.mock_mgmt_put(
            make_response(
                {
                    "cleartext": "cleartext-secret",
                    "key": {
                        "id": "mk1",
                        "name": "test-key",
                        "description": "test key",
                        "permittedIps": ["10.0.0.1"],
                        "status": "active",
                        "createdTime": 1764849768,
                        "expireTime": 3600,
                        "reBac": {
                            "companyRoles": ["role1"],
                            "projectRoles": [],
                            "tagRoles": [],
                        },
                        "version": 1,
                        "authzVersion": 1,
                    },
                }
            )
        ) as mock_put:
            resp = await client.invoke(
                client.mgmt.management_key.create(
                    name="test-key",
                    rebac=MgmtKeyReBac(company_roles=["role1"]),
                    description="test key",
                    expires_in=3600,
                    permitted_ips=["10.0.0.1"],
                )
            )
            assert resp["cleartext"] == "cleartext-secret"
            key = resp["key"]
            assert key["name"] == "test-key"
            assert key["description"] == "test key"
            assert len(key["permittedIps"]) == 1
            assert key["permittedIps"][0] == "10.0.0.1"
            assert key["expireTime"] == 3600
            assert key["reBac"] is not None
            assert len(key["reBac"]["companyRoles"]) == 1
            assert key["reBac"]["companyRoles"][0] == "role1"
            assert_http_called(
                mock_put,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.mgmt_key_create_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "name": "test-key",
                    "description": "test key",
                    "expiresIn": 3600,
                    "permittedIps": ["10.0.0.1"],
                    "reBac": {
                        "companyRoles": ["role1"],
                    },
                },
                follow_redirects=False,
            )

    async def test_create_with_project_and_tag_roles(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test success flow with project_roles and tag_roles
        with client.mock_mgmt_put(
            make_response(
                {
                    "cleartext": "cleartext-secret",
                    "key": {
                        "id": "mk1",
                        "name": "test-key",
                        "description": "test key",
                        "permittedIps": [],
                        "status": "active",
                        "createdTime": 1764849768,
                        "expireTime": 0,
                        "reBac": {
                            "companyRoles": [],
                            "projectRoles": [{"projectIds": ["proj1"], "roles": ["admin"]}],
                            "tagRoles": [{"tags": ["tag1"], "roles": ["viewer"]}],
                        },
                        "version": 1,
                        "authzVersion": 1,
                    },
                }
            )
        ) as mock_put:
            resp = await client.invoke(
                client.mgmt.management_key.create(
                    name="test-key",
                    rebac=MgmtKeyReBac(
                        project_roles=[MgmtKeyProjectRole(project_ids=["proj1"], roles=["admin"])],
                        tag_roles=[MgmtKeyTagRole(tags=["tag1"], roles=["viewer"])],
                    ),
                )
            )
            assert resp["cleartext"] == "cleartext-secret"
            key = resp["key"]
            assert key["name"] == "test-key"
            assert len(key["reBac"]["projectRoles"]) == 1
            assert key["reBac"]["projectRoles"][0]["projectIds"] == ["proj1"]
            assert len(key["reBac"]["tagRoles"]) == 1
            assert key["reBac"]["tagRoles"][0]["tags"] == ["tag1"]
            assert_http_called(
                mock_put,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.mgmt_key_create_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "name": "test-key",
                    "description": None,
                    "expiresIn": 0,
                    "permittedIps": [],
                    "reBac": {
                        "projectRoles": [{"projectIds": ["proj1"], "roles": ["admin"]}],
                        "tagRoles": [{"tags": ["tag1"], "roles": ["viewer"]}],
                    },
                },
                follow_redirects=False,
            )

    async def test_update_empty_id(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")
        with pytest.raises(ValueError) as exc_info:
            await client.invoke(
                client.mgmt.management_key.update(
                    id="",
                    name="updated-key",
                    description="updated key",
                    permitted_ips=["1.2.3.4"],
                    status=MgmtKeyStatus.INACTIVE,
                )
            )
        assert str(exc_info.value) == "id cannot be empty"

    async def test_update_empty_name(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")
        with pytest.raises(ValueError) as exc_info:
            await client.invoke(
                client.mgmt.management_key.update(
                    id="mk1",
                    name="",
                    description="updated key",
                    permitted_ips=["1.2.3.4"],
                    status=MgmtKeyStatus.INACTIVE,
                )
            )
        assert str(exc_info.value) == "name cannot be empty"

    async def test_update_none_status(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")
        with pytest.raises(ValueError) as exc_info:
            await client.invoke(
                client.mgmt.management_key.update(
                    id="mk1",
                    name="updated-key",
                    description="updated key",
                    permitted_ips=["1.2.3.4"],
                    status=None,
                )
            )
        assert str(exc_info.value) == "status cannot be empty"

    async def test_update(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test success flow
        with client.mock_mgmt_patch(
            make_response(
                {
                    "key": {
                        "id": "mk1",
                        "name": "updated-key",
                        "description": "updated key",
                        "permittedIps": ["1.2.3.4"],
                        "status": "inactive",
                        "createdTime": 1764673442,
                        "expireTime": 0,
                        "reBac": {
                            "companyRoles": [],
                            "projectRoles": [],
                            "tagRoles": [],
                        },
                        "version": 22,
                        "authzVersion": 1,
                    },
                }
            )
        ) as mock_patch:
            resp = await client.invoke(
                client.mgmt.management_key.update(
                    id="mk1",
                    name="updated-key",
                    description="updated key",
                    permitted_ips=["1.2.3.4"],
                    status=MgmtKeyStatus.INACTIVE,
                )
            )
            key = resp["key"]
            assert key["id"] == "mk1"
            assert key["name"] == "updated-key"
            assert key["description"] == "updated key"
            assert len(key["permittedIps"]) == 1
            assert key["permittedIps"][0] == "1.2.3.4"
            assert key["status"] == "inactive"
            assert_http_called(
                mock_patch,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.mgmt_key_update_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "id": "mk1",
                    "name": "updated-key",
                    "description": "updated key",
                    "permittedIps": ["1.2.3.4"],
                    "status": "inactive",
                },
                follow_redirects=False,
            )

    async def test_load_empty_id(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")
        with pytest.raises(ValueError) as exc_info:
            await client.invoke(client.mgmt.management_key.load(""))
        assert str(exc_info.value) == "id cannot be empty"

    async def test_load(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test success flow
        with client.mock_mgmt_get(
            make_response(
                {
                    "key": {
                        "id": "mk1",
                        "name": "test-key",
                        "description": "a key description",
                        "status": "active",
                        "createdTime": 1764677065,
                        "expireTime": 0,
                        "permittedIps": [],
                        "reBac": {
                            "companyRoles": [],
                            "projectRoles": [],
                            "tagRoles": [],
                        },
                        "version": 1,
                        "authzVersion": 1,
                    },
                }
            )
        ) as mock_get:
            resp = await client.invoke(client.mgmt.management_key.load("mk1"))
            key = resp["key"]
            assert key is not None
            assert key["name"] == "test-key"
            assert key["description"] == "a key description"
            assert key["status"] == "active"
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.mgmt_key_load_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params={"id": "mk1"},
                follow_redirects=True,
            )

    async def test_delete_empty_ids(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")
        with pytest.raises(ValueError) as exc_info:
            await client.invoke(client.mgmt.management_key.delete([]))
        assert str(exc_info.value) == "ids list cannot be empty"

    async def test_delete(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test success flow
        with client.mock_mgmt_post(make_response({"total": 2})) as mock_post:
            resp = await client.invoke(client.mgmt.management_key.delete(["mk1", "mk2"]))
            assert resp["total"] == 2
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.mgmt_key_delete_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={"ids": ["mk1", "mk2"]},
                follow_redirects=False,
            )

    async def test_search(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test success flow
        with client.mock_mgmt_get(
            make_response(
                {
                    "keys": [
                        {
                            "id": "mk1",
                            "name": "key1",
                            "description": "",
                            "status": "active",
                            "createdTime": 1764677065,
                            "expireTime": 0,
                            "permittedIps": [],
                            "reBac": {
                                "companyRoles": [],
                                "projectRoles": [],
                                "tagRoles": [],
                            },
                            "version": 1,
                            "authzVersion": 1,
                        },
                        {
                            "id": "mk2",
                            "name": "key2",
                            "description": "",
                            "status": "inactive",
                            "createdTime": 1764773205,
                            "expireTime": 1234,
                            "permittedIps": [],
                            "reBac": {
                                "companyRoles": [],
                                "projectRoles": [],
                                "tagRoles": [],
                            },
                            "version": 1,
                            "authzVersion": 1,
                        },
                    ],
                }
            )
        ) as mock_get:
            resp = await client.invoke(client.mgmt.management_key.search())
            keys = resp["keys"]
            assert keys is not None
            assert len(keys) == 2
            assert keys[0]["id"] == "mk1"
            assert keys[0]["name"] == "key1"
            assert keys[0]["status"] == "active"
            assert keys[1]["id"] == "mk2"
            assert keys[1]["name"] == "key2"
            assert keys[1]["status"] == "inactive"
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.mgmt_key_search_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                follow_redirects=True,
            )
