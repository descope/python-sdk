import pytest

from descope import AuthException
from descope.management.common import MgmtV1

from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.common import DEFAULT_BASE_URL, default_headers
from tests.testutils import PUBLIC_KEY_DICT


class TestRole:
    async def test_create(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.role.create("name"))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock:
            assert await client.invoke(client.mgmt.role.create("R1", "Something", ["P1"], "t1", True, False)) is None
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.role_create_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "name": "R1",
                    "description": "Something",
                    "permissionNames": ["P1"],
                    "tenantId": "t1",
                    "default": True,
                    "private": False,
                },
                follow_redirects=False,
            )

    async def test_create_batch(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)) as mock:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.role.create_batch([{"name": "R1"}]))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock:
            assert (
                await client.invoke(
                    client.mgmt.role.create_batch(
                        [
                            {
                                "name": "R1",
                                "description": "desc1",
                                "permissionNames": ["P1"],
                                "tenantId": "t1",
                                "default": True,
                                "private": False,
                            },
                            {"name": "R2"},
                        ]
                    )
                )
                is None
            )
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.role_create_batch_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "roles": [
                        {
                            "name": "R1",
                            "description": "desc1",
                            "permissionNames": ["P1"],
                            "tenantId": "t1",
                            "default": True,
                            "private": False,
                        },
                        {"name": "R2"},
                    ]
                },
                follow_redirects=False,
            )

    async def test_update_batch(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)) as mock:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.role.update_batch([{"name": "R1", "newName": "R1-new"}]))

        # Test success flow — by name
        with client.mock_mgmt_post(make_response()) as mock:
            assert (
                await client.invoke(
                    client.mgmt.role.update_batch(
                        [
                            {
                                "name": "R1",
                                "newName": "R1-new",
                                "description": "d1",
                                "permissionNames": ["P1", "P2"],
                                "tenantId": "t1",
                                "default": False,
                                "private": True,
                            },
                            {"name": "R2", "newName": "R2-new"},
                        ]
                    )
                )
                is None
            )
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.role_update_batch_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "roles": [
                        {
                            "name": "R1",
                            "newName": "R1-new",
                            "description": "d1",
                            "permissionNames": ["P1", "P2"],
                            "tenantId": "t1",
                            "default": False,
                            "private": True,
                        },
                        {"name": "R2", "newName": "R2-new"},
                    ]
                },
                follow_redirects=False,
            )

        # Test success flow — by id
        with client.mock_mgmt_post(make_response()) as mock:
            assert (
                await client.invoke(
                    client.mgmt.role.update_batch(
                        [
                            {"id": "ROL1", "newName": "R1-new", "description": "d1"},
                            {"id": "ROL2", "newName": "R2-new"},
                        ]
                    )
                )
                is None
            )
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.role_update_batch_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "roles": [
                        {"id": "ROL1", "newName": "R1-new", "description": "d1"},
                        {"id": "ROL2", "newName": "R2-new"},
                    ]
                },
                follow_redirects=False,
            )

    async def test_update(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.role.update("name", "new-name"))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock:
            assert (
                await client.invoke(
                    client.mgmt.role.update(
                        "name",
                        "new-name",
                        "new-description",
                        ["P1", "P2"],
                        "t1",
                        True,
                        False,
                    )
                )
                is None
            )
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.role_update_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "name": "name",
                    "newName": "new-name",
                    "description": "new-description",
                    "permissionNames": ["P1", "P2"],
                    "tenantId": "t1",
                    "default": True,
                    "private": False,
                },
                follow_redirects=False,
            )

    async def test_update_by_id(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)) as mock:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.role.update_by_id("ROL123", "new-name"))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock:
            assert (
                await client.invoke(
                    client.mgmt.role.update_by_id(
                        "ROL123",
                        "new-name",
                        "new-description",
                        ["P1", "P2"],
                        "t1",
                        True,
                        False,
                    )
                )
                is None
            )
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.role_update_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "id": "ROL123",
                    "newName": "new-name",
                    "description": "new-description",
                    "permissionNames": ["P1", "P2"],
                    "tenantId": "t1",
                    "default": True,
                    "private": False,
                },
                follow_redirects=False,
            )

    async def test_delete(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.role.delete("name"))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock:
            assert await client.invoke(client.mgmt.role.delete("name")) is None
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.role_delete_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={"name": "name", "tenantId": None},
                follow_redirects=False,
            )

    async def test_delete_by_id(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)) as mock:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.role.delete_by_id("ROL123"))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock:
            assert await client.invoke(client.mgmt.role.delete_by_id("ROL123", "t1")) is None
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.role_delete_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={"id": "ROL123", "tenantId": "t1"},
                follow_redirects=False,
            )

    async def test_delete_batch(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)) as mock:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.role.delete_batch([{"name": "R1"}]))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock:
            assert (
                await client.invoke(
                    client.mgmt.role.delete_batch(
                        [
                            {"name": "R1", "tenantId": "t1"},
                            {"name": "R2"},
                        ]
                    )
                )
                is None
            )
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.role_delete_batch_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "roles": [
                        {"name": "R1", "tenantId": "t1"},
                        {"name": "R2"},
                    ]
                },
                follow_redirects=False,
            )

    async def test_delete_batch_by_ids(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)) as mock:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.role.delete_batch_by_ids(["ROL1"]))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock:
            assert await client.invoke(client.mgmt.role.delete_batch_by_ids(["ROL1", "ROL2"], "t1")) is None
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.role_delete_batch_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={"roleIds": ["ROL1", "ROL2"], "tenantId": "t1"},
                follow_redirects=False,
            )

    async def test_load_all(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_get(make_response(status=500)) as mock:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.role.load_all())

        # Test success flow
        with client.mock_mgmt_get(
            make_response(
                {
                    "roles": [
                        {"name": "R1", "permissionNames": ["P1", "P2"]},
                        {"name": "R2"},
                    ]
                }
            )
        ) as mock:
            resp = await client.invoke(client.mgmt.role.load_all())
            roles = resp["roles"]
            assert len(roles) == 2
            assert roles[0]["name"] == "R1"
            assert roles[1]["name"] == "R2"
            permissions = roles[0]["permissionNames"]
            assert len(permissions) == 2
            assert permissions[0] == "P1"
            assert permissions[1] == "P2"
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.role_load_all_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                follow_redirects=True,
            )

    async def test_search(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.role.search(["t"], ["r"]))

        # Test success flow
        with client.mock_mgmt_post(
            make_response(
                {
                    "roles": [
                        {"name": "R1", "permissionNames": ["P1", "P2"]},
                        {"name": "R2"},
                    ]
                }
            )
        ) as mock:
            resp = await client.invoke(client.mgmt.role.search(["t"], ["r"], "x", ["p1", "p2"]))
            roles = resp["roles"]
            assert len(roles) == 2
            assert roles[0]["name"] == "R1"
            assert roles[1]["name"] == "R2"
            permissions = roles[0]["permissionNames"]
            assert len(permissions) == 2
            assert permissions[0] == "P1"
            assert permissions[1] == "P2"
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.role_search_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "tenantIds": ["t"],
                    "roleNames": ["r"],
                    "roleNameLike": "x",
                    "permissionNames": ["p1", "p2"],
                },
                follow_redirects=False,
            )

    async def test_search_by_role_ids(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(
            make_response({"roles": [{"id": "ROL123", "name": "R1"}]})
        ) as mock:
            resp = await client.invoke(client.mgmt.role.search(role_ids=["ROL123"]))
            roles = resp["roles"]
            assert len(roles) == 1
            assert roles[0]["id"] == "ROL123"
            assert roles[0]["name"] == "R1"
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.role_search_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={"roleIds": ["ROL123"]},
                follow_redirects=False,
            )

    async def test_create_with_private_true(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test private=True
        with client.mock_mgmt_post(make_response()) as mock:
            assert await client.invoke(client.mgmt.role.create("PrivateRole", "Private role", ["P1"], "t1", False, True)) is None
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.role_create_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "name": "PrivateRole",
                    "description": "Private role",
                    "permissionNames": ["P1"],
                    "tenantId": "t1",
                    "default": False,
                    "private": True,
                },
                follow_redirects=False,
            )

    async def test_update_with_private_true(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test private=True
        with client.mock_mgmt_post(make_response()) as mock:
            assert (
                await client.invoke(
                    client.mgmt.role.update(
                        "role",
                        "updated-role",
                        "Updated private role",
                        ["P1", "P2"],
                        "t1",
                        False,
                        True,
                    )
                )
                is None
            )
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.role_update_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "name": "role",
                    "newName": "updated-role",
                    "description": "Updated private role",
                    "permissionNames": ["P1", "P2"],
                    "tenantId": "t1",
                    "default": False,
                    "private": True,
                },
                follow_redirects=False,
            )

    async def test_create_without_private_parameter(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test without private parameter (should be None)
        with client.mock_mgmt_post(make_response()) as mock:
            assert await client.invoke(client.mgmt.role.create("SimpleRole", "Simple role")) is None
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.role_create_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "name": "SimpleRole",
                    "description": "Simple role",
                    "permissionNames": [],
                    "tenantId": None,
                    "default": None,
                    "private": None,
                },
                follow_redirects=False,
            )
