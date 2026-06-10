import pytest

from descope import AuthException
from descope.management.common import MgmtV1
from tests.common import DEFAULT_BASE_URL, default_headers
from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.testutils import PUBLIC_KEY_DICT


class TestPermission:
    async def test_create(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.permission.create("name"))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            assert await client.invoke(client.mgmt.permission.create("P1", "Something")) is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.permission_create_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "name": "P1",
                    "description": "Something",
                },
                follow_redirects=False,
            )

    async def test_update(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.permission.update("name", "new-name"))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            assert (
                await client.invoke(
                    client.mgmt.permission.update("name", "new-name", "new-description")
                )
            ) is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.permission_update_path}",
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
                },
                follow_redirects=False,
            )

    async def test_update_by_id(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.permission.update_by_id("PERM123", "new-name"))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            assert (
                await client.invoke(
                    client.mgmt.permission.update_by_id("PERM123", "new-name", "new-description")
                )
            ) is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.permission_update_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "id": "PERM123",
                    "newName": "new-name",
                    "description": "new-description",
                },
                follow_redirects=False,
            )

    async def test_delete(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.permission.delete("name"))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            assert await client.invoke(client.mgmt.permission.delete("name")) is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.permission_delete_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "name": "name",
                },
                follow_redirects=False,
            )

    async def test_delete_by_id(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.permission.delete_by_id("PERM123"))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            assert await client.invoke(client.mgmt.permission.delete_by_id("PERM123")) is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.permission_delete_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={"id": "PERM123"},
                follow_redirects=False,
            )

    async def test_create_batch(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.permission.create_batch([{"name": "P1"}]))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            assert (
                await client.invoke(
                    client.mgmt.permission.create_batch(
                        [
                            {"name": "P1", "description": "desc1"},
                            {"name": "P2"},
                        ]
                    )
                )
            ) is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.permission_create_batch_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "permissions": [
                        {"name": "P1", "description": "desc1"},
                        {"name": "P2"},
                    ]
                },
                follow_redirects=False,
            )

    async def test_update_batch(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.permission.update_batch(
                        [{"name": "P1", "newName": "P1-new"}]
                    )
                )

        # Test success flow — by name
        with client.mock_mgmt_post(make_response()) as mock_post:
            assert (
                await client.invoke(
                    client.mgmt.permission.update_batch(
                        [
                            {"name": "P1", "newName": "P1-new", "description": "d1"},
                            {"name": "P2", "newName": "P2-new"},
                        ]
                    )
                )
            ) is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.permission_update_batch_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "permissions": [
                        {"name": "P1", "newName": "P1-new", "description": "d1"},
                        {"name": "P2", "newName": "P2-new"},
                    ]
                },
                follow_redirects=False,
            )

        # Test success flow — by id
        with client.mock_mgmt_post(make_response()) as mock_post:
            assert (
                await client.invoke(
                    client.mgmt.permission.update_batch(
                        [
                            {"id": "PERM1", "newName": "P1-new", "description": "d1"},
                            {"id": "PERM2", "newName": "P2-new"},
                        ]
                    )
                )
            ) is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.permission_update_batch_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "permissions": [
                        {"id": "PERM1", "newName": "P1-new", "description": "d1"},
                        {"id": "PERM2", "newName": "P2-new"},
                    ]
                },
                follow_redirects=False,
            )

    async def test_delete_batch(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.permission.delete_batch(["P1"]))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            assert await client.invoke(client.mgmt.permission.delete_batch(["P1", "P2"])) is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.permission_delete_batch_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={"names": ["P1", "P2"]},
                follow_redirects=False,
            )

    async def test_delete_batch_by_ids(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.permission.delete_batch_by_ids(["PERM1"]))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            assert (
                await client.invoke(client.mgmt.permission.delete_batch_by_ids(["PERM1", "PERM2"]))
            ) is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.permission_delete_batch_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={"ids": ["PERM1", "PERM2"]},
                follow_redirects=False,
            )

    async def test_load_all(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_get(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.permission.load_all())

        # Test success flow
        with client.mock_mgmt_get(
            make_response({"permissions": [{"name": "p1"}, {"name": "p2"}]})
        ) as mock_get:
            resp = await client.invoke(client.mgmt.permission.load_all())
            permissions = resp["permissions"]
            assert len(permissions) == 2
            assert permissions[0]["name"] == "p1"
            assert permissions[1]["name"] == "p2"
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.permission_load_all_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                follow_redirects=True,
            )
