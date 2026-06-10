import pytest

from descope import AuthException
from descope.management.common import MgmtV1

from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.common import DEFAULT_BASE_URL, default_headers
from tests.testutils import PUBLIC_KEY_DICT


class TestProject:
    async def test_update_name(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.project.update_name("name"))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            assert await client.invoke(client.mgmt.project.update_name("new-name")) is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.project_update_name}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "name": "new-name",
                },
                follow_redirects=False,
            )

    async def test_update_tags(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.project.update_tags("tags"))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            assert await client.invoke(client.mgmt.project.update_tags(["tag1", "tag2"])) is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.project_update_tags}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "tags": ["tag1", "tag2"],
                },
                follow_redirects=False,
            )

    async def test_list_projects(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.project.list_projects())

        # Test success flow
        json_data = {
            "projects": [
                {
                    "id": "dummy",
                    "name": "hey",
                    "environment": "",
                    "tags": ["tag1", "tag2"],
                }
            ]
        }
        with client.mock_mgmt_post(make_response(json_data)) as mock_post:
            resp = await client.invoke(client.mgmt.project.list_projects())
            projects = resp["projects"]
            assert len(projects) == 1
            assert projects[0]["id"] == "dummy"
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.project_list_projects}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={},
                follow_redirects=False,
            )

    async def test_clone(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.project.clone(
                        "new-name",
                        "production",
                        ["apple", "banana", "cherry"],
                    )
                )

        # Test success flow
        with client.mock_mgmt_post(make_response({"id": "dummy"})) as mock_post:
            resp = await client.invoke(
                client.mgmt.project.clone(
                    "new-name",
                    "production",
                    ["apple", "banana", "cherry"],
                )
            )
            assert resp["id"] == "dummy"
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.project_clone}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "name": "new-name",
                    "environment": "production",
                    "tags": ["apple", "banana", "cherry"],
                },
                follow_redirects=False,
            )

    async def test_export_project(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.project.export_project())

        # Test success flow
        with client.mock_mgmt_post(make_response({"files": {"foo": "bar"}})) as mock_post:
            resp = await client.invoke(client.mgmt.project.export_project())
            assert resp is not None
            assert resp["foo"] == "bar"
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.project_export}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={},
                follow_redirects=False,
            )

    async def test_import_project(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.project.import_project({"foo": "bar"}))

        # Test success flow
        files = {"foo": "bar"}
        with client.mock_mgmt_post(make_response()) as mock_post:
            await client.invoke(client.mgmt.project.import_project(files))
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.project_import}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "files": {
                        "foo": "bar",
                    },
                },
                follow_redirects=False,
            )
