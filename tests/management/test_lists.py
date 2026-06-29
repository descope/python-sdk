import pytest

from descope import AuthException
from descope.management.common import MgmtV1
from tests.common import DEFAULT_BASE_URL, default_headers
from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.testutils import PUBLIC_KEY_DICT

MGMT_HEADERS = {
    **default_headers,
    "Authorization": f"Bearer {PROJECT_ID}:key",
    "x-descope-project-id": PROJECT_ID,
}

LIST_RESPONSE = {
    "list": {
        "id": "list1",
        "name": "my-list",
        "description": "Test list",
        "type": "texts",
        "data": ["item1", "item2"],
        "createdTime": 1719571200,
    }
}


class TestLists:
    async def test_create(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.list.create("my-list", "texts", "Test list", ["item1"]))

        # Test success flow
        with client.mock_mgmt_post(make_response(LIST_RESPONSE)) as mock_post:
            resp = await client.invoke(client.mgmt.list.create("my-list", "texts", "Test list", ["item1"]))
            assert resp["list"]["id"] == "list1"
            assert resp["list"]["name"] == "my-list"
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.list_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={
                    "name": "my-list",
                    "type": "texts",
                    "description": "Test list",
                    "data": ["item1"],
                },
                follow_redirects=False,
            )

    async def test_update(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.list.update("list1", "renamed", "ips", None, ["1.2.3.4"]))

        with client.mock_mgmt_post(make_response({"list": {"id": "list1", "name": "renamed"}})) as mock_post:
            resp = await client.invoke(client.mgmt.list.update("list1", "renamed", "ips", None, ["1.2.3.4"]))
            assert resp["list"]["name"] == "renamed"
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.list_update_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={"id": "list1", "name": "renamed", "type": "ips", "data": ["1.2.3.4"]},
                follow_redirects=False,
            )

    async def test_delete(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.list.delete("list1"))

        with client.mock_mgmt_post(make_response({})) as mock_post:
            await client.invoke(client.mgmt.list.delete("list1"))
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.list_delete_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={"id": "list1"},
                follow_redirects=False,
            )

    async def test_load(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_get(make_response(status=500)) as mock_get:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.list.load("list1"))

        with client.mock_mgmt_get(make_response({"list": {"id": "list1", "name": "my-list"}})) as mock_get:
            resp = await client.invoke(client.mgmt.list.load("list1"))
            assert resp["list"]["id"] == "list1"
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.list_path}",
                headers=MGMT_HEADERS,
                params={"id": "list1"},
                follow_redirects=True,
            )

    async def test_load_by_name(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_get(make_response(status=500)) as mock_get:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.list.load_by_name("my-list"))

        with client.mock_mgmt_get(make_response({"list": {"id": "list1", "name": "my-list"}})) as mock_get:
            resp = await client.invoke(client.mgmt.list.load_by_name("my-list"))
            assert resp["list"]["name"] == "my-list"
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.list_name_path}",
                headers=MGMT_HEADERS,
                params={"name": "my-list"},
                follow_redirects=True,
            )

    async def test_load_all(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_get(make_response(status=500)) as mock_get:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.list.load_all())

        with client.mock_mgmt_get(make_response({"lists": [{"id": "list1"}, {"id": "list2"}]})) as mock_get:
            resp = await client.invoke(client.mgmt.list.load_all())
            assert len(resp["lists"]) == 2
            assert resp["lists"][0]["id"] == "list1"
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.list_all_path}",
                headers=MGMT_HEADERS,
                params=None,
                follow_redirects=True,
            )

    async def test_import_lists(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        lists_to_import = [
            {"id": "list1", "name": "List 1", "type": "texts", "data": ["a", "b"]},
            {"id": "list2", "name": "List 2", "type": "ips", "data": ["1.2.3.4"]},
        ]

        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.list.import_lists(lists_to_import))

        with client.mock_mgmt_post(make_response({})) as mock_post:
            await client.invoke(client.mgmt.list.import_lists(lists_to_import))
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.list_import_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={"lists": lists_to_import},
                follow_redirects=False,
            )

    async def test_add_ips(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.list.add_ips("list1", ["1.2.3.4", "5.6.7.8"]))

        with client.mock_mgmt_post(make_response({})) as mock_post:
            await client.invoke(client.mgmt.list.add_ips("list1", ["1.2.3.4", "5.6.7.8"]))
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.list_ip_add_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={"id": "list1", "ips": ["1.2.3.4", "5.6.7.8"]},
                follow_redirects=False,
            )

    async def test_remove_ips(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.list.remove_ips("list1", ["1.2.3.4"]))

        with client.mock_mgmt_post(make_response({})) as mock_post:
            await client.invoke(client.mgmt.list.remove_ips("list1", ["1.2.3.4"]))
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.list_ip_remove_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={"id": "list1", "ips": ["1.2.3.4"]},
                follow_redirects=False,
            )

    async def test_check_ip(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.list.check_ip("list1", "1.2.3.4"))

        with client.mock_mgmt_post(make_response({"exists": True})) as mock_post:
            result = await client.invoke(client.mgmt.list.check_ip("list1", "1.2.3.4"))
            assert result is True
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.list_ip_check_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={"id": "list1", "ip": "1.2.3.4"},
                follow_redirects=False,
            )

        with client.mock_mgmt_post(make_response({"exists": False})) as mock_post:
            result = await client.invoke(client.mgmt.list.check_ip("list1", "1.2.3.4"))
            assert result is False

    async def test_add_texts(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.list.add_texts("list1", ["text1", "text2"]))

        with client.mock_mgmt_post(make_response({})) as mock_post:
            await client.invoke(client.mgmt.list.add_texts("list1", ["text1", "text2"]))
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.list_text_add_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={"id": "list1", "texts": ["text1", "text2"]},
                follow_redirects=False,
            )

    async def test_remove_texts(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.list.remove_texts("list1", ["text1"]))

        with client.mock_mgmt_post(make_response({})) as mock_post:
            await client.invoke(client.mgmt.list.remove_texts("list1", ["text1"]))
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.list_text_remove_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={"id": "list1", "texts": ["text1"]},
                follow_redirects=False,
            )

    async def test_check_text(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.list.check_text("list1", "text1"))

        with client.mock_mgmt_post(make_response({"exists": True})) as mock_post:
            result = await client.invoke(client.mgmt.list.check_text("list1", "text1"))
            assert result is True
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.list_text_check_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={"id": "list1", "text": "text1"},
                follow_redirects=False,
            )

        with client.mock_mgmt_post(make_response({"exists": False})) as mock_post:
            result = await client.invoke(client.mgmt.list.check_text("list1", "text1"))
            assert result is False

    async def test_clear(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.list.clear("list1"))

        with client.mock_mgmt_post(make_response({})) as mock_post:
            await client.invoke(client.mgmt.list.clear("list1"))
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.list_clear_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={"id": "list1"},
                follow_redirects=False,
            )
