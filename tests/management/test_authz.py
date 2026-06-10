import pytest

from descope import AuthException
from descope.management.common import MgmtV1

from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.common import DEFAULT_BASE_URL, default_headers
from tests.testutils import PUBLIC_KEY_DICT

AUTH_HEADERS = {
    **default_headers,
    "Authorization": f"Bearer {PROJECT_ID}:key",
    "x-descope-project-id": PROJECT_ID,
}


class TestAuthz:
    async def test_save_schema(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed save_schema
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.authz.save_schema({}, True))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock:
            await client.invoke(client.mgmt.authz.save_schema({"name": "kuku"}, True))
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.authz_schema_save}",
                headers=AUTH_HEADERS,
                params=None,
                json={"schema": {"name": "kuku"}, "upgrade": True},
                follow_redirects=False,
            )

    async def test_delete_schema(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed delete_schema
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.authz.delete_schema())

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock:
            await client.invoke(client.mgmt.authz.delete_schema())
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.authz_schema_delete}",
                headers=AUTH_HEADERS,
                params=None,
                json=None,
                follow_redirects=False,
            )

    async def test_load_schema(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed load_schema
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.authz.load_schema())

        # Test success flow
        with client.mock_mgmt_post(make_response({"schema": {"name": "kuku"}})) as mock:
            result = await client.invoke(client.mgmt.authz.load_schema())
            assert result is not None
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.authz_schema_load}",
                headers=AUTH_HEADERS,
                params=None,
                json=None,
                follow_redirects=False,
            )

    async def test_save_namespace(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed save_namespace
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.authz.save_namespace({}))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock:
            await client.invoke(client.mgmt.authz.save_namespace({"name": "kuku"}, "old", "v1"))
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.authz_ns_save}",
                headers=AUTH_HEADERS,
                params=None,
                json={
                    "namespace": {"name": "kuku"},
                    "oldName": "old",
                    "schemaName": "v1",
                },
                follow_redirects=False,
            )

    async def test_delete_namespace(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed delete_namespace
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.authz.delete_namespace("a"))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock:
            await client.invoke(client.mgmt.authz.delete_namespace("a", "b"))
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.authz_ns_delete}",
                headers=AUTH_HEADERS,
                params=None,
                json={"name": "a", "schemaName": "b"},
                follow_redirects=False,
            )

    async def test_save_relation_definition(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed save_relation_definition
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.authz.save_relation_definition({}, "a"))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock:
            await client.invoke(client.mgmt.authz.save_relation_definition({"name": "kuku"}, "a", "old", "v1"))
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.authz_rd_save}",
                headers=AUTH_HEADERS,
                params=None,
                json={
                    "relationDefinition": {"name": "kuku"},
                    "namespace": "a",
                    "oldName": "old",
                    "schemaName": "v1",
                },
                follow_redirects=False,
            )

    async def test_delete_relation_definition(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed delete_relation_definition
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.authz.delete_relation_definition("a", "b"))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock:
            await client.invoke(client.mgmt.authz.delete_relation_definition("a", "b", "c"))
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.authz_rd_delete}",
                headers=AUTH_HEADERS,
                params=None,
                json={"name": "a", "namespace": "b", "schemaName": "c"},
                follow_redirects=False,
            )

    async def test_create_relations(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed create_relations
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.authz.create_relations([]))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock:
            await client.invoke(
                client.mgmt.authz.create_relations(
                    [
                        {
                            "resource": "r",
                            "relationDefinition": "rd",
                            "namespace": "ns",
                            "target": "u",
                        }
                    ]
                )
            )
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.authz_re_create}",
                headers=AUTH_HEADERS,
                params=None,
                json={
                    "relations": [
                        {
                            "resource": "r",
                            "relationDefinition": "rd",
                            "namespace": "ns",
                            "target": "u",
                        }
                    ]
                },
                follow_redirects=False,
            )

    async def test_delete_relations(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed delete_relations
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.authz.delete_relations([]))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock:
            await client.invoke(
                client.mgmt.authz.delete_relations(
                    [
                        {
                            "resource": "r",
                            "relationDefinition": "rd",
                            "namespace": "ns",
                            "target": "u",
                        }
                    ]
                )
            )
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.authz_re_delete}",
                headers=AUTH_HEADERS,
                params=None,
                json={
                    "relations": [
                        {
                            "resource": "r",
                            "relationDefinition": "rd",
                            "namespace": "ns",
                            "target": "u",
                        }
                    ]
                },
                follow_redirects=False,
            )

    async def test_delete_relations_for_resources(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed delete_relations_for_resources
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.authz.delete_relations_for_resources([]))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock:
            await client.invoke(client.mgmt.authz.delete_relations_for_resources(["r"]))
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.authz_re_delete_resources}",
                headers=AUTH_HEADERS,
                params=None,
                json={"resources": ["r"]},
                follow_redirects=False,
            )

    async def test_has_relations(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed has_relations
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.authz.has_relations([]))

        # Test success flow
        with client.mock_mgmt_post(make_response({"relationQueries": []})) as mock:
            result = await client.invoke(
                client.mgmt.authz.has_relations(
                    [
                        {
                            "resource": "r",
                            "relationDefinition": "rd",
                            "namespace": "ns",
                            "target": "u",
                        }
                    ]
                )
            )
            assert result is not None
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.authz_re_has_relations}",
                headers=AUTH_HEADERS,
                params=None,
                json={
                    "relationQueries": [
                        {
                            "resource": "r",
                            "relationDefinition": "rd",
                            "namespace": "ns",
                            "target": "u",
                        }
                    ]
                },
                follow_redirects=False,
            )

    async def test_who_can_access(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed who_can_access
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.authz.who_can_access("a", "b", "c"))

        # Test success flow
        with client.mock_mgmt_post(make_response({"targets": []})) as mock:
            result = await client.invoke(client.mgmt.authz.who_can_access("a", "b", "c"))
            assert result is not None
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.authz_re_who}",
                headers=AUTH_HEADERS,
                params=None,
                json={"resource": "a", "relationDefinition": "b", "namespace": "c"},
                follow_redirects=False,
            )

    async def test_resource_relations(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed resource_relations
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.authz.resource_relations("a"))

        # Test success flow
        with client.mock_mgmt_post(make_response({"relations": []})) as mock:
            result = await client.invoke(client.mgmt.authz.resource_relations("a"))
            assert result is not None
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.authz_re_resource}",
                headers=AUTH_HEADERS,
                params=None,
                json={"resource": "a"},
                follow_redirects=False,
            )

    async def test_targets_relations(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed targets_relations
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.authz.targets_relations(["a"]))

        # Test success flow
        with client.mock_mgmt_post(make_response({"relations": []})) as mock:
            result = await client.invoke(client.mgmt.authz.targets_relations(["a"]))
            assert result is not None
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.authz_re_targets}",
                headers=AUTH_HEADERS,
                params=None,
                json={"targets": ["a"]},
                follow_redirects=False,
            )

    async def test_what_can_target_access(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed what_can_target_access
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.authz.what_can_target_access("a"))

        # Test success flow
        with client.mock_mgmt_post(make_response({"relations": []})) as mock:
            result = await client.invoke(client.mgmt.authz.what_can_target_access("a"))
            assert result is not None
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.authz_re_target_all}",
                headers=AUTH_HEADERS,
                params=None,
                json={"target": "a"},
                follow_redirects=False,
            )

    async def test_what_can_target_access_with_relation(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed what_can_target_access_with_relation
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.authz.what_can_target_access_with_relation("a", "b", "c")
                )

        # Test success flow
        with client.mock_mgmt_post(make_response({"relations": []})) as mock:
            result = await client.invoke(
                client.mgmt.authz.what_can_target_access_with_relation("a", "b", "c")
            )
            assert result is not None
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.authz_re_target_with_relation}",
                headers=AUTH_HEADERS,
                params=None,
                json={"target": "a", "relationDefinition": "b", "namespace": "c"},
                follow_redirects=False,
            )

    async def test_get_modified(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed get_modified
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.authz.get_modified())

        # Test success flow
        with client.mock_mgmt_post(make_response({"relations": []})) as mock:
            result = await client.invoke(client.mgmt.authz.get_modified())
            assert result is not None
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.authz_get_modified}",
                headers=AUTH_HEADERS,
                params=None,
                json={"since": 0},
                follow_redirects=False,
            )

    async def test_authz_cache_url_who_can_access(self, client_factory):
        fga_cache_url = "https://my-fga-cache.example.com"
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key", fga_cache_url=fga_cache_url)

        with client.mock_mgmt_post(make_response({"targets": ["u1"]})) as mock:
            result = await client.invoke(client.mgmt.authz.who_can_access("a", "b", "c"))
            assert_http_called(
                mock,
                client.mode,
                f"{fga_cache_url}{MgmtV1.authz_re_who}",
                headers=AUTH_HEADERS,
                params=None,
                json={
                    "resource": "a",
                    "relationDefinition": "b",
                    "namespace": "c",
                },
                follow_redirects=False,
            )
            assert result == ["u1"]

    async def test_authz_cache_url_what_can_target_access(self, client_factory):
        fga_cache_url = "https://my-fga-cache.example.com"
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key", fga_cache_url=fga_cache_url)

        with client.mock_mgmt_post(make_response({"relations": [{"resource": "r1"}]})) as mock:
            result = await client.invoke(client.mgmt.authz.what_can_target_access("a"))
            assert_http_called(
                mock,
                client.mode,
                f"{fga_cache_url}{MgmtV1.authz_re_target_all}",
                headers=AUTH_HEADERS,
                params=None,
                json={"target": "a"},
                follow_redirects=False,
            )
            assert result == [{"resource": "r1"}]
