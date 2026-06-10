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

TUPLE = {
    "resource": "r",
    "resourceType": "rt",
    "relation": "rel",
    "target": "u",
    "targetType": "ty",
}


class TestFGA:
    async def test_save_schema(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed save_schema
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.fga.save_schema(""))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock:
            assert await client.invoke(client.mgmt.fga.save_schema("model AuthZ 1.0")) is None
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.fga_save_schema}",
                headers=MGMT_HEADERS,
                params=None,
                json={"dsl": "model AuthZ 1.0"},
                follow_redirects=False,
            )

    async def test_create_relations(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed create_relations
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.fga.create_relations([]))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock:
            assert await client.invoke(client.mgmt.fga.create_relations([TUPLE])) is None
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.fga_create_relations}",
                headers=MGMT_HEADERS,
                params=None,
                json={"tuples": [TUPLE]},
                follow_redirects=False,
            )

    async def test_delete_relations(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed delete_relations
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.fga.delete_relations([]))

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock:
            assert await client.invoke(client.mgmt.fga.delete_relations([TUPLE])) is None
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.fga_delete_relations}",
                headers=MGMT_HEADERS,
                params=None,
                json={"tuples": [TUPLE]},
                follow_redirects=False,
            )

    async def test_check(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed check
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.fga.check([]))

        # Test success flow
        with client.mock_mgmt_post(make_response({"tuples": []})) as mock:
            result = await client.invoke(client.mgmt.fga.check([TUPLE]))
            assert result is not None
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.fga_check}",
                headers=MGMT_HEADERS,
                params=None,
                json={"tuples": [TUPLE]},
                follow_redirects=False,
            )

    async def test_load_resources_details_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")
        response_body = {
            "resourcesDetails": [
                {"resourceId": "r1", "resourceType": "type1", "displayName": "Name1"},
                {"resourceId": "r2", "resourceType": "type2", "displayName": "Name2"},
            ]
        }
        ids = [
            {"resourceId": "r1", "resourceType": "type1"},
            {"resourceId": "r2", "resourceType": "type2"},
        ]
        with client.mock_mgmt_post(make_response(response_body)) as mock:
            details = await client.invoke(client.mgmt.fga.load_resources_details(ids))
            assert details == response_body["resourcesDetails"]
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.fga_resources_load}",
                headers=MGMT_HEADERS,
                params=None,
                json={"resourceIdentifiers": ids},
                follow_redirects=False,
            )

    async def test_load_resources_details_error(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")
        ids = [{"resourceId": "r1", "resourceType": "type1"}]
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.fga.load_resources_details(ids))

    async def test_save_resources_details_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")
        details = [{"resourceId": "r1", "resourceType": "type1", "displayName": "Name1"}]
        with client.mock_mgmt_post(make_response()) as mock:
            await client.invoke(client.mgmt.fga.save_resources_details(details))
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.fga_resources_save}",
                headers=MGMT_HEADERS,
                params=None,
                json={"resourcesDetails": details},
                follow_redirects=False,
            )

    async def test_save_resources_details_error(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")
        details = [{"resourceId": "r1", "resourceType": "type1", "displayName": "Name1"}]
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.fga.save_resources_details(details))

    async def test_fga_cache_url_save_schema(self, client_factory):
        fga_cache_url = "https://my-fga-cache.example.com"
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key", fga_cache_url=fga_cache_url)

        with client.mock_mgmt_post(make_response()) as mock:
            await client.invoke(client.mgmt.fga.save_schema("model AuthZ 1.0"))
            assert_http_called(
                mock,
                client.mode,
                f"{fga_cache_url}{MgmtV1.fga_save_schema}",
                headers=MGMT_HEADERS,
                params=None,
                json={"dsl": "model AuthZ 1.0"},
                follow_redirects=False,
            )

    async def test_fga_cache_url_create_relations(self, client_factory):
        fga_cache_url = "https://my-fga-cache.example.com"
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key", fga_cache_url=fga_cache_url)

        with client.mock_mgmt_post(make_response()) as mock:
            await client.invoke(client.mgmt.fga.create_relations([TUPLE]))
            assert_http_called(
                mock,
                client.mode,
                f"{fga_cache_url}{MgmtV1.fga_create_relations}",
                headers=MGMT_HEADERS,
                params=None,
                json={"tuples": [TUPLE]},
                follow_redirects=False,
            )

    async def test_fga_cache_url_delete_relations(self, client_factory):
        fga_cache_url = "https://my-fga-cache.example.com"
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key", fga_cache_url=fga_cache_url)

        with client.mock_mgmt_post(make_response()) as mock:
            await client.invoke(client.mgmt.fga.delete_relations([TUPLE]))
            assert_http_called(
                mock,
                client.mode,
                f"{fga_cache_url}{MgmtV1.fga_delete_relations}",
                headers=MGMT_HEADERS,
                params=None,
                json={"tuples": [TUPLE]},
                follow_redirects=False,
            )

    async def test_fga_cache_url_check(self, client_factory):
        fga_cache_url = "https://my-fga-cache.example.com"
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key", fga_cache_url=fga_cache_url)

        response_body = {
            "tuples": [
                {
                    "allowed": True,
                    "tuple": TUPLE,
                }
            ]
        }

        with client.mock_mgmt_post(make_response(response_body)) as mock:
            result = await client.invoke(client.mgmt.fga.check([TUPLE]))
            assert_http_called(
                mock,
                client.mode,
                f"{fga_cache_url}{MgmtV1.fga_check}",
                headers=MGMT_HEADERS,
                params=None,
                json={"tuples": [TUPLE]},
                follow_redirects=False,
            )
            assert len(result) == 1
            assert result[0]["allowed"] is True
            assert result[0]["relation"] == TUPLE

    async def test_fga_without_cache_url_uses_default_base_url(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response()) as mock:
            await client.invoke(client.mgmt.fga.save_schema("model AuthZ 1.0"))
            assert_http_called(
                mock,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.fga_save_schema}",
                headers=MGMT_HEADERS,
                params=None,
                json={"dsl": "model AuthZ 1.0"},
                follow_redirects=False,
            )
