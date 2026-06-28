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

# The management Engine exposes only id/name/secret/createdTime; createdTime is an int32
# epoch-seconds JSON number.
ENGINE_RESPONSE = {
    "engine": {
        "id": "eng1",
        "name": "my-engine",
        "secret": "s3cret",
        "createdTime": 1719571200,
    }
}


class TestEngine:
    async def test_create(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flow
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.engine.create("my-engine"))

        # Test success flow
        with client.mock_mgmt_post(make_response(ENGINE_RESPONSE)) as mock_post:
            resp = await client.invoke(client.mgmt.engine.create("my-engine"))
            engine = resp["engine"]
            assert engine["id"] == "eng1"
            assert engine["secret"] == "s3cret"
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.engine_create_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={"name": "my-engine"},
                follow_redirects=False,
            )

    async def test_update(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.engine.update("eng1", "renamed"))

        with client.mock_mgmt_post(make_response({"engine": {"id": "eng1", "name": "renamed"}})) as mock_post:
            resp = await client.invoke(client.mgmt.engine.update("eng1", "renamed"))
            assert resp["engine"]["name"] == "renamed"
            # Update never returns a secret.
            assert "secret" not in resp["engine"]
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.engine_update_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={"id": "eng1", "name": "renamed"},
                follow_redirects=False,
            )

    async def test_delete(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.engine.delete("eng1"))

        with client.mock_mgmt_post(make_response({})) as mock_post:
            await client.invoke(client.mgmt.engine.delete("eng1"))
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.engine_delete_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={"id": "eng1"},
                follow_redirects=False,
            )

    async def test_load(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_get(make_response(status=500)) as mock_get:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.engine.load("eng1"))

        with client.mock_mgmt_get(make_response({"engine": {"id": "eng1", "name": "my-engine"}})) as mock_get:
            resp = await client.invoke(client.mgmt.engine.load("eng1"))
            assert resp["engine"]["id"] == "eng1"
            # Load never returns a secret.
            assert "secret" not in resp["engine"]
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.engine_load_path}",
                headers=MGMT_HEADERS,
                params={"id": "eng1"},
                follow_redirects=True,
            )

    async def test_load_all(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_get(make_response(status=500)) as mock_get:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.engine.load_all())

        with client.mock_mgmt_get(make_response({"engines": [{"id": "eng1"}, {"id": "eng2"}]})) as mock_get:
            resp = await client.invoke(client.mgmt.engine.load_all())
            assert len(resp["engines"]) == 2
            assert resp["engines"][0]["id"] == "eng1"
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.engine_load_all_path}",
                headers=MGMT_HEADERS,
                params=None,
                follow_redirects=True,
            )

    async def test_rotate_secret(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.engine.rotate_secret("eng1"))

        with client.mock_mgmt_post(make_response({"secret": "newS3cret"})) as mock_post:
            resp = await client.invoke(client.mgmt.engine.rotate_secret("eng1"))
            assert resp["secret"] == "newS3cret"
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.engine_rotate_secret_path}",
                headers=MGMT_HEADERS,
                params=None,
                json={"id": "eng1"},
                follow_redirects=False,
            )
