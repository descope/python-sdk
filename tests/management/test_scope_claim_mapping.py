import pytest

from descope import AuthException
from descope.management.common import MgmtV1
from tests.common import DEFAULT_BASE_URL, default_headers
from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.testutils import PUBLIC_KEY_DICT


class TestScopeClaimMapping:
    async def test_get(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.scope_claim_mapping.get())

        # Test success flow
        json_data = {
            "mappings": [
                {
                    "scope": "openid",
                    "claims": {"sub": "userId", "email": "email"},
                    "description": "OpenID scope mapping",
                }
            ]
        }
        with client.mock_mgmt_post(make_response(json_data)) as mock_post:
            resp = await client.invoke(client.mgmt.scope_claim_mapping.get())
            assert resp is not None
            assert "mappings" in resp
            assert len(resp["mappings"]) == 1
            assert resp["mappings"][0]["scope"] == "openid"
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.scope_claim_mapping_get_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={},
                follow_redirects=False,
            )

    async def test_set(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.scope_claim_mapping.set([]))

        # Test success flow
        mappings = [
            {
                "scope": "profile",
                "claims": {"name": "name", "picture": "picture"},
                "description": "Profile scope mapping",
            }
        ]
        with client.mock_mgmt_post(make_response()) as mock_post:
            assert await client.invoke(client.mgmt.scope_claim_mapping.set(mappings)) is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.scope_claim_mapping_set_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "mappings": [
                        {
                            "scope": "profile",
                            "claims": {"name": "name", "picture": "picture"},
                            "description": "Profile scope mapping",
                        }
                    ]
                },
                follow_redirects=False,
            )

    async def test_delete(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.scope_claim_mapping.delete())

        # Test success flow
        with client.mock_mgmt_post(make_response()) as mock_post:
            resp = await client.invoke(client.mgmt.scope_claim_mapping.delete())
            assert resp is None
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.scope_claim_mapping_delete_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={},
                follow_redirects=False,
            )
