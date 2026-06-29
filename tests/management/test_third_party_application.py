import pytest

from descope import AuthException
from descope.management.common import MgmtV1
from tests.common import DEFAULT_BASE_URL, default_headers
from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.testutils import PUBLIC_KEY_DICT


class TestThirdPartyApplication:
    async def test_create(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.third_party_application.create(
                        "valid-name",
                        "http://dummy.com",
                    )
                )

        # Test success flow
        with client.mock_mgmt_post(make_response({"id": "app1", "cleartext": "secret123"})) as mock_post:
            resp = await client.invoke(
                client.mgmt.third_party_application.create(
                    name="test-app",
                    login_page_url="http://dummy.com",
                    description="Test application",
                    approved_callback_urls=["http://callback.com"],
                    force_pkce=True,
                )
            )
            assert resp["id"] == "app1"
            assert resp["cleartext"] == "secret123"
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.thirdparty_application_create_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "name": "test-app",
                    "loginPageUrl": "http://dummy.com",
                    "description": "Test application",
                    "approvedCallbackUrls": ["http://callback.com"],
                    "forcePkce": True,
                },
                follow_redirects=False,
            )

    async def test_update(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.third_party_application.update(
                        "app1",
                        "valid-name",
                        "http://dummy.com",
                    )
                )

        # Test success flow
        with client.mock_mgmt_post(make_response({})) as mock_post:
            await client.invoke(
                client.mgmt.third_party_application.update(
                    id="app1",
                    name="updated-app",
                    login_page_url="http://updated.com",
                    description="Updated application",
                    logo="http://logo.png",
                    default_audience="projectId",
                )
            )
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.thirdparty_application_update_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "id": "app1",
                    "name": "updated-app",
                    "loginPageUrl": "http://updated.com",
                    "description": "Updated application",
                    "logo": "http://logo.png",
                    "defaultAudience": "projectId",
                },
                follow_redirects=False,
            )

    async def test_patch(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.third_party_application.patch(
                        "app1",
                        name="new-name",
                    )
                )

        # Test success flow
        with client.mock_mgmt_post(make_response({})) as mock_post:
            await client.invoke(
                client.mgmt.third_party_application.patch(
                    id="app1",
                    name="patched-app",
                    force_pkce=False,
                )
            )
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.thirdparty_application_patch_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "id": "app1",
                    "name": "patched-app",
                    "forcePkce": False,
                },
                follow_redirects=False,
            )

    async def test_delete(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.third_party_application.delete("app1"))

        # Test success flow
        with client.mock_mgmt_post(make_response({})) as mock_post:
            await client.invoke(client.mgmt.third_party_application.delete("app1"))
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.thirdparty_application_delete_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={"id": "app1"},
                follow_redirects=False,
            )

    async def test_delete_batch(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.third_party_application.delete_batch(["app1", "app2"]))

        # Test success flow
        with client.mock_mgmt_post(make_response({})) as mock_post:
            await client.invoke(client.mgmt.third_party_application.delete_batch(["app1", "app2"]))
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.thirdparty_application_delete_batch_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={"ids": ["app1", "app2"]},
                follow_redirects=False,
            )

    async def test_load(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_get(make_response(status=500)) as mock_get:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.third_party_application.load("app1"))

        # Test success flow
        with client.mock_mgmt_get(
            make_response(
                {
                    "id": "app1",
                    "name": "test-app",
                    "loginPageUrl": "http://dummy.com",
                    "clientId": "client123",
                }
            )
        ) as mock_get:
            resp = await client.invoke(client.mgmt.third_party_application.load("app1"))
            assert resp["id"] == "app1"
            assert resp["name"] == "test-app"
            assert resp["clientId"] == "client123"
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.thirdparty_application_load_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params={"id": "app1"},
                follow_redirects=True,
            )

    async def test_load_all(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_get(make_response(status=500)) as mock_get:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.third_party_application.load_all())

        # Test success flow
        with client.mock_mgmt_get(
            make_response(
                {
                    "apps": [
                        {"id": "app1", "name": "test-app1"},
                        {"id": "app2", "name": "test-app2"},
                    ]
                }
            )
        ) as mock_get:
            resp = await client.invoke(client.mgmt.third_party_application.load_all())
            assert len(resp["apps"]) == 2
            assert resp["apps"][0]["id"] == "app1"
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.thirdparty_application_load_all_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                follow_redirects=True,
            )

    async def test_rotate_secret(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.third_party_application.rotate_secret("app1"))

        # Test success flow
        with client.mock_mgmt_post(make_response({"cleartext": "new-secret123"})) as mock_post:
            resp = await client.invoke(client.mgmt.third_party_application.rotate_secret("app1"))
            assert resp["cleartext"] == "new-secret123"
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.thirdparty_application_rotate_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={"id": "app1"},
                follow_redirects=False,
            )

    async def test_get_secret(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_get(make_response(status=500)) as mock_get:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.third_party_application.get_secret("app1"))

        # Test success flow
        with client.mock_mgmt_get(make_response({"cleartext": "secret123"})) as mock_get:
            resp = await client.invoke(client.mgmt.third_party_application.get_secret("app1"))
            assert resp["cleartext"] == "secret123"
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.thirdparty_application_secret_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params={"id": "app1"},
                follow_redirects=True,
            )

    async def test_delete_consents(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.third_party_application.delete_consents(app_id="app1", user_ids=["user1"])
                )

        # Test success flow
        with client.mock_mgmt_post(make_response({})) as mock_post:
            await client.invoke(
                client.mgmt.third_party_application.delete_consents(
                    consent_ids=["c1", "c2"],
                    app_id="app1",
                    user_ids=["user1"],
                    tenant_id="tenant1",
                )
            )
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.thirdparty_consents_delete_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "consentIds": ["c1", "c2"],
                    "appId": "app1",
                    "userIds": ["user1"],
                    "tenantId": "tenant1",
                },
                follow_redirects=False,
            )

    async def test_delete_tenant_consents(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.third_party_application.delete_tenant_consents("tenant1"))

        # Test success flow
        with client.mock_mgmt_post(make_response({})) as mock_post:
            await client.invoke(client.mgmt.third_party_application.delete_tenant_consents("tenant1"))
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.thirdparty_consents_delete_tenant_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={"tenantId": "tenant1"},
                follow_redirects=False,
            )

    async def test_search_consents(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.third_party_application.search_consents(app_id="app1"))

        # Test success flow
        with client.mock_mgmt_post(
            make_response({"consents": [{"consentId": "c1", "appId": "app1", "userId": "user1"}]})
        ) as mock_post:
            resp = await client.invoke(
                client.mgmt.third_party_application.search_consents(
                    app_id="app1",
                    user_id="user1",
                    page=1,
                    limit=10,
                    tenant_id="tenant1",
                )
            )
            assert len(resp["consents"]) == 1
            assert resp["consents"][0]["consentId"] == "c1"
            assert_http_called(
                mock_post,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.thirdparty_consents_search_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "appId": "app1",
                    "userId": "user1",
                    "page": 1,
                    "limit": 10,
                    "tenantId": "tenant1",
                },
                follow_redirects=False,
            )
