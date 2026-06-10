import pytest

from descope import AuthException
from descope.management.common import AccessType, MgmtV1, PromptType, URLParam
from descope.management.outbound_application import OutboundApplication

from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.common import DEFAULT_BASE_URL, default_headers
from tests.testutils import PUBLIC_KEY_DICT

DUMMY_TOKEN = "inbound-app-token"

APP_RESPONSE = {
    "app": {
        "id": "app123",
        "name": "Test App",
        "description": "Test Description",
    }
}

TOKEN_RESPONSE = {
    "token": {
        "token": "access-token",
        "refreshToken": "refresh-token",
        "expiresIn": 3600,
        "tokenType": "Bearer",
        "scopes": ["read", "write"],
    }
}

MGMT_HEADERS = {
    **default_headers,
    "Authorization": f"Bearer {PROJECT_ID}:key",
    "x-descope-project-id": PROJECT_ID,
}


class TestOutboundApplication:
    async def test_create_application_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(APP_RESPONSE)) as mock_post:
            response = await client.invoke(
                client.mgmt.outbound_application.create_application(
                    "Test App", description="Test Description", client_secret="secret"
                )
            )
            assert response == APP_RESPONSE

    async def test_create_application_with_all_parameters_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        auth_params = [
            URLParam("response_type", "code"),
            URLParam("client_id", "test-client"),
        ]
        token_params = [URLParam("grant_type", "authorization_code")]
        prompts = [PromptType.LOGIN, PromptType.CONSENT]

        with client.mock_mgmt_post(
            make_response(
                {
                    "app": {
                        "id": "app123",
                        "name": "Test OAuth App",
                        "description": "Test Description",
                    }
                }
            )
        ) as mock_post:
            response = await client.invoke(
                client.mgmt.outbound_application.create_application(
                    name="Test OAuth App",
                    description="Test Description",
                    logo="https://example.com/logo.png",
                    id="app123",
                    client_secret="secret",
                    client_id="test-client-id",
                    discovery_url="https://accounts.google.com/.well-known/openid_configuration",
                    authorization_url="https://accounts.google.com/o/oauth2/v2/auth",
                    authorization_url_params=auth_params,
                    token_url="https://oauth2.googleapis.com/token",
                    token_url_params=token_params,
                    revocation_url="https://oauth2.googleapis.com/revoke",
                    default_scopes=["https://www.googleapis.com/auth/userinfo.profile"],
                    default_redirect_url="https://myapp.com/callback",
                    callback_domain="myapp.com",
                    pkce=True,
                    access_type=AccessType.OFFLINE,
                    prompt=prompts,
                )
            )
            assert response == {
                "app": {
                    "id": "app123",
                    "name": "Test OAuth App",
                    "description": "Test Description",
                }
            }

    async def test_create_application_failure(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.outbound_application.create_application("Test App")
                )

    async def test_update_application_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(
            make_response(
                {
                    "app": {
                        "id": "app123",
                        "name": "Updated App",
                        "description": "Updated Description",
                    }
                }
            )
        ) as mock_post:
            response = await client.invoke(
                client.mgmt.outbound_application.update_application(
                    "app123",
                    "Updated App",
                    description="Updated Description",
                    client_secret="new-secret",
                )
            )
            assert response == {
                "app": {
                    "id": "app123",
                    "name": "Updated App",
                    "description": "Updated Description",
                }
            }

    async def test_update_application_with_all_parameters_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        auth_params = [
            URLParam("response_type", "code"),
            URLParam("client_id", "test-client"),
        ]
        token_params = [URLParam("grant_type", "authorization_code")]
        prompts = [PromptType.LOGIN, PromptType.CONSENT, PromptType.SELECT_ACCOUNT]

        with client.mock_mgmt_post(
            make_response(
                {
                    "app": {
                        "id": "app123",
                        "name": "Updated OAuth App",
                        "description": "Updated Description",
                    }
                }
            )
        ) as mock_post:
            response = await client.invoke(
                client.mgmt.outbound_application.update_application(
                    id="app123",
                    name="Updated OAuth App",
                    description="Updated Description",
                    logo="https://example.com/new-logo.png",
                    client_secret="new-secret",
                    client_id="new-client-id",
                    discovery_url="https://accounts.google.com/.well-known/openid_configuration",
                    authorization_url="https://accounts.google.com/o/oauth2/v2/auth",
                    authorization_url_params=auth_params,
                    token_url="https://oauth2.googleapis.com/token",
                    token_url_params=token_params,
                    revocation_url="https://oauth2.googleapis.com/revoke",
                    default_scopes=[
                        "https://www.googleapis.com/auth/userinfo.profile",
                        "https://www.googleapis.com/auth/userinfo.email",
                    ],
                    default_redirect_url="https://myapp.com/updated-callback",
                    callback_domain="myapp.com",
                    pkce=True,
                    access_type=AccessType.OFFLINE,
                    prompt=prompts,
                )
            )
            assert response == {
                "app": {
                    "id": "app123",
                    "name": "Updated OAuth App",
                    "description": "Updated Description",
                }
            }

    async def test_update_application_failure(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.outbound_application.update_application(
                        "app123", "Updated App"
                    )
                )

    async def test_delete_application_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=200)):
            await client.invoke(
                client.mgmt.outbound_application.delete_application("app123")
            )

    async def test_delete_application_failure(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.outbound_application.delete_application("app123")
                )

    async def test_load_application_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_get(make_response(APP_RESPONSE)) as mock_get:
            response = await client.invoke(
                client.mgmt.outbound_application.load_application("app123")
            )
            assert response == APP_RESPONSE
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.outbound_application_load_path}/app123",
                headers=MGMT_HEADERS,
                params=None,
                follow_redirects=True,
            )

    async def test_load_application_failure(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_get(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.outbound_application.load_application("app123")
                )

    async def test_load_all_applications_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        apps_response = {
            "apps": [
                {"id": "app1", "name": "App 1", "description": "Description 1"},
                {"id": "app2", "name": "App 2", "description": "Description 2"},
            ]
        }
        with client.mock_mgmt_get(make_response(apps_response)) as mock_get:
            response = await client.invoke(
                client.mgmt.outbound_application.load_all_applications()
            )
            assert response == apps_response
            assert_http_called(
                mock_get,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.outbound_application_load_all_path}",
                headers=MGMT_HEADERS,
                params=None,
                follow_redirects=True,
            )

    async def test_load_all_applications_failure(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_get(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.outbound_application.load_all_applications()
                )

    async def test_fetch_token_by_scopes_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(TOKEN_RESPONSE)) as mock_post:
            response = await client.invoke(
                client.mgmt.outbound_application.fetch_token_by_scopes(
                    "app123",
                    "user456",
                    ["read", "write"],
                    {"refreshToken": True},
                    "tenant789",
                )
            )
            assert response == TOKEN_RESPONSE

    async def test_fetch_token_by_scopes_failure(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.outbound_application.fetch_token_by_scopes(
                        "app123", "user456", ["read"]
                    )
                )

    async def test_fetch_token_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(TOKEN_RESPONSE)) as mock_post:
            response = await client.invoke(
                client.mgmt.outbound_application.fetch_token(
                    "app123", "user456", "tenant789", {"forceRefresh": True}
                )
            )
            assert response == TOKEN_RESPONSE

    async def test_fetch_token_failure(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.outbound_application.fetch_token("app123", "user456")
                )

    async def test_fetch_tenant_token_by_scopes_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(TOKEN_RESPONSE)) as mock_post:
            response = await client.invoke(
                client.mgmt.outbound_application.fetch_tenant_token_by_scopes(
                    "app123", "tenant789", ["read", "write"], {"refreshToken": True}
                )
            )
            assert response == TOKEN_RESPONSE

    async def test_fetch_tenant_token_by_scopes_failure(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.outbound_application.fetch_tenant_token_by_scopes(
                        "app123", "tenant789", ["read"]
                    )
                )

    async def test_fetch_tenant_token_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(TOKEN_RESPONSE)) as mock_post:
            response = await client.invoke(
                client.mgmt.outbound_application.fetch_tenant_token(
                    "app123", "tenant789", {"forceRefresh": True}
                )
            )
            assert response == TOKEN_RESPONSE

    async def test_fetch_tenant_token_failure(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.outbound_application.fetch_tenant_token(
                        "app123", "tenant789"
                    )
                )

    def test_compose_create_update_body(self):
        body = OutboundApplication._compose_create_update_body(
            "Test App",
            "Test Description",
            "https://example.com/logo.png",
            "app123",
            "secret",
        )

        expected_body = {
            "name": "Test App",
            "id": "app123",
            "description": "Test Description",
            "logo": "https://example.com/logo.png",
            "clientSecret": "secret",
        }

        assert body == expected_body

    def test_compose_create_update_body_without_client_secret(self):
        body = OutboundApplication._compose_create_update_body(
            "Test App", "Test Description", "https://example.com/logo.png", "app123"
        )

        expected_body = {
            "name": "Test App",
            "id": "app123",
            "description": "Test Description",
            "logo": "https://example.com/logo.png",
        }

        assert body == expected_body

    def test_compose_create_update_body_with_all_new_parameters(self):
        auth_params = [
            URLParam("response_type", "code"),
            URLParam("client_id", "test-client"),
        ]
        token_params = [URLParam("grant_type", "authorization_code")]
        prompts = [PromptType.LOGIN, PromptType.CONSENT]

        body = OutboundApplication._compose_create_update_body(
            name="Test OAuth App",
            description="Test Description",
            logo="https://example.com/logo.png",
            id="app123",
            client_secret="secret",
            client_id="test-client-id",
            discovery_url="https://accounts.google.com/.well-known/openid_configuration",
            authorization_url="https://accounts.google.com/o/oauth2/v2/auth",
            authorization_url_params=auth_params,
            token_url="https://oauth2.googleapis.com/token",
            token_url_params=token_params,
            revocation_url="https://oauth2.googleapis.com/revoke",
            default_scopes=["https://www.googleapis.com/auth/userinfo.profile"],
            default_redirect_url="https://myapp.com/callback",
            callback_domain="myapp.com",
            pkce=True,
            access_type=AccessType.OFFLINE,
            prompt=prompts,
        )

        expected_body = {
            "name": "Test OAuth App",
            "id": "app123",
            "description": "Test Description",
            "logo": "https://example.com/logo.png",
            "clientSecret": "secret",
            "clientId": "test-client-id",
            "discoveryUrl": "https://accounts.google.com/.well-known/openid_configuration",
            "authorizationUrl": "https://accounts.google.com/o/oauth2/v2/auth",
            "authorizationUrlParams": [
                {"name": "response_type", "value": "code"},
                {"name": "client_id", "value": "test-client"},
            ],
            "tokenUrl": "https://oauth2.googleapis.com/token",
            "tokenUrlParams": [{"name": "grant_type", "value": "authorization_code"}],
            "revocationUrl": "https://oauth2.googleapis.com/revoke",
            "defaultScopes": ["https://www.googleapis.com/auth/userinfo.profile"],
            "defaultRedirectUrl": "https://myapp.com/callback",
            "callbackDomain": "myapp.com",
            "pkce": True,
            "accessType": "offline",
            "prompt": ["login", "consent"],
        }

        assert body == expected_body

    def test_compose_create_update_body_with_partial_new_parameters(self):
        body = OutboundApplication._compose_create_update_body(
            name="Test App",
            description="Test Description",
            logo="https://example.com/logo.png",
            id="app123",
            client_secret="secret",
            client_id="test-client-id",
            discovery_url="https://accounts.google.com/.well-known/openid_configuration",
            pkce=False,
            access_type=AccessType.ONLINE,
        )

        expected_body = {
            "name": "Test App",
            "id": "app123",
            "description": "Test Description",
            "logo": "https://example.com/logo.png",
            "clientSecret": "secret",
            "clientId": "test-client-id",
            "discoveryUrl": "https://accounts.google.com/.well-known/openid_configuration",
            "pkce": False,
            "accessType": "online",
        }

        assert body == expected_body

    def test_compose_create_update_body_with_url_params_only(self):
        auth_params = [URLParam("response_type", "code")]
        token_params = [URLParam("grant_type", "authorization_code")]

        body = OutboundApplication._compose_create_update_body(
            name="Test App",
            description="Test Description",
            authorization_url_params=auth_params,
            token_url_params=token_params,
        )

        expected_body = {
            "name": "Test App",
            "id": None,
            "description": "Test Description",
            "logo": None,
            "authorizationUrlParams": [{"name": "response_type", "value": "code"}],
            "tokenUrlParams": [{"name": "grant_type", "value": "authorization_code"}],
        }

        assert body == expected_body

    def test_compose_create_update_body_with_prompt_types(self):
        prompts = [PromptType.LOGIN, PromptType.CONSENT, PromptType.SELECT_ACCOUNT]

        body = OutboundApplication._compose_create_update_body(
            name="Test App", description="Test Description", prompt=prompts
        )

        expected_body = {
            "name": "Test App",
            "id": None,
            "description": "Test Description",
            "logo": None,
            "prompt": ["login", "consent", "select_account"],
        }

        assert body == expected_body

    def test_compose_create_update_body_with_none_values(self):
        body = OutboundApplication._compose_create_update_body(
            name="Test App",
            description="Test Description",
            pkce=None,
            access_type=None,
            prompt=None,
        )

        expected_body = {
            "name": "Test App",
            "id": None,
            "description": "Test Description",
            "logo": None,
        }

        assert body == expected_body

    def test_compose_create_update_body_with_empty_lists(self):
        body = OutboundApplication._compose_create_update_body(
            name="Test App",
            description="Test Description",
            authorization_url_params=[],
            token_url_params=[],
            default_scopes=[],
            prompt=[],
        )

        expected_body = {
            "name": "Test App",
            "id": None,
            "description": "Test Description",
            "logo": None,
            "authorizationUrlParams": [],
            "tokenUrlParams": [],
            "defaultScopes": [],
            "prompt": [],
        }

        assert body == expected_body

    async def test_delete_user_tokens_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_delete(make_response(status=200)) as mock_delete:
            await client.invoke(
                client.mgmt.outbound_application.delete_user_tokens(
                    app_id="app123", user_id="user456"
                )
            )
            assert_http_called(
                mock_delete,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.outbound_application_delete_user_tokens_path}",
                headers=MGMT_HEADERS,
                params={"appId": "app123", "userId": "user456"},
                follow_redirects=False,
            )

    async def test_delete_user_tokens_with_app_id_only(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_delete(make_response(status=200)) as mock_delete:
            await client.invoke(
                client.mgmt.outbound_application.delete_user_tokens(app_id="app123")
            )
            assert_http_called(
                mock_delete,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.outbound_application_delete_user_tokens_path}",
                headers=MGMT_HEADERS,
                params={"appId": "app123"},
                follow_redirects=False,
            )

    async def test_delete_user_tokens_with_user_id_only(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_delete(make_response(status=200)) as mock_delete:
            await client.invoke(
                client.mgmt.outbound_application.delete_user_tokens(user_id="user456")
            )
            assert_http_called(
                mock_delete,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.outbound_application_delete_user_tokens_path}",
                headers=MGMT_HEADERS,
                params={"userId": "user456"},
                follow_redirects=False,
            )

    async def test_delete_user_tokens_failure(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_delete(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.outbound_application.delete_user_tokens(
                        app_id="app123", user_id="user456"
                    )
                )

    async def test_delete_token_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_delete(make_response(status=200)) as mock_delete:
            await client.invoke(
                client.mgmt.outbound_application.delete_token("token123")
            )
            assert_http_called(
                mock_delete,
                client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.outbound_application_delete_token_path}",
                headers=MGMT_HEADERS,
                params={"id": "token123"},
                follow_redirects=False,
            )

    async def test_delete_token_failure(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_delete(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.outbound_application.delete_token("token123")
                )

    def test_url_param_to_dict(self):
        param = URLParam("test_name", "test_value")
        param_dict = param.to_dict()

        expected_dict = {"name": "test_name", "value": "test_value"}
        assert param_dict == expected_dict

    def test_access_type_enum_values(self):
        assert AccessType.OFFLINE.value == "offline"
        assert AccessType.ONLINE.value == "online"

    def test_prompt_type_enum_values(self):
        assert PromptType.NONE.value == "none"
        assert PromptType.LOGIN.value == "login"
        assert PromptType.CONSENT.value == "consent"
        assert PromptType.SELECT_ACCOUNT.value == "select_account"


class TestOutboundApplicationByToken:
    async def test_fetch_token_by_scopes_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False)

        with client.mock_mgmt_by_token_post(make_response(TOKEN_RESPONSE)) as mock_post:
            response = await client.invoke(
                client.mgmt.outbound_application_by_token.fetch_token_by_scopes(
                    DUMMY_TOKEN,
                    "app123",
                    "user456",
                    ["read", "write"],
                    {"refreshToken": True},
                    "tenant789",
                )
            )
            assert response == TOKEN_RESPONSE

    async def test_fetch_token_by_scopes_failure(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False)

        # Empty token should raise AuthException immediately (no HTTP call needed)
        with pytest.raises(AuthException):
            await client.invoke(
                client.mgmt.outbound_application_by_token.fetch_token_by_scopes(
                    "",
                    "app123",
                    "user456",
                    ["read"],
                )
            )

        # Invalid response failure
        with client.mock_mgmt_by_token_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.outbound_application_by_token.fetch_token_by_scopes(
                        DUMMY_TOKEN,
                        "app123",
                        "user456",
                        ["read"],
                    )
                )

    async def test_fetch_token_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False)

        with client.mock_mgmt_by_token_post(make_response(TOKEN_RESPONSE)) as mock_post:
            response = await client.invoke(
                client.mgmt.outbound_application_by_token.fetch_token(
                    DUMMY_TOKEN,
                    "app123",
                    "user456",
                    "tenant789",
                    {"forceRefresh": True},
                )
            )
            assert response == TOKEN_RESPONSE

    async def test_fetch_token_failure(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False)

        # Empty token should raise AuthException immediately
        with pytest.raises(AuthException):
            await client.invoke(
                client.mgmt.outbound_application_by_token.fetch_token(
                    "",
                    "app123",
                    "user456",
                )
            )

        # Invalid response failure
        with client.mock_mgmt_by_token_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.outbound_application_by_token.fetch_token(
                        DUMMY_TOKEN,
                        "app123",
                        "user456",
                    )
                )

    async def test_fetch_tenant_token_by_scopes_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False)

        with client.mock_mgmt_by_token_post(make_response(TOKEN_RESPONSE)) as mock_post:
            response = await client.invoke(
                client.mgmt.outbound_application_by_token.fetch_tenant_token_by_scopes(
                    DUMMY_TOKEN,
                    "app123",
                    "tenant789",
                    ["read", "write"],
                    {"refreshToken": True},
                )
            )
            assert response == TOKEN_RESPONSE

    async def test_fetch_tenant_token_by_scopes_failure(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False)

        # Empty token should raise AuthException immediately
        with pytest.raises(AuthException):
            await client.invoke(
                client.mgmt.outbound_application_by_token.fetch_tenant_token_by_scopes(
                    "",
                    "app123",
                    "tenant789",
                    ["read"],
                )
            )

        # Invalid response failure
        with client.mock_mgmt_by_token_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.outbound_application_by_token.fetch_tenant_token_by_scopes(
                        DUMMY_TOKEN,
                        "app123",
                        "tenant789",
                        ["read"],
                    )
                )

    async def test_fetch_tenant_token_success(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False)

        with client.mock_mgmt_by_token_post(make_response(TOKEN_RESPONSE)) as mock_post:
            response = await client.invoke(
                client.mgmt.outbound_application_by_token.fetch_tenant_token(
                    DUMMY_TOKEN, "app123", "tenant789", {"forceRefresh": True}
                )
            )
            assert response == TOKEN_RESPONSE

    async def test_fetch_tenant_token_failure(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False)

        # Empty token should raise AuthException immediately
        with pytest.raises(AuthException):
            await client.invoke(
                client.mgmt.outbound_application_by_token.fetch_tenant_token(
                    "",
                    "app123",
                    "tenant789",
                )
            )

        # Invalid response failure
        with client.mock_mgmt_by_token_post(make_response(status=500)):
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.outbound_application_by_token.fetch_tenant_token(
                        DUMMY_TOKEN,
                        "app123",
                        "tenant789",
                    )
                )
