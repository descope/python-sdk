from unittest import mock
from unittest.mock import patch

from descope import AuthException, DescopeClient
from descope.management.common import AccessType, PromptType, URLParam
from descope.management.outbound_application import OutboundApplication

from .. import common


class TestOutboundApplication(common.DescopeTest):
    def setUp(self) -> None:
        super().setUp()
        self.dummy_project_id = "dummy"
        self.dummy_management_key = "key"
        self.public_key_dict = {
            "alg": "ES384",
            "crv": "P-384",
            "kid": "P2CtzUhdqpIF2ys9gg7ms06UvtC4",
            "kty": "EC",
            "use": "sig",
            "x": "pX1l7nT2turcK5_Cdzos8SKIhpLh1Wy9jmKAVyMFiOCURoj-WQX1J0OUQqMsQO0s",
            "y": "B0_nWAv2pmG_PzoH3-bSYZZzLNKUA0RoE2SH7DaS0KV4rtfWZhYd0MEr0xfdGKx0",
        }

    def test_create_application_success(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = {
                "app": {
                    "id": "app123",
                    "name": "Test App",
                    "description": "Test Description",
                }
            }
            mock_post.return_value = network_resp
            response = client.mgmt.outbound_application.create_application(
                "Test App", description="Test Description", client_secret="secret"
            )

            assert response == {
                "app": {
                    "id": "app123",
                    "name": "Test App",
                    "description": "Test Description",
                }
            }

    def test_create_application_with_all_parameters_success(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Create test data for all new parameters
        auth_params = [
            URLParam("response_type", "code"),
            URLParam("client_id", "test-client"),
        ]
        token_params = [URLParam("grant_type", "authorization_code")]
        prompts = [PromptType.LOGIN, PromptType.CONSENT]

        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = {
                "app": {
                    "id": "app123",
                    "name": "Test OAuth App",
                    "description": "Test Description",
                }
            }
            mock_post.return_value = network_resp
            response = client.mgmt.outbound_application.create_application(
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

            assert response == {
                "app": {
                    "id": "app123",
                    "name": "Test OAuth App",
                    "description": "Test Description",
                }
            }

    def test_create_application_failure(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application.create_application,
                "Test App",
            )

    def test_update_application_success(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = {
                "app": {
                    "id": "app123",
                    "name": "Updated App",
                    "description": "Updated Description",
                }
            }
            mock_post.return_value = network_resp
            response = client.mgmt.outbound_application.update_application(
                "app123",
                "Updated App",
                description="Updated Description",
                client_secret="new-secret",
            )

            assert response == {
                "app": {
                    "id": "app123",
                    "name": "Updated App",
                    "description": "Updated Description",
                }
            }

    def test_update_application_with_all_parameters_success(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Create test data for all new parameters
        auth_params = [
            URLParam("response_type", "code"),
            URLParam("client_id", "test-client"),
        ]
        token_params = [URLParam("grant_type", "authorization_code")]
        prompts = [PromptType.LOGIN, PromptType.CONSENT, PromptType.SELECT_ACCOUNT]

        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = {
                "app": {
                    "id": "app123",
                    "name": "Updated OAuth App",
                    "description": "Updated Description",
                }
            }
            mock_post.return_value = network_resp
            response = client.mgmt.outbound_application.update_application(
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

            assert response == {
                "app": {
                    "id": "app123",
                    "name": "Updated OAuth App",
                    "description": "Updated Description",
                }
            }

    def test_update_application_failure(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application.update_application,
                "app123",
                "Updated App",
            )

    def test_delete_application_success(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            mock_post.return_value = network_resp
            client.mgmt.outbound_application.delete_application("app123")

    def test_delete_application_failure(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application.delete_application,
                "app123",
            )

    def test_load_application_success(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        with patch("requests.get") as mock_get:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = {
                "app": {
                    "id": "app123",
                    "name": "Test App",
                    "description": "Test Description",
                }
            }
            mock_get.return_value = network_resp
            response = client.mgmt.outbound_application.load_application("app123")

            assert response == {
                "app": {
                    "id": "app123",
                    "name": "Test App",
                    "description": "Test Description",
                }
            }

    def test_load_application_failure(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application.load_application,
                "app123",
            )

    def test_load_all_applications_success(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        with patch("requests.get") as mock_get:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = {
                "apps": [
                    {"id": "app1", "name": "App 1", "description": "Description 1"},
                    {"id": "app2", "name": "App 2", "description": "Description 2"},
                ]
            }
            mock_get.return_value = network_resp
            response = client.mgmt.outbound_application.load_all_applications()

            assert response == {
                "apps": [
                    {"id": "app1", "name": "App 1", "description": "Description 1"},
                    {"id": "app2", "name": "App 2", "description": "Description 2"},
                ]
            }

    def test_load_all_applications_failure(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application.load_all_applications,
            )

    def test_fetch_token_by_scopes_success(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = {
                "token": {
                    "token": "access-token",
                    "refreshToken": "refresh-token",
                    "expiresIn": 3600,
                    "tokenType": "Bearer",
                    "scopes": ["read", "write"],
                }
            }
            mock_post.return_value = network_resp
            response = client.mgmt.outbound_application.fetch_token_by_scopes(
                "app123",
                "user456",
                ["read", "write"],
                {"refreshToken": True},
                "tenant789",
            )

            assert response == {
                "token": {
                    "token": "access-token",
                    "refreshToken": "refresh-token",
                    "expiresIn": 3600,
                    "tokenType": "Bearer",
                    "scopes": ["read", "write"],
                }
            }

    def test_fetch_token_by_scopes_failure(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application.fetch_token_by_scopes,
                "app123",
                "user456",
                ["read"],
            )

    def test_fetch_token_success(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = {
                "token": {
                    "token": "access-token",
                    "refreshToken": "refresh-token",
                    "expiresIn": 3600,
                    "tokenType": "Bearer",
                    "scopes": ["read", "write"],
                }
            }
            mock_post.return_value = network_resp
            response = client.mgmt.outbound_application.fetch_token(
                "app123", "user456", "tenant789", {"forceRefresh": True}
            )

            assert response == {
                "token": {
                    "token": "access-token",
                    "refreshToken": "refresh-token",
                    "expiresIn": 3600,
                    "tokenType": "Bearer",
                    "scopes": ["read", "write"],
                }
            }

    def test_fetch_token_failure(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application.fetch_token,
                "app123",
                "user456",
            )

    def test_fetch_tenant_token_by_scopes_success(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = {
                "token": {
                    "token": "access-token",
                    "refreshToken": "refresh-token",
                    "expiresIn": 3600,
                    "tokenType": "Bearer",
                    "scopes": ["read", "write"],
                }
            }
            mock_post.return_value = network_resp
            response = client.mgmt.outbound_application.fetch_tenant_token_by_scopes(
                "app123", "tenant789", ["read", "write"], {"refreshToken": True}
            )

            assert response == {
                "token": {
                    "token": "access-token",
                    "refreshToken": "refresh-token",
                    "expiresIn": 3600,
                    "tokenType": "Bearer",
                    "scopes": ["read", "write"],
                }
            }

    def test_fetch_tenant_token_by_scopes_failure(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application.fetch_tenant_token_by_scopes,
                "app123",
                "tenant789",
                ["read"],
            )

    def test_fetch_tenant_token_success(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = {
                "token": {
                    "token": "access-token",
                    "refreshToken": "refresh-token",
                    "expiresIn": 3600,
                    "tokenType": "Bearer",
                    "scopes": ["read", "write"],
                }
            }
            mock_post.return_value = network_resp
            response = client.mgmt.outbound_application.fetch_tenant_token(
                "app123", "tenant789", {"forceRefresh": True}
            )

            assert response == {
                "token": {
                    "token": "access-token",
                    "refreshToken": "refresh-token",
                    "expiresIn": 3600,
                    "tokenType": "Bearer",
                    "scopes": ["read", "write"],
                }
            }

    def test_fetch_tenant_token_failure(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application.fetch_tenant_token,
                "app123",
                "tenant789",
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
        # Create test data for all new parameters
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
        # Test with only some of the new parameters
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
        # Test with only URL parameters
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
        # Test with different prompt type combinations
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
        # Test that None values are handled correctly
        body = OutboundApplication._compose_create_update_body(
            name="Test App",
            description="Test Description",
            pkce=None,  # Should not be included in body
            access_type=None,  # Should not be included in body
            prompt=None,  # Should not be included in body
        )

        expected_body = {
            "name": "Test App",
            "id": None,
            "description": "Test Description",
            "logo": None,
        }

        assert body == expected_body

    def test_compose_create_update_body_with_empty_lists(self):
        # Test with empty lists for URL parameters and prompts
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

    def test_url_param_to_dict(self):
        # Test URLParam to_dict method
        param = URLParam("test_name", "test_value")
        param_dict = param.to_dict()

        expected_dict = {"name": "test_name", "value": "test_value"}
        assert param_dict == expected_dict

    def test_access_type_enum_values(self):
        # Test AccessType enum values
        assert AccessType.OFFLINE.value == "offline"
        assert AccessType.ONLINE.value == "online"

    def test_prompt_type_enum_values(self):
        # Test PromptType enum values
        assert PromptType.NONE.value == "none"
        assert PromptType.LOGIN.value == "login"
        assert PromptType.CONSENT.value == "consent"
        assert PromptType.SELECT_ACCOUNT.value == "select_account"


class TestOutboundApplicationByToken(common.DescopeTest):
    def setUp(self) -> None:
        super().setUp()
        self.dummy_project_id = "dummy"
        self.dummy_token = "inbound-app-token"
        self.public_key_dict = {
            "alg": "ES384",
            "crv": "P-384",
            "kid": "P2CtzUhdqpIF2ys9gg7ms06UvtC4",
            "kty": "EC",
            "use": "sig",
            "x": "pX1l7nT2turcK5_Cdzos8SKIhpLh1Wy9jmKAVyMFiOCURoj-WQX1J0OUQqMsQO0s",
            "y": "B0_nWAv2pmG_PzoH3-bSYZZzLNKUA0RoE2SH7DaS0KV4rtfWZhYd0MEr0xfdGKx0",
        }

    def test_fetch_token_by_scopes_success(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict, False)

        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = {
                "token": {
                    "token": "access-token",
                    "refreshToken": "refresh-token",
                    "expiresIn": 3600,
                    "tokenType": "Bearer",
                    "scopes": ["read", "write"],
                }
            }
            mock_post.return_value = network_resp
            response = client.mgmt.outbound_application_by_token.fetch_token_by_scopes(
                self.dummy_token,
                "app123",
                "user456",
                ["read", "write"],
                {"refreshToken": True},
                "tenant789",
            )

            assert response == {
                "token": {
                    "token": "access-token",
                    "refreshToken": "refresh-token",
                    "expiresIn": 3600,
                    "tokenType": "Bearer",
                    "scopes": ["read", "write"],
                }
            }

    def test_fetch_token_by_scopes_failure(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict, False)

        # Test failure of empty token
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application_by_token.fetch_token_by_scopes,
                "",  # empty token
                "app123",
                "user456",
                ["read"],
            )

        # Test invalid response failure
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application_by_token.fetch_token_by_scopes,
                self.dummy_token,
                "app123",
                "user456",
                ["read"],
            )

    def test_fetch_token_success(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict, False)

        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = {
                "token": {
                    "token": "access-token",
                    "refreshToken": "refresh-token",
                    "expiresIn": 3600,
                    "tokenType": "Bearer",
                    "scopes": ["read", "write"],
                }
            }
            mock_post.return_value = network_resp
            response = client.mgmt.outbound_application_by_token.fetch_token(
                self.dummy_token,
                "app123",
                "user456",
                "tenant789",
                {"forceRefresh": True},
            )

            assert response == {
                "token": {
                    "token": "access-token",
                    "refreshToken": "refresh-token",
                    "expiresIn": 3600,
                    "tokenType": "Bearer",
                    "scopes": ["read", "write"],
                }
            }

    def test_fetch_token_failure(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict, False)

        # Test failure of empty token
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application_by_token.fetch_token,
                "",  # empty token
                "app123",
                "user456",
            )

        # Test invalid response failure
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application_by_token.fetch_token,
                self.dummy_token,
                "app123",
                "user456",
            )

    def test_fetch_tenant_token_by_scopes_success(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict, False)

        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = {
                "token": {
                    "token": "access-token",
                    "refreshToken": "refresh-token",
                    "expiresIn": 3600,
                    "tokenType": "Bearer",
                    "scopes": ["read", "write"],
                }
            }
            mock_post.return_value = network_resp
            response = (
                client.mgmt.outbound_application_by_token.fetch_tenant_token_by_scopes(
                    self.dummy_token,
                    "app123",
                    "tenant789",
                    ["read", "write"],
                    {"refreshToken": True},
                )
            )

            assert response == {
                "token": {
                    "token": "access-token",
                    "refreshToken": "refresh-token",
                    "expiresIn": 3600,
                    "tokenType": "Bearer",
                    "scopes": ["read", "write"],
                }
            }

    def test_fetch_tenant_token_by_scopes_failure(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict, False)

        # Test failure of empty token
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application_by_token.fetch_tenant_token_by_scopes,
                "",  # empty token
                "app123",
                "tenant789",
                ["read"],
            )

        # Test invalid response failure
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application_by_token.fetch_tenant_token_by_scopes,
                self.dummy_token,
                "app123",
                "tenant789",
                ["read"],
            )

    def test_fetch_tenant_token_success(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict, False)

        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = {
                "token": {
                    "token": "access-token",
                    "refreshToken": "refresh-token",
                    "expiresIn": 3600,
                    "tokenType": "Bearer",
                    "scopes": ["read", "write"],
                }
            }
            mock_post.return_value = network_resp
            response = client.mgmt.outbound_application_by_token.fetch_tenant_token(
                self.dummy_token, "app123", "tenant789", {"forceRefresh": True}
            )

            assert response == {
                "token": {
                    "token": "access-token",
                    "refreshToken": "refresh-token",
                    "expiresIn": 3600,
                    "tokenType": "Bearer",
                    "scopes": ["read", "write"],
                }
            }

    def test_fetch_tenant_token_failure(self):
        client = DescopeClient(self.dummy_project_id, self.public_key_dict, False)

        # Test failure of empty token
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application_by_token.fetch_tenant_token,
                "",  # empty token
                "app123",
                "tenant789",
            )

        # Test invalid response failure
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application_by_token.fetch_tenant_token,
                self.dummy_token,
                "app123",
                "tenant789",
            )
