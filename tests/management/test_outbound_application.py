import json
from unittest import mock
from unittest.mock import patch

from descope import (
    AuthException,
    DescopeClient,
)
from descope.common import DEFAULT_TIMEOUT_SECONDS
from descope.management.common import MgmtV1

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

    def test_create_application(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application.create_application,
                "valid-name",
                "client-id",
                "client-secret",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"app": {"id": "app1", "name": "Test App"}}""")
            mock_post.return_value = network_resp
            resp = client.mgmt.outbound_application.create_application(
                name="Test App",
                client_id="test-client-id",
                client_secret="test-client-secret",
                description="Test description",
                template_id="google",
                default_scopes=["openid", "profile"],
                pkce=True,
                access_type="offline",
            )
            self.assertEqual(resp["app"]["id"], "app1")
            self.assertEqual(resp["app"]["name"], "Test App")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.outbound_application_create_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "id": None,
                    "name": "Test App",
                    "description": "Test description",
                    "templateId": "google",
                    "clientId": "test-client-id",
                    "clientSecret": "test-client-secret",
                    "logo": None,
                    "discoveryUrl": None,
                    "authorizationUrl": None,
                    "authorizationUrlParams": [],
                    "tokenUrl": None,
                    "tokenUrlParams": [],
                    "revocationUrl": None,
                    "defaultScopes": ["openid", "profile"],
                    "defaultRedirectUrl": None,
                    "callbackDomain": None,
                    "pkce": True,
                    "accessType": "offline",
                    "prompt": [],
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_update_application(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application.update_application,
                "app1",
                "valid-name",
                "client-id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"app": {"id": "app1", "name": "Updated App"}}""")
            mock_post.return_value = network_resp
            resp = client.mgmt.outbound_application.update_application(
                id="app1",
                name="Updated App",
                client_id="updated-client-id",
                description="Updated description",
            )
            self.assertEqual(resp["app"]["id"], "app1")
            self.assertEqual(resp["app"]["name"], "Updated App")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.outbound_application_update_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "app": {
                        "id": "app1",
                        "name": "Updated App",
                        "description": "Updated description",
                        "templateId": None,
                        "clientId": "updated-client-id",
                        "logo": None,
                        "discoveryUrl": None,
                        "authorizationUrl": None,
                        "authorizationUrlParams": [],
                        "tokenUrl": None,
                        "tokenUrlParams": [],
                        "revocationUrl": None,
                        "defaultScopes": [],
                        "defaultRedirectUrl": None,
                        "callbackDomain": None,
                        "pkce": None,
                        "accessType": None,
                        "prompt": [],
                    }
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_delete_application(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application.delete_application,
                "valid-id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(client.mgmt.outbound_application.delete_application("app1"))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.outbound_application_delete_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "id": "app1",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_load_application(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application.load_application,
                "valid-id",
            )

        # Test success flow
        with patch("requests.get") as mock_get:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """
                {"app": {"id":"app1","name":"Test App","description":"Test description","templateId":"google","clientId":"test-client-id","defaultScopes":["openid","profile"],"pkce":true,"accessType":"offline"}}
                """
            )
            mock_get.return_value = network_resp
            resp = client.mgmt.outbound_application.load_application("app1")
            self.assertEqual(resp["app"]["name"], "Test App")
            self.assertEqual(resp["app"]["templateId"], "google")
            self.assertEqual(resp["app"]["clientId"], "test-client-id")
            self.assertEqual(resp["app"]["defaultScopes"], ["openid", "profile"])
            self.assertTrue(resp["app"]["pkce"])
            self.assertEqual(resp["app"]["accessType"], "offline")
            mock_get.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.outbound_application_load_path}/app1",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                allow_redirects=None,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_load_all_applications(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = False
            self.assertRaises(AuthException, client.mgmt.outbound_application.load_all_applications)

        # Test success flow
        with patch("requests.get") as mock_get:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """
                {
                    "apps": [
                        {"id":"app1","name":"Test App 1","templateId":"google","clientId":"client1"},
                        {"id":"app2","name":"Test App 2","templateId":"microsoft","clientId":"client2"}
                    ]
                }
                """
            )
            mock_get.return_value = network_resp
            resp = client.mgmt.outbound_application.load_all_applications()
            apps = resp["apps"]
            self.assertEqual(len(apps), 2)
            self.assertEqual(apps[0]["name"], "Test App 1")
            self.assertEqual(apps[0]["templateId"], "google")
            self.assertEqual(apps[1]["name"], "Test App 2")
            self.assertEqual(apps[1]["templateId"], "microsoft")
            mock_get.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.outbound_application_load_all_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                allow_redirects=None,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_fetch_outbound_app_user_token(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application.fetch_outbound_app_user_token,
                "user123",
                "app1",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{"token": {"accessToken": "access123", "refreshToken": "refresh456", "scopes": ["openid", "profile"]}}"""
            )
            mock_post.return_value = network_resp
            resp = client.mgmt.outbound_application.fetch_outbound_app_user_token(
                user_id="user123",
                app_id="app1",
                scopes=["openid", "profile"],
            )
            self.assertEqual(resp["token"]["accessToken"], "access123")
            self.assertEqual(resp["token"]["refreshToken"], "refresh456")
            self.assertEqual(resp["token"]["scopes"], ["openid", "profile"])
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.outbound_application_fetch_user_token_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "userId": "user123",
                    "appId": "app1",
                    "scopes": ["openid", "profile"],
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_delete_outbound_app_token_by_id(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application.delete_outbound_app_token_by_id,
                "token123",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.outbound_application.delete_outbound_app_token_by_id("token123")
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.outbound_application_delete_token_by_id_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tokenId": "token123",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_delete_outbound_app_user_tokens(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.outbound_application.delete_outbound_app_user_tokens,
                "user123",
                "app1",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.outbound_application.delete_outbound_app_user_tokens("user123", "app1")
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.outbound_application_delete_user_tokens_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "userId": "user123",
                    "appId": "app1",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
