import json
from unittest import mock
from unittest.mock import patch

import pytest

from descope import AuthException, DescopeClient
from descope.management.outbound_application import OutboundApplication
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
                "app": {"id": "app123", "name": "Test App", "description": "Test Description"}
            }
            mock_post.return_value = network_resp
            response = client.mgmt.outbound_application.create_application(
                "Test App", description="Test Description", client_secret="secret"
            )

            assert response == {
                "app": {"id": "app123", "name": "Test App", "description": "Test Description"}
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
                "app": {"id": "app123", "name": "Updated App", "description": "Updated Description"}
            }
            mock_post.return_value = network_resp
            response = client.mgmt.outbound_application.update_application(
                "app123", "Updated App", description="Updated Description", client_secret="new-secret"
            )

            assert response == {
                "app": {"id": "app123", "name": "Updated App", "description": "Updated Description"}
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
                "app": {"id": "app123", "name": "Test App", "description": "Test Description"}
            }
            mock_get.return_value = network_resp
            response = client.mgmt.outbound_application.load_application("app123")

            assert response == {
                "app": {"id": "app123", "name": "Test App", "description": "Test Description"}
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
                "app123", "user456", ["read", "write"], {"refreshToken": True}, "tenant789"
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
            "Test App", "Test Description", "https://example.com/logo.png", "app123", "secret"
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