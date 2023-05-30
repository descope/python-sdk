import json
from unittest import mock
from unittest.mock import patch

from descope import AttributeMapping, AuthException, DescopeClient, RoleMapping
from descope.common import DEFAULT_TIMEOUT_SECONDS
from descope.management.common import MgmtV1

from .. import common


class TestSSOSettings(common.DescopeTest):
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

    def test_get_settings(self):
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
                client.mgmt.sso.get_settings,
                "tenant-id",
            )

        # Test success flow
        with patch("requests.get") as mock_get:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{"domain": "lulu", "tenantId": "tenant-id"}"""
            )
            mock_get.return_value = network_resp
            resp = client.mgmt.sso.get_settings("tenant-id")
            self.assertEqual(resp["tenantId"], "tenant-id")
            self.assertEqual(resp["domain"], "lulu")
            mock_get.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_settings_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params={"tenantId": "tenant-id"},
                allow_redirects=None,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_delete_settings(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.delete") as mock_delete:
            mock_delete.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.sso.delete_settings,
                "tenant-id",
            )

        # Test success flow
        with patch("requests.delete") as mock_delete:
            network_resp = mock.Mock()
            network_resp.ok = True

            mock_delete.return_value = network_resp
            client.mgmt.sso.delete_settings("tenant-id")

            mock_delete.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_settings_path}",
                params={"tenantId": "tenant-id"},
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_configure(self):
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
                client.mgmt.sso.configure,
                "tenant-id",
                "https://idp.com",
                "entity-id",
                "cert",
                "https://redirect.com",
                "domain.com",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.sso.configure(
                    "tenant-id",
                    "https://idp.com",
                    "entity-id",
                    "cert",
                    "https://redirect.com",
                    "domain.com",
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_settings_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={
                    "tenantId": "tenant-id",
                    "idpURL": "https://idp.com",
                    "entityId": "entity-id",
                    "idpCert": "cert",
                    "redirectURL": "https://redirect.com",
                    "domain": "domain.com",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Domain is optional
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.sso.configure(
                    "tenant-id",
                    "https://idp.com",
                    "entity-id",
                    "cert",
                    "https://redirect.com",
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_settings_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={
                    "tenantId": "tenant-id",
                    "idpURL": "https://idp.com",
                    "entityId": "entity-id",
                    "idpCert": "cert",
                    "redirectURL": "https://redirect.com",
                    "domain": None,
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Redirect is optional
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.sso.configure(
                    "tenant-id",
                    "https://idp.com",
                    "entity-id",
                    "cert",
                    domain="domain.com",
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_settings_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={
                    "tenantId": "tenant-id",
                    "idpURL": "https://idp.com",
                    "entityId": "entity-id",
                    "idpCert": "cert",
                    "redirectURL": None,
                    "domain": "domain.com",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_configure_via_metadata(self):
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
                client.mgmt.sso.configure_via_metadata,
                "tenant-id",
                "https://idp-meta.com",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.sso.configure_via_metadata(
                    "tenant-id",
                    "https://idp-meta.com",
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_metadata_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={
                    "tenantId": "tenant-id",
                    "idpMetadataURL": "https://idp-meta.com",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_mapping(self):
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
                client.mgmt.sso.mapping,
                "tenant-id",
                [RoleMapping(["a", "b"], "role")],
                AttributeMapping(name="UName"),
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.sso.mapping(
                    "tenant-id",
                    [RoleMapping(["a", "b"], "role")],
                    AttributeMapping(name="UName"),
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_mapping_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={
                    "tenantId": "tenant-id",
                    "roleMappings": [{"groups": ["a", "b"], "roleName": "role"}],
                    "attributeMapping": {
                        "name": "UName",
                        "email": None,
                        "phoneNumber": None,
                        "group": None,
                    },
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
