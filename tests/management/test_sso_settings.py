import json
from unittest.mock import patch

from descope import AttributeMapping, AuthException, DescopeClient, RoleMapping
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
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_configure_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "tenantId": "tenant-id",
                        "idpURL": "https://idp.com",
                        "entityId": "entity-id",
                        "idpCert": "cert",
                        "redirectURL": "https://redirect.com",
                        "domain": "domain.com",
                    }
                ),
                allow_redirects=False,
                verify=True,
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
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_configure_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "tenantId": "tenant-id",
                        "idpURL": "https://idp.com",
                        "entityId": "entity-id",
                        "idpCert": "cert",
                        "redirectURL": "https://redirect.com",
                        "domain": None,
                    }
                ),
                allow_redirects=False,
                verify=True,
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
                f"{common.DEFAULT_BASE_URL}{MgmtV1.sso_configure_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "tenantId": "tenant-id",
                        "idpURL": "https://idp.com",
                        "entityId": "entity-id",
                        "idpCert": "cert",
                        "redirectURL": None,
                        "domain": "domain.com",
                    }
                ),
                allow_redirects=False,
                verify=True,
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
                data=json.dumps(
                    {
                        "tenantId": "tenant-id",
                        "idpMetadataURL": "https://idp-meta.com",
                    }
                ),
                allow_redirects=False,
                verify=True,
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
                data=json.dumps(
                    {
                        "tenantId": "tenant-id",
                        "roleMappings": [{"groups": ["a", "b"], "roleName": "role"}],
                        "attributeMapping": {
                            "name": "UName",
                            "email": None,
                            "phoneNumber": None,
                            "group": None,
                        },
                    }
                ),
                allow_redirects=False,
                verify=True,
            )
