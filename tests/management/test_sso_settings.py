import unittest
from unittest.mock import patch

from descope import AttributeMapping, AuthException, DescopeClient, RoleMapping


class TestSSOSettings(unittest.TestCase):
    def setUp(self) -> None:
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
                )
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
                )
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

    # DEPRECATED

    def test_role_mapping(self):
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
                client.mgmt.sso.map_roles,
                "tenant-id",
                [RoleMapping(["a", "b"], "role")],
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.sso.map_roles(
                    "tenant-id",
                    [RoleMapping(["a", "b"], "role")],
                )
            )
