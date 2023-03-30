import json
import unittest
from unittest.mock import patch

import common

from descope import AuthException, DescopeClient
from descope.common import DEFAULT_BASE_URL
from descope.management.common import MgmtV1


class TestFlow(unittest.TestCase):
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

    def test_export_flow(self):
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
                client.mgmt.flow.export_flow,
                "name",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(client.mgmt.flow.export_flow("test"))
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.flow_export_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "flowId": "test",
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_import_flow(self):
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
                client.mgmt.flow.import_flow,
                "name",
                { "name": "test" },
                [{ "id": "test" }]
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.flow.import_flow(
                    "name",
                { "name": "test" },
                [{ "id": "test" }]
                )
            )
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.flow_import_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "flowId": "name",
                        "flow": { "name": "test" },
                        "screens": [{ "id": "test" }],
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_export_theme(self):
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
                client.mgmt.flow.export_theme
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(client.mgmt.flow.export_theme())
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.theme_export_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {}
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_import_theme(self):
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
                client.mgmt.flow.import_theme,
                {"id": "test"}
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.flow.import_theme(
                { "id": "test" }
                )
            )
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.theme_import_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "theme": { "id": "test" }
                    }
                ),
                allow_redirects=False,
                verify=True,
            )
