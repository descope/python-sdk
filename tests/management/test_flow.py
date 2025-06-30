from unittest.mock import patch

from descope import AuthException, DescopeClient
from descope.common import DEFAULT_TIMEOUT_SECONDS
from descope.management.common import MgmtV1

from .. import common


class TestFlow(common.DescopeTest):
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

    def test_list_flows(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("httpx.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.flow.list_flows,
            )

        # Test success flow
        with patch("httpx.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(client.mgmt.flow.list_flows())
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.flow_list_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json=None,
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_delete_flows(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed delete flows
        with patch("httpx.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.flow.delete_flows,
                ["flow-1", "flow-2"],
            )

        # Test success delete flows
        with patch("httpx.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(client.mgmt.flow.delete_flows(["flow-1", "flow-2"]))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.flow_delete_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"ids": ["flow-1", "flow-2"]},
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_export_flow(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("httpx.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.flow.export_flow,
                "name",
            )

        # Test success flow
        with patch("httpx.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(client.mgmt.flow.export_flow("test"))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.flow_export_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "flowId": "test",
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_import_flow(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("httpx.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                client.mgmt.flow.import_flow,
                "name",
                {"name": "test"},
                [{"id": "test"}],
            )

        # Test success flow
        with patch("httpx.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(
                client.mgmt.flow.import_flow("name", {"name": "test"}, [{"id": "test"}])
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.flow_import_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "flowId": "name",
                    "flow": {"name": "test"},
                    "screens": [{"id": "test"}],
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_export_theme(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("httpx.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(AuthException, client.mgmt.flow.export_theme)

        # Test success flow
        with patch("httpx.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(client.mgmt.flow.export_theme())
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.theme_export_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={},
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_import_theme(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("httpx.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException, client.mgmt.flow.import_theme, {"id": "test"}
            )

        # Test success flow
        with patch("httpx.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNotNone(client.mgmt.flow.import_theme({"id": "test"}))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.theme_import_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"theme": {"id": "test"}},
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
