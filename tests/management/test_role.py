import json
from unittest import mock
from unittest.mock import patch

from descope import AuthException, DescopeClient
from descope.common import DEFAULT_TIMEOUT_SECONDS
from descope.management.common import MgmtV1

from .. import common


class TestRole(common.DescopeTest):
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

    def test_create(self):
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
                client.mgmt.role.create,
                "name",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(client.mgmt.role.create("R1", "Something", ["P1"], "t1", True))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.role_create_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "name": "R1",
                    "description": "Something",
                    "permissionNames": ["P1"],
                    "tenantId": "t1",
                    "default": True,
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_update(self):
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
                client.mgmt.role.update,
                "name",
                "new-name",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.role.update(
                    "name",
                    "new-name",
                    "new-description",
                    ["P1", "P2"],
                    "t1",
                    True,
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.role_update_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "name": "name",
                    "newName": "new-name",
                    "description": "new-description",
                    "permissionNames": ["P1", "P2"],
                    "tenantId": "t1",
                    "default": True,
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_delete(self):
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
                client.mgmt.role.delete,
                "name",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(client.mgmt.role.delete("name"))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.role_delete_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={"name": "name", "tenantId": None},
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_load_all(self):
        client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

        # Test failed flows
        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = False
            self.assertRaises(AuthException, client.mgmt.role.load_all)

        # Test success flow
        with patch("requests.get") as mock_get:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """
                {
                    "roles": [
                        {"name": "R1", "permissionNames": ["P1", "P2"]},
                        {"name": "R2"}
                    ]
                }
                """
            )
            mock_get.return_value = network_resp
            resp = client.mgmt.role.load_all()
            roles = resp["roles"]
            self.assertEqual(len(roles), 2)
            self.assertEqual(roles[0]["name"], "R1")
            self.assertEqual(roles[1]["name"], "R2")
            permissions = roles[0]["permissionNames"]
            self.assertEqual(len(permissions), 2)
            self.assertEqual(permissions[0], "P1")
            self.assertEqual(permissions[1], "P2")
            mock_get.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.role_load_all_path}",
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

    def test_search(self):
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
                client.mgmt.role.search,
                ["t"],
                ["r"],
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """
                {
                    "roles": [
                        {"name": "R1", "permissionNames": ["P1", "P2"]},
                        {"name": "R2"}
                    ]
                }
                """
            )
            mock_post.return_value = network_resp
            resp = client.mgmt.role.search(["t"], ["r"], "x", ["p1", "p2"])
            roles = resp["roles"]
            self.assertEqual(len(roles), 2)
            self.assertEqual(roles[0]["name"], "R1")
            self.assertEqual(roles[1]["name"], "R2")
            permissions = roles[0]["permissionNames"]
            self.assertEqual(len(permissions), 2)
            self.assertEqual(permissions[0], "P1")
            self.assertEqual(permissions[1], "P2")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.role_search_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantIds": ["t"],
                    "roleNames": ["r"],
                    "roleNameLike": "x",
                    "permissionNames": ["p1", "p2"],
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
