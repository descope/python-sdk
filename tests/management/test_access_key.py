import json
from unittest import mock
from unittest.mock import patch

from descope import AssociatedTenant, AuthException, DescopeClient
from descope.management.common import MgmtV1

from .. import common


class TestAccessKey(common.DescopeTest):
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
                client.mgmt.access_key.create,
                "key-name",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{"key": {"id": "ak1"}, "cleartext": "abc"}"""
            )
            mock_post.return_value = network_resp
            resp = client.mgmt.access_key.create(
                name="key-name",
                expire_time=123456789,
                key_tenants=[
                    AssociatedTenant("tenant1"),
                    AssociatedTenant("tenant2", ["role1", "role2"]),
                ],
            )
            access_key = resp["key"]
            self.assertEqual(access_key["id"], "ak1")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.access_key_create_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "name": "key-name",
                        "expireTime": 123456789,
                        "roleNames": [],
                        "keyTenants": [
                            {"tenantId": "tenant1", "roleNames": []},
                            {"tenantId": "tenant2", "roleNames": ["role1", "role2"]},
                        ],
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_load(self):
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
                client.mgmt.access_key.load,
                "key-id",
            )

        # Test success flow
        with patch("requests.get") as mock_get:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"key": {"id": "ak1"}}""")
            mock_get.return_value = network_resp
            resp = client.mgmt.access_key.load("key-id")
            access_key = resp["key"]
            self.assertEqual(access_key["id"], "ak1")
            mock_get.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.access_key_load_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params={"id": "key-id"},
                allow_redirects=None,
                verify=True,
            )

    def test_search_all_users(self):
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
                client.mgmt.access_key.search_all_access_keys,
                ["t1, t2"],
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{"keys": [{"id": "ak1"}, {"id": "ak2"}]}"""
            )
            mock_post.return_value = network_resp
            resp = client.mgmt.access_key.search_all_access_keys(["t1, t2"])
            keys = resp["keys"]
            self.assertEqual(len(keys), 2)
            self.assertEqual(keys[0]["id"], "ak1")
            self.assertEqual(keys[1]["id"], "ak2")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.access_keys_search_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "tenantIds": ["t1, t2"],
                    }
                ),
                allow_redirects=False,
                verify=True,
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
                client.mgmt.access_key.update,
                "key-id",
                "new-name",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.access_key.update(
                    "key-id",
                    name="new-name",
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.access_key_update_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "id": "key-id",
                        "name": "new-name",
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_deactivate(self):
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
                client.mgmt.access_key.deactivate,
                "key-id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(client.mgmt.access_key.deactivate("ak1"))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.access_key_deactivate_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "id": "ak1",
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_activate(self):
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
                client.mgmt.access_key.activate,
                "key-id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(client.mgmt.access_key.activate("ak1"))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.access_key_activate_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "id": "ak1",
                    }
                ),
                allow_redirects=False,
                verify=True,
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
                client.mgmt.access_key.delete,
                "key-id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(client.mgmt.access_key.delete("ak1"))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.access_key_delete_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "id": "ak1",
                    }
                ),
                allow_redirects=False,
                verify=True,
            )
