import json
import unittest
from unittest import mock
from unittest.mock import patch

from descope import AuthException, DescopeClient, UserTenants


class TestUser(unittest.TestCase):
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
                client.mgmt.user.create,
                "valid-identifier",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.user.create(
                    identifier="name@mail.com",
                    email="name@mail.com",
                    display_name="Name",
                    user_tenants=[
                        UserTenants("tenant1"),
                        UserTenants("tenant2", ["role1", "role2"]),
                    ],
                )
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
                client.mgmt.user.update,
                "valid-identifier",
                "email@something.com",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                client.mgmt.user.update(
                    "identifier",
                    display_name="new-name",
                    role_names=["domain.com"],
                )
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
                client.mgmt.user.delete,
                "valid-id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(client.mgmt.user.delete("t1"))

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
                client.mgmt.user.load,
                "valid-id",
            )

        # Test success flow
        with patch("requests.get") as mock_get:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_get.return_value = network_resp
            resp = client.mgmt.user.load("valid-id")
            user = resp["user"]
            self.assertEqual(user["id"], "u1")

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
                client.mgmt.user.searchAllUsers,
                ["t1, t2"],
                ["r1", "r2"],
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{"users": [{"id": "u1"}, {"id": "u2"}]}"""
            )
            mock_post.return_value = network_resp
            resp = client.mgmt.user.searchAllUsers(["t1, t2"], ["r1", "r2"])
            users = resp["users"]
            self.assertEqual(len(users), 2)
            self.assertEqual(users[0]["id"], "u1")
            self.assertEqual(users[1]["id"], "u2")
