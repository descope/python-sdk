import json
import unittest
from unittest import mock
from unittest.mock import patch

import common

from descope import AssociatedTenant, AuthException, DescopeClient
from descope.common import DEFAULT_BASE_URL
from descope.management.common import MgmtV1


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
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_post.return_value = network_resp
            resp = client.mgmt.user.create(
                identifier="name@mail.com",
                email="name@mail.com",
                display_name="Name",
                user_tenants=[
                    AssociatedTenant("tenant1"),
                    AssociatedTenant("tenant2", ["role1", "role2"]),
                ],
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.userCreatePath}",
                headers={
                    **common.defaultHeaders,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "identifier": "name@mail.com",
                        "email": "name@mail.com",
                        "phoneNumber": None,
                        "displayName": "Name",
                        "roleNames": [],
                        "userTenants": [
                            {"tenantId": "tenant1", "roleNames": []},
                            {"tenantId": "tenant2", "roleNames": ["role1", "role2"]},
                        ],
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
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.userUpdatePath}",
                headers={
                    **common.defaultHeaders,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "identifier": "identifier",
                        "email": None,
                        "phoneNumber": None,
                        "displayName": "new-name",
                        "roleNames": ["domain.com"],
                        "userTenants": [],
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
                client.mgmt.user.delete,
                "valid-id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(client.mgmt.user.delete("u1"))
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.userDeletePath}",
                headers={
                    **common.defaultHeaders,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "identifier": "u1",
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
            mock_get.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.userLoadPath}",
                headers={
                    **common.defaultHeaders,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params={"identifier": "valid-id"},
                allow_redirects=None,
                verify=True,
            )

    def test_load_by_jwt_subject(self):
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
                client.mgmt.user.load_by_jwt_subject,
                "jwt-subject",
            )

        # Test success flow
        with patch("requests.get") as mock_get:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_get.return_value = network_resp
            resp = client.mgmt.user.load_by_jwt_subject("jwt-subject")
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_get.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.userLoadPath}",
                headers={
                    **common.defaultHeaders,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params={"jwtSubject": "jwt-subject"},
                allow_redirects=None,
                verify=True,
            )

    def test_search_all(self):
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
                client.mgmt.user.search_all,
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
            resp = client.mgmt.user.search_all(["t1, t2"], ["r1", "r2"])
            users = resp["users"]
            self.assertEqual(len(users), 2)
            self.assertEqual(users[0]["id"], "u1")
            self.assertEqual(users[1]["id"], "u2")
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.usersSearchPath}",
                headers={
                    **common.defaultHeaders,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "tenantIds": ["t1, t2"],
                        "roleNames": ["r1", "r2"],
                        "limit": 0,
                    }
                ),
                allow_redirects=False,
                verify=True,
            )
