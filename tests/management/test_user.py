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
        self.client = DescopeClient(
            self.dummy_project_id,
            self.public_key_dict,
            False,
            self.dummy_management_key,
        )

    def test_create(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.create,
                "valid-id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.create(
                login_id="name@mail.com",
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
                        "loginId": "name@mail.com",
                        "email": "name@mail.com",
                        "phone": None,
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
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.update,
                "valid-id",
                "email@something.com",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                self.client.mgmt.user.update(
                    "id",
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
                        "loginId": "id",
                        "email": None,
                        "phone": None,
                        "displayName": "new-name",
                        "roleNames": ["domain.com"],
                        "userTenants": [],
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_delete(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.delete,
                "valid-id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(self.client.mgmt.user.delete("u1"))
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.userDeletePath}",
                headers={
                    **common.defaultHeaders,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "u1",
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_load(self):
        # Test failed flows
        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.load,
                "valid-id",
            )

        # Test success flow
        with patch("requests.get") as mock_get:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_get.return_value = network_resp
            resp = self.client.mgmt.user.load("valid-id")
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_get.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.userLoadPath}",
                headers={
                    **common.defaultHeaders,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params={"loginId": "valid-id"},
                allow_redirects=None,
                verify=True,
            )

    def test_load_by_user_id(self):
        # Test failed flows
        with patch("requests.get") as mock_get:
            mock_get.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.load_by_user_id,
                "user-id",
            )

        # Test success flow
        with patch("requests.get") as mock_get:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_get.return_value = network_resp
            resp = self.client.mgmt.user.load_by_user_id("user-id")
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_get.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.userLoadPath}",
                headers={
                    **common.defaultHeaders,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params={"userId": "user-id"},
                allow_redirects=None,
                verify=True,
            )

    def test_search_all(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.search_all,
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
            resp = self.client.mgmt.user.search_all(["t1, t2"], ["r1", "r2"])
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

    def test_activate(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.activate,
                "valid-id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.activate("valid-id")
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.userUpdateStatusPath}",
                headers={
                    **common.defaultHeaders,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "valid-id",
                        "status": "enabled",
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_deactivate(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.deactivate,
                "valid-id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.deactivate("valid-id")
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.userUpdateStatusPath}",
                headers={
                    **common.defaultHeaders,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "valid-id",
                        "status": "disabled",
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_update_email(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.update_email,
                "valid-id",
                "a@b.c",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.update_email("valid-id", "a@b.c")
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.userUpdateEmailPath}",
                headers={
                    **common.defaultHeaders,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "valid-id",
                        "email": "a@b.c",
                        "verified": None,
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_update_phone(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.update_phone,
                "valid-id",
                "+18005551234",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.update_phone("valid-id", "+18005551234", True)
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.userUpdatePhonePath}",
                headers={
                    **common.defaultHeaders,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "valid-id",
                        "phone": "+18005551234",
                        "verified": True,
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_update_display_name(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.update_display_name,
                "valid-id",
                "foo",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.update_display_name("valid-id", "foo")
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.userUpdateNamePath}",
                headers={
                    **common.defaultHeaders,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "valid-id",
                        "displayName": "foo",
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_add_roles(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.add_roles,
                "valid-id",
                ["foo", "bar"],
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.add_roles("valid-id", ["foo", "bar"])
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.userAddRolePath}",
                headers={
                    **common.defaultHeaders,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "valid-id",
                        "roleNames": ["foo", "bar"],
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_remove_roles(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.remove_roles,
                "valid-id",
                ["foo", "bar"],
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.remove_roles("valid-id", ["foo", "bar"])
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.userRemoveRolePath}",
                headers={
                    **common.defaultHeaders,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "valid-id",
                        "roleNames": ["foo", "bar"],
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_add_tenant(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.add_tenant,
                "valid-id",
                "tid",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.add_tenant("valid-id", "tid")
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.userAddTenantPath}",
                headers={
                    **common.defaultHeaders,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "valid-id",
                        "tenantId": "tid",
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_remove_tenant(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.remove_tenant,
                "valid-id",
                "tid",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.remove_tenant("valid-id", "tid")
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.userRemoveTenantPath}",
                headers={
                    **common.defaultHeaders,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "valid-id",
                        "tenantId": "tid",
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_add_tenant_roles(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.add_tenant_roles,
                "valid-id",
                "tid",
                ["foo", "bar"],
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.add_tenant_roles(
                "valid-id", "tid", ["foo", "bar"]
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.userAddRolePath}",
                headers={
                    **common.defaultHeaders,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "valid-id",
                        "tenantId": "tid",
                        "roleNames": ["foo", "bar"],
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_remove_tenant_roles(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.remove_tenant_roles,
                "valid-id",
                "tid",
                ["foo", "bar"],
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.remove_tenant_roles(
                "valid-id", "tid", ["foo", "bar"]
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{DEFAULT_BASE_URL}{MgmtV1.userRemoveRolePath}",
                headers={
                    **common.defaultHeaders,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "valid-id",
                        "tenantId": "tid",
                        "roleNames": ["foo", "bar"],
                    }
                ),
                allow_redirects=False,
                verify=True,
            )
