import json
from unittest import mock
from unittest.mock import patch

from descope import AssociatedTenant, AuthException, DescopeClient
from descope.common import DeliveryMethod
from descope.management.common import MgmtV1

from .. import common


class TestUser(common.DescopeTest):
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
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_create_path}",
                headers={
                    **common.default_headers,
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
                        "test": False,
                        "invite": False,
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_create_test_user(self):
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
            resp = self.client.mgmt.user.create_test_user(
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
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_create_path}",
                headers={
                    **common.default_headers,
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
                        "test": True,
                        "invite": False,
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_invite(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.invite,
                "valid-id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.invite(
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
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_create_path}",
                headers={
                    **common.default_headers,
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
                        "test": False,
                        "invite": True,
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
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_update_path}",
                headers={
                    **common.default_headers,
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
                        "test": False,
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
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_delete_path}",
                headers={
                    **common.default_headers,
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

    def test_delete_all_test_users(self):
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
            self.assertIsNone(self.client.mgmt.user.delete_all_test_users())
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_delete_all_test_users_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps({}),
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
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_load_path}",
                headers={
                    **common.default_headers,
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
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_load_path}",
                headers={
                    **common.default_headers,
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

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertRaises(
                AuthException, self.client.mgmt.user.search_all, [], [], -1, 0
            )

            self.assertRaises(
                AuthException, self.client.mgmt.user.search_all, [], [], 0, -1
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{"users": [{"id": "u1"}, {"id": "u2"}]}"""
            )
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.search_all(
                ["t1, t2"], ["r1", "r2"], with_test_user=True
            )
            users = resp["users"]
            self.assertEqual(len(users), 2)
            self.assertEqual(users[0]["id"], "u1")
            self.assertEqual(users[1]["id"], "u2")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.users_search_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "tenantIds": ["t1, t2"],
                        "roleNames": ["r1", "r2"],
                        "limit": 0,
                        "page": 0,
                        "testUsersOnly": False,
                        "withTestUser": True,
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
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_update_status_path}",
                headers={
                    **common.default_headers,
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
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_update_status_path}",
                headers={
                    **common.default_headers,
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
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_update_email_path}",
                headers={
                    **common.default_headers,
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
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_update_phone_path}",
                headers={
                    **common.default_headers,
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
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_update_name_path}",
                headers={
                    **common.default_headers,
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
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_add_role_path}",
                headers={
                    **common.default_headers,
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
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_remove_role_path}",
                headers={
                    **common.default_headers,
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
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_add_tenant_path}",
                headers={
                    **common.default_headers,
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
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_remove_tenant_path}",
                headers={
                    **common.default_headers,
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
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_add_role_path}",
                headers={
                    **common.default_headers,
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
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_remove_role_path}",
                headers={
                    **common.default_headers,
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

    def test_generate_otp_for_test_user(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.generate_otp_for_test_user,
                "login-id",
                "email",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{"code": "123456", "loginId": "login-id"}"""
            )
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.generate_otp_for_test_user(
                DeliveryMethod.EMAIL, "login-id"
            )
            self.assertEqual(resp["code"], "123456")
            self.assertEqual(resp["loginId"], "login-id")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_generate_otp_for_test_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "login-id",
                        "deliveryMethod": "email",
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_generate_magic_link_for_test_user(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.generate_magic_link_for_test_user,
                "login-id",
                "email",
                "bla",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{"link": "some-link", "loginId": "login-id"}"""
            )
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.generate_magic_link_for_test_user(
                DeliveryMethod.EMAIL, "login-id", "bla"
            )
            self.assertEqual(resp["link"], "some-link")
            self.assertEqual(resp["loginId"], "login-id")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_generate_magic_link_for_test_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "login-id",
                        "deliveryMethod": "email",
                        "URI": "bla",
                    }
                ),
                allow_redirects=False,
                verify=True,
            )

    def test_generate_enchanted_link_for_test_user(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.generate_enchanted_link_for_test_user,
                "login-id",
                "bla",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{"link": "some-link", "loginId": "login-id", "pendingRef": "some-ref"}"""
            )
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.generate_enchanted_link_for_test_user(
                "login-id", "bla"
            )
            self.assertEqual(resp["link"], "some-link")
            self.assertEqual(resp["loginId"], "login-id")
            self.assertEqual(resp["pendingRef"], "some-ref")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_generate_enchanted_link_for_test_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                data=json.dumps(
                    {
                        "loginId": "login-id",
                        "URI": "bla",
                    }
                ),
                allow_redirects=False,
                verify=True,
            )
