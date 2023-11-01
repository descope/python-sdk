import json
from unittest import mock
from unittest.mock import patch

from descope import AssociatedTenant, AuthException, DescopeClient
from descope.common import DEFAULT_TIMEOUT_SECONDS, DeliveryMethod
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
                picture="https://test.com",
                custom_attributes={"ak": "av"},
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
                json={
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
                    "picture": "https://test.com",
                    "customAttributes": {"ak": "av"},
                    "invite": False,
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_create_with_verified_parameters(self):
        # Test success flow with verified email and phone
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
                picture="https://test.com",
                custom_attributes={"ak": "av"},
                verified_email=True,
                verified_phone=False,
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
                json={
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
                    "picture": "https://test.com",
                    "customAttributes": {"ak": "av"},
                    "invite": False,
                    "verifiedEmail": True,
                    "verifiedPhone": False,
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
                custom_attributes={"ak": "av"},
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
                json={
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
                    "picture": None,
                    "customAttributes": {"ak": "av"},
                    "invite": False,
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
                custom_attributes={"ak": "av"},
                invite_url="invite.me",
                send_sms=True
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
                json={
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
                    "picture": None,
                    "customAttributes": {"ak": "av"},
                    "invite": True,
                    "inviteUrl": "invite.me",
                    "sendSMS": True
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
                    picture="https://test.com",
                    custom_attributes={"ak": "av"},
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_update_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={
                    "loginId": "id",
                    "email": None,
                    "phone": None,
                    "displayName": "new-name",
                    "roleNames": ["domain.com"],
                    "userTenants": [],
                    "test": False,
                    "picture": "https://test.com",
                    "customAttributes": {"ak": "av"},
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
        # Test success flow with verified flags
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(
                self.client.mgmt.user.update(
                    "id", verified_email=True, verified_phone=False
                )
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_update_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={
                    "loginId": "id",
                    "email": None,
                    "phone": None,
                    "displayName": None,
                    "roleNames": [],
                    "userTenants": [],
                    "test": False,
                    "picture": None,
                    "customAttributes": None,
                    "verifiedEmail": True,
                    "verifiedPhone": False,
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
                json={
                    "loginId": "u1",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_logout(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.logout_user,
                "valid-id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(self.client.mgmt.user.logout_user("u1"))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_logout_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={
                    "loginId": "u1",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_logout_by_user_id(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.logout_user_by_user_id,
                "valid-id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(self.client.mgmt.user.logout_user_by_user_id("u1"))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_logout_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={
                    "userId": "u1",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_delete_all_test_users(self):
        # Test failed flows
        with patch("requests.delete") as mock_delete:
            mock_delete.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.delete_all_test_users,
            )

        # Test success flow
        with patch("requests.delete") as mock_delete:
            mock_delete.return_value.ok = True
            self.assertIsNone(self.client.mgmt.user.delete_all_test_users())
            mock_delete.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_delete_all_test_users_path}",
                params=None,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
                json={
                    "tenantIds": ["t1, t2"],
                    "roleNames": ["r1", "r2"],
                    "limit": 0,
                    "page": 0,
                    "testUsersOnly": False,
                    "withTestUser": True,
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test success flow with custom attributes
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{"users": [{"id": "u1"}, {"id": "u2"}]}"""
            )
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.search_all(
                ["t1, t2"],
                ["r1", "r2"],
                with_test_user=True,
                custom_attributes={"ak": "av"},
                statuses=["invited"],
                phones=["+111111"],
                emails=["a@b.com"],
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
                json={
                    "tenantIds": ["t1, t2"],
                    "roleNames": ["r1", "r2"],
                    "limit": 0,
                    "page": 0,
                    "testUsersOnly": False,
                    "withTestUser": True,
                    "customAttributes": {"ak": "av"},
                    "statuses": ["invited"],
                    "emails": ["a@b.com"],
                    "phones": ["+111111"],
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_get_provider_token(self):
        # Test failed flows
        with patch("requests.get") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.get_provider_token,
                "valid-id",
                "p1",
            )
            # Test success flow
        with patch("requests.get") as mock_get:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{"provider": "p1", "providerUserId": "puid", "accessToken": "access123", "expiration": "123123123", "scopes": ["s1", "s2"]}"""
            )
            mock_get.return_value = network_resp
            resp = self.client.mgmt.user.get_provider_token("valid-id", "p1")
            self.assertEqual(resp["provider"], "p1")
            self.assertEqual(resp["providerUserId"], "puid")
            self.assertEqual(resp["accessToken"], "access123")
            self.assertEqual(resp["expiration"], "123123123")
            self.assertEqual(resp["scopes"], ["s1", "s2"])
            mock_get.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_get_provider_token}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params={"loginId": "valid-id", "provider": "p1"},
                allow_redirects=None,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
                json={
                    "loginId": "valid-id",
                    "status": "enabled",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
                json={
                    "loginId": "valid-id",
                    "status": "disabled",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_update_login_id(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.update_login_id,
                "valid-id",
                "a@b.c",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "a@b.c"}}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.update_login_id("valid-id", "a@b.c")
            user = resp["user"]
            self.assertEqual(user["id"], "a@b.c")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_update_login_id_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={
                    "loginId": "valid-id",
                    "newLoginId": "a@b.c",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
                json={
                    "loginId": "valid-id",
                    "email": "a@b.c",
                    "verified": None,
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
                json={
                    "loginId": "valid-id",
                    "phone": "+18005551234",
                    "verified": True,
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
                json={
                    "loginId": "valid-id",
                    "displayName": "foo",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_update_picture(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.update_picture,
                "valid-id",
                "foo",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.update_picture("valid-id", "foo")
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_update_picture_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={
                    "loginId": "valid-id",
                    "picture": "foo",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_update_custom_attribute(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.update_custom_attribute,
                "valid-id",
                "foo",
                "bar",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.update_custom_attribute(
                "valid-id", "foo", "bar"
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_update_custom_attribute_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                json={
                    "loginId": "valid-id",
                    "attributeKey": "foo",
                    "attributeValue": "bar",
                },
                allow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
                json={
                    "loginId": "valid-id",
                    "roleNames": ["foo", "bar"],
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
                json={
                    "loginId": "valid-id",
                    "roleNames": ["foo", "bar"],
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
                json={
                    "loginId": "valid-id",
                    "tenantId": "tid",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
                json={
                    "loginId": "valid-id",
                    "tenantId": "tid",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
                json={
                    "loginId": "valid-id",
                    "tenantId": "tid",
                    "roleNames": ["foo", "bar"],
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
                json={
                    "loginId": "valid-id",
                    "tenantId": "tid",
                    "roleNames": ["foo", "bar"],
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
                json={
                    "loginId": "login-id",
                    "deliveryMethod": "email",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_user_set_password(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.set_password,
                "login-id",
                "some-password",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            mock_post.return_value = network_resp
            self.client.mgmt.user.set_password(
                "login-id",
                "some-password",
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_set_password_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={
                    "loginId": "login-id",
                    "password": "some-password",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_user_expire_password(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.expire_password,
                "login-id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            mock_post.return_value = network_resp
            self.client.mgmt.user.expire_password(
                "login-id",
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_expire_password_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                params=None,
                json={
                    "loginId": "login-id",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
                json={
                    "loginId": "login-id",
                    "deliveryMethod": "email",
                    "URI": "bla",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
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
                json={
                    "loginId": "login-id",
                    "URI": "bla",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_generate_embedded_link(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException, self.client.mgmt.user.generate_embedded_link, "login-id"
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"token": "some-token"}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.generate_embedded_link(
                "login-id", {"k1": "v1"}
            )
            self.assertEqual(resp, "some-token")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_generate_embedded_link_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                },
                json={
                    "loginId": "login-id",
                    "customClaims": {"k1": "v1"},
                },
                allow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
