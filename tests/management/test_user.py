import json
from unittest import mock
from unittest.mock import patch

from descope import AssociatedTenant, AuthException, DescopeClient
from descope.common import DEFAULT_TIMEOUT_SECONDS, DeliveryMethod, LoginOptions
from descope.management.common import MgmtV1, Sort
from descope.management.user import UserObj
from descope.management.user_pwd import (
    UserPassword,
    UserPasswordBcrypt,
    UserPasswordDjango,
    UserPasswordFirebase,
    UserPasswordPbkdf2,
)

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
                additional_login_ids=["id-1", "id-2"],
                sso_app_ids=["app1", "app2"],
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_create_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
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
                    "additionalLoginIds": ["id-1", "id-2"],
                    "ssoAppIDs": ["app1", "app2"],
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
                    "x-descope-project-id": self.dummy_project_id,
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
                    "additionalLoginIds": None,
                    "ssoAppIDs": None,
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
                f"{common.DEFAULT_BASE_URL}{MgmtV1.test_user_create_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
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
                    "additionalLoginIds": None,
                    "ssoAppIDs": None,
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
                send_sms=True,
                sso_app_ids=["app1", "app2"],
                template_id="tid",
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_create_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
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
                    "sendSMS": True,
                    "additionalLoginIds": None,
                    "ssoAppIDs": ["app1", "app2"],
                    "templateId": "tid",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_invite_batch(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.invite_batch,
                [],
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"users": [{"id": "u1"}]}""")
            mock_post.return_value = network_resp
            user = UserObj(
                login_id="name@mail.com",
                email="name@mail.com",
                display_name="Name",
                user_tenants=[
                    AssociatedTenant("tenant1"),
                    AssociatedTenant("tenant2", ["role1", "role2"]),
                ],
                custom_attributes={"ak": "av"},
                sso_app_ids=["app1", "app2"],
                password=UserPassword(
                    hashed=UserPasswordFirebase(
                        hash="h",
                        salt="s",
                        salt_separator="sp",
                        signer_key="sk",
                        memory=14,
                        rounds=8,
                    ),
                ),
                seed="aaa",
                status="invited",
            )
            resp = self.client.mgmt.user.invite_batch(
                users=[user],
                invite_url="invite.me",
                send_sms=True,
            )
            users = resp["users"]
            self.assertEqual(users[0]["id"], "u1")

            expected_users = {
                "users": [
                    {
                        "loginId": "name@mail.com",
                        "email": "name@mail.com",
                        "phone": None,
                        "displayName": "Name",
                        "roleNames": [],
                        "userTenants": [
                            {"tenantId": "tenant1", "roleNames": []},
                            {
                                "tenantId": "tenant2",
                                "roleNames": ["role1", "role2"],
                            },
                        ],
                        "test": False,
                        "picture": None,
                        "customAttributes": {"ak": "av"},
                        "additionalLoginIds": None,
                        "ssoAppIDs": ["app1", "app2"],
                        "hashedPassword": {
                            "firebase": {
                                "hash": "h",
                                "salt": "s",
                                "saltSeparator": "sp",
                                "signerKey": "sk",
                                "memory": 14,
                                "rounds": 8,
                            }
                        },
                        "seed": "aaa",
                        "status": "invited",
                    },
                ],
                "invite": True,
                "inviteUrl": "invite.me",
                "sendSMS": True,
            }
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_create_batch_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json=expected_users,
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

            bcrypt = UserPasswordBcrypt(hash="h")
            self.assertEqual(bcrypt.to_dict(), {"bcrypt": {"hash": "h"}})

            pbkdf2 = UserPasswordPbkdf2(
                hash="h", salt="s", iterations=14, variant="sha256"
            )
            self.assertEqual(
                pbkdf2.to_dict(),
                {
                    "pbkdf2": {
                        "hash": "h",
                        "salt": "s",
                        "iterations": 14,
                        "type": "sha256",
                    }
                },
            )

            django = UserPasswordDjango(hash="h")
            self.assertEqual(django.to_dict(), {"django": {"hash": "h"}})

            user.password = UserPassword(cleartext="clear")
            resp = self.client.mgmt.user.invite_batch(
                users=[user],
                invite_url="invite.me",
                send_sms=True,
            )

            del expected_users["users"][0]["hashedPassword"]
            expected_users["users"][0]["password"] = "clear"
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_create_batch_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json=expected_users,
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

            user.password = None
            resp = self.client.mgmt.user.invite_batch(
                users=[user],
                invite_url="invite.me",
                send_sms=True,
            )

            del expected_users["users"][0]["password"]
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_create_batch_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json=expected_users,
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
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.update(
                "id",
                display_name="new-name",
                role_names=["domain.com"],
                picture="https://test.com",
                custom_attributes={"ak": "av"},
                sso_app_ids=["app1", "app2"],
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_update_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
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
                    "additionalLoginIds": None,
                    "ssoAppIDs": ["app1", "app2"],
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
        # Test success flow with verified flags
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.update(
                "id", verified_email=True, verified_phone=False
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_update_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
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
                    "additionalLoginIds": None,
                    "ssoAppIDs": None,
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_patch(self):
        # Test failed flows
        with patch("requests.patch") as mock_patch:
            mock_patch.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.patch,
                "valid-id",
                "email@something.com",
            )

        # Test success flow with some params set
        with patch("requests.patch") as mock_patch:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_patch.return_value = network_resp
            resp = self.client.mgmt.user.patch(
                "id",
                display_name="new-name",
                email=None,
                phone=None,
                given_name=None,
                role_names=["domain.com"],
                user_tenants=None,
                picture="https://test.com",
                custom_attributes={"ak": "av"},
                sso_app_ids=["app1", "app2"],
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_patch.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_patch_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "id",
                    "displayName": "new-name",
                    "roleNames": ["domain.com"],
                    "picture": "https://test.com",
                    "customAttributes": {"ak": "av"},
                    "ssoAppIds": ["app1", "app2"],
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
        # Test success flow with other params
        with patch("requests.patch") as mock_patch:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_patch.return_value = network_resp
            resp = self.client.mgmt.user.patch(
                "id",
                email="a@test.com",
                phone="+123456789",
                given_name="given",
                middle_name="middle",
                family_name="family",
                role_names=None,
                user_tenants=[
                    AssociatedTenant("tenant1"),
                    AssociatedTenant("tenant2", ["role1", "role2"]),
                ],
                custom_attributes=None,
                verified_email=True,
                verified_phone=False,
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_patch.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_patch_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "id",
                    "email": "a@test.com",
                    "phone": "+123456789",
                    "givenName": "given",
                    "middleName": "middle",
                    "familyName": "family",
                    "verifiedEmail": True,
                    "verifiedPhone": False,
                    "userTenants": [
                        {"tenantId": "tenant1", "roleNames": []},
                        {"tenantId": "tenant2", "roleNames": ["role1", "role2"]},
                    ],
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_patch_with_status(self):
        # Test invalid status value
        with self.assertRaises(AuthException) as context:
            self.client.mgmt.user.patch("valid-id", status="invalid_status")

        self.assertEqual(context.exception.status_code, 400)
        self.assertIn("Invalid status value: invalid_status", str(context.exception))

        # Test valid status values
        valid_statuses = ["enabled", "disabled", "invited"]

        for status in valid_statuses:
            with patch("requests.patch") as mock_patch:
                network_resp = mock.Mock()
                network_resp.ok = True
                network_resp.json.return_value = json.loads(
                    """{"user": {"id": "u1"}}"""
                )
                mock_patch.return_value = network_resp

                resp = self.client.mgmt.user.patch("id", status=status)
                user = resp["user"]
                self.assertEqual(user["id"], "u1")

                mock_patch.assert_called_with(
                    f"{common.DEFAULT_BASE_URL}{MgmtV1.user_patch_path}",
                    headers={
                        **common.default_headers,
                        "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                        "x-descope-project-id": self.dummy_project_id,
                    },
                    params=None,
                    json={
                        "loginId": "id",
                        "status": status,
                    },
                    allow_redirects=False,
                    verify=True,
                    timeout=DEFAULT_TIMEOUT_SECONDS,
                )

        # Test that status is not included when None
        with patch("requests.patch") as mock_patch:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_patch.return_value = network_resp

            resp = self.client.mgmt.user.patch("id", display_name="test", status=None)
            user = resp["user"]
            self.assertEqual(user["id"], "u1")

            # Verify that status is not in the JSON payload
            call_args = mock_patch.call_args
            json_payload = call_args[1]["json"]
            self.assertNotIn("status", json_payload)
            self.assertEqual(json_payload["displayName"], "test")

    def test_patch_batch(self):
        # Test invalid status value in batch
        users_with_invalid_status = [
            UserObj(login_id="user1", status="invalid_status"),
            UserObj(login_id="user2", status="enabled"),
        ]

        with self.assertRaises(AuthException) as context:
            self.client.mgmt.user.patch_batch(users_with_invalid_status)

        self.assertEqual(context.exception.status_code, 400)
        self.assertIn(
            "Invalid status value: invalid_status for user user1",
            str(context.exception),
        )

        # Test successful batch patch
        users = [
            UserObj(login_id="user1", email="user1@test.com", status="enabled"),
            UserObj(login_id="user2", display_name="User Two", status="disabled"),
            UserObj(login_id="user3", phone="+123456789", status="invited"),
        ]

        with patch("requests.patch") as mock_patch:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{"patchedUsers": [{"id": "u1"}, {"id": "u2"}, {"id": "u3"}], "failedUsers": []}"""
            )
            mock_patch.return_value = network_resp

            resp = self.client.mgmt.user.patch_batch(users)

            self.assertEqual(len(resp["patchedUsers"]), 3)
            self.assertEqual(len(resp["failedUsers"]), 0)

            mock_patch.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_patch_batch_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "users": [
                        {
                            "loginId": "user1",
                            "email": "user1@test.com",
                            "status": "enabled",
                        },
                        {
                            "loginId": "user2",
                            "displayName": "User Two",
                            "status": "disabled",
                        },
                        {
                            "loginId": "user3",
                            "phone": "+123456789",
                            "status": "invited",
                        },
                    ]
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test batch with mixed success/failure response
        with patch("requests.patch") as mock_patch:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{"patchedUsers": [{"id": "u1"}], "failedUsers": [{"failure": "User not found", "user": {"loginId": "user2"}}]}"""
            )
            mock_patch.return_value = network_resp

            resp = self.client.mgmt.user.patch_batch(
                [UserObj(login_id="user1"), UserObj(login_id="user2")]
            )

            self.assertEqual(len(resp["patchedUsers"]), 1)
            self.assertEqual(len(resp["failedUsers"]), 1)
            self.assertEqual(resp["failedUsers"][0]["failure"], "User not found")

        # Test failed batch operation
        with patch("requests.patch") as mock_patch:
            mock_patch.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.patch_batch,
                [UserObj(login_id="user1")],
            )

        # Test with test users flag
        with patch("requests.patch") as mock_patch:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{"patchedUsers": [{"id": "u1"}], "failedUsers": []}"""
            )
            mock_patch.return_value = network_resp

            resp = self.client.mgmt.user.patch_batch(
                [UserObj(login_id="test_user1")], test=True
            )

            call_args = mock_patch.call_args
            json_payload = call_args[1]["json"]
            self.assertTrue(json_payload["users"][0]["test"])

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
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "u1",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_delete_by_user_id(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.delete_by_user_id,
                "valid-id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertIsNone(self.client.mgmt.user.delete_by_user_id("u1"))
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_delete_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "userId": "u1",
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
                    "x-descope-project-id": self.dummy_project_id,
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
                    "x-descope-project-id": self.dummy_project_id,
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
                json=None,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
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
                    "x-descope-project-id": self.dummy_project_id,
                },
                params={"loginId": "valid-id"},
                allow_redirects=True,
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
                    "x-descope-project-id": self.dummy_project_id,
                },
                params={"userId": "user-id"},
                allow_redirects=True,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_load_users(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.load_users,
                [""],
            )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertRaises(
                AuthException, self.client.mgmt.user.load_users, None, False
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{"users": [{"id": "u1"}, {"id": "u2"}]}"""
            )
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.load_users(
                ["uid"],
                include_invalid_users=True,
            )
            users = resp["users"]
            self.assertEqual(len(users), 2)
            self.assertEqual(users[0]["id"], "u1")
            self.assertEqual(users[1]["id"], "u2")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.users_load_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "userIds": ["uid"],
                    "includeInvalidUsers": True,
                },
                allow_redirects=False,
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
                ["t1, t2"],
                ["r1", "r2"],
                with_test_user=True,
                sso_app_ids=["app1"],
                login_ids=["l1"],
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
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantIds": ["t1, t2"],
                    "roleNames": ["r1", "r2"],
                    "limit": 0,
                    "page": 0,
                    "testUsersOnly": False,
                    "withTestUser": True,
                    "ssoAppIds": ["app1"],
                    "loginIds": ["l1"],
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test success flow with text and sort
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{"users": [{"id": "u1"}, {"id": "u2"}]}"""
            )
            mock_post.return_value = network_resp
            sort = [Sort(field="kuku", desc=True), Sort(field="bubu")]
            resp = self.client.mgmt.user.search_all(
                ["t1, t2"],
                ["r1", "r2"],
                with_test_user=True,
                sso_app_ids=["app1"],
                text="blue",
                sort=sort,
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
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantIds": ["t1, t2"],
                    "roleNames": ["r1", "r2"],
                    "limit": 0,
                    "page": 0,
                    "testUsersOnly": False,
                    "withTestUser": True,
                    "ssoAppIds": ["app1"],
                    "text": "blue",
                    "sort": [
                        {"desc": True, "field": "kuku"},
                        {"desc": False, "field": "bubu"},
                    ],
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
                    "x-descope-project-id": self.dummy_project_id,
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

        # Test success flow with time parameters
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{"users": [{"id": "u1"}, {"id": "u2"}]}"""
            )
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.search_all(
                from_created_time=100,
                to_created_time=200,
                from_modified_time=300,
                to_modified_time=400,
                limit=10,
                page=0,
            )
            users = resp["users"]
            self.assertEqual(len(users), 2)
            self.assertEqual(users[0]["id"], "u1")
            self.assertEqual(users[1]["id"], "u2")
            # Verify the request body includes our time parameters
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.users_search_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantIds": [],
                    "roleNames": [],
                    "limit": 10,
                    "page": 0,
                    "testUsersOnly": False,
                    "withTestUser": False,
                    "fromCreatedTime": 100,
                    "toCreatedTime": 200,
                    "fromModifiedTime": 300,
                    "toModifiedTime": 400,
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test success flow with tenant_role_ids and tenant_role_names
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{"users": [{"id": "u1"}, {"id": "u2"}]}"""
            )
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.search_all(
                tenant_role_ids={
                    "tenant1": {"values": ["roleA", "roleB"], "and": True}
                },
                tenant_role_names={
                    "tenant2": {"values": ["admin", "user"], "and": False}
                },
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
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantIds": [],
                    "roleNames": [],
                    "limit": 0,
                    "page": 0,
                    "testUsersOnly": False,
                    "withTestUser": False,
                    "tenantRoleIds": {
                        "tenant1": {"values": ["roleA", "roleB"], "and": True}
                    },
                    "tenantRoleNames": {
                        "tenant2": {"values": ["admin", "user"], "and": False}
                    },
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_search_all_test_users(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.search_all_test_users,
                ["t1, t2"],
                ["r1", "r2"],
            )

        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = True
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.search_all_test_users,
                [],
                [],
                -1,
                0,
            )

            self.assertRaises(
                AuthException,
                self.client.mgmt.user.search_all_test_users,
                [],
                [],
                0,
                -1,
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{"users": [{"id": "u1"}, {"id": "u2"}]}"""
            )
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.search_all_test_users(
                ["t1, t2"],
                ["r1", "r2"],
                sso_app_ids=["app1"],
                login_ids=["l1"],
            )
            users = resp["users"]
            self.assertEqual(len(users), 2)
            self.assertEqual(users[0]["id"], "u1")
            self.assertEqual(users[1]["id"], "u2")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.test_users_search_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantIds": ["t1, t2"],
                    "roleNames": ["r1", "r2"],
                    "limit": 0,
                    "page": 0,
                    "testUsersOnly": True,
                    "withTestUser": True,
                    "ssoAppIds": ["app1"],
                    "loginIds": ["l1"],
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test success flow with text and sort
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{"users": [{"id": "u1"}, {"id": "u2"}]}"""
            )
            mock_post.return_value = network_resp
            sort = [Sort(field="kuku", desc=True), Sort(field="bubu")]
            resp = self.client.mgmt.user.search_all_test_users(
                ["t1, t2"],
                ["r1", "r2"],
                sso_app_ids=["app1"],
                text="blue",
                sort=sort,
            )
            users = resp["users"]
            self.assertEqual(len(users), 2)
            self.assertEqual(users[0]["id"], "u1")
            self.assertEqual(users[1]["id"], "u2")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.test_users_search_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantIds": ["t1, t2"],
                    "roleNames": ["r1", "r2"],
                    "limit": 0,
                    "page": 0,
                    "testUsersOnly": True,
                    "withTestUser": True,
                    "ssoAppIds": ["app1"],
                    "text": "blue",
                    "sort": [
                        {"desc": True, "field": "kuku"},
                        {"desc": False, "field": "bubu"},
                    ],
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
            resp = self.client.mgmt.user.search_all_test_users(
                ["t1, t2"],
                ["r1", "r2"],
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
                f"{common.DEFAULT_BASE_URL}{MgmtV1.test_users_search_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantIds": ["t1, t2"],
                    "roleNames": ["r1", "r2"],
                    "limit": 0,
                    "page": 0,
                    "testUsersOnly": True,
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

        # Test success flow with time parameters
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"users": [{"id": "u1"}]}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.search_all_test_users(
                from_created_time=100,
                to_created_time=200,
                from_modified_time=300,
                to_modified_time=400,
                limit=10,
                page=0,
            )
            users = resp["users"]
            self.assertEqual(len(users), 1)
            self.assertEqual(users[0]["id"], "u1")
            # Verify the request body includes our time parameters
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.test_users_search_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantIds": [],
                    "roleNames": [],
                    "limit": 10,
                    "page": 0,
                    "testUsersOnly": True,
                    "withTestUser": True,
                    "fromCreatedTime": 100,
                    "toCreatedTime": 200,
                    "fromModifiedTime": 300,
                    "toModifiedTime": 400,
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test success flow with tenant_role_ids and tenant_role_names
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """{"users": [{"id": "u1"}, {"id": "u2"}]}"""
            )
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.search_all_test_users(
                tenant_role_ids={
                    "tenant1": {"values": ["roleA", "roleB"], "and": True}
                },
                tenant_role_names={
                    "tenant2": {"values": ["admin", "user"], "and": False}
                },
            )
            users = resp["users"]
            self.assertEqual(len(users), 2)
            self.assertEqual(users[0]["id"], "u1")
            self.assertEqual(users[1]["id"], "u2")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.test_users_search_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "tenantIds": [],
                    "roleNames": [],
                    "limit": 0,
                    "page": 0,
                    "testUsersOnly": True,
                    "withTestUser": True,
                    "tenantRoleIds": {
                        "tenant1": {"values": ["roleA", "roleB"], "and": True}
                    },
                    "tenantRoleNames": {
                        "tenant2": {"values": ["admin", "user"], "and": False}
                    },
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
                """{"provider": "p1", "providerUserId": "puid", "accessToken": "access123", "refreshToken": "refresh456", "expiration": "123123123", "scopes": ["s1", "s2"]}"""
            )
            mock_get.return_value = network_resp
            resp = self.client.mgmt.user.get_provider_token(
                "valid-id", "p1", True, True
            )
            self.assertEqual(resp["provider"], "p1")
            self.assertEqual(resp["providerUserId"], "puid")
            self.assertEqual(resp["accessToken"], "access123")
            self.assertEqual(resp["refreshToken"], "refresh456")
            self.assertEqual(resp["expiration"], "123123123")
            self.assertEqual(resp["scopes"], ["s1", "s2"])
            mock_get.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_get_provider_token}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params={
                    "loginId": "valid-id",
                    "provider": "p1",
                    "withRefreshToken": True,
                    "forceRefresh": True,
                },
                allow_redirects=True,
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
                    "x-descope-project-id": self.dummy_project_id,
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
                    "x-descope-project-id": self.dummy_project_id,
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
                    "x-descope-project-id": self.dummy_project_id,
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
                    "x-descope-project-id": self.dummy_project_id,
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
                    "x-descope-project-id": self.dummy_project_id,
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
                    "x-descope-project-id": self.dummy_project_id,
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
                    "x-descope-project-id": self.dummy_project_id,
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
                    "x-descope-project-id": self.dummy_project_id,
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

    def test_set_roles(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.set_roles,
                "valid-id",
                ["foo", "bar"],
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.set_roles("valid-id", ["foo", "bar"])
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_set_role_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
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
                    "x-descope-project-id": self.dummy_project_id,
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
                    "x-descope-project-id": self.dummy_project_id,
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

    def test_add_sso_apps(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.add_sso_apps,
                "valid-id",
                ["foo", "bar"],
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.add_sso_apps("valid-id", ["foo", "bar"])
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_add_sso_apps}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "valid-id",
                    "ssoAppIds": ["foo", "bar"],
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_set_sso_apps(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.set_sso_apps,
                "valid-id",
                ["foo", "bar"],
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.set_sso_apps("valid-id", ["foo", "bar"])
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_set_sso_apps}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "valid-id",
                    "ssoAppIds": ["foo", "bar"],
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_remove_sso_apps(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.remove_sso_apps,
                "valid-id",
                ["foo", "bar"],
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"user": {"id": "u1"}}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.remove_sso_apps("valid-id", ["foo", "bar"])
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_remove_sso_apps}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "valid-id",
                    "ssoAppIds": ["foo", "bar"],
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
                    "x-descope-project-id": self.dummy_project_id,
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
                    "x-descope-project-id": self.dummy_project_id,
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

    def test_set_tenant_roles(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.set_tenant_roles,
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
            resp = self.client.mgmt.user.set_tenant_roles(
                "valid-id", "tid", ["foo", "bar"]
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_set_role_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
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
                    "x-descope-project-id": self.dummy_project_id,
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
                    "x-descope-project-id": self.dummy_project_id,
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
            login_options = LoginOptions(stepup=True)
            resp = self.client.mgmt.user.generate_otp_for_test_user(
                DeliveryMethod.EMAIL, "login-id", login_options
            )
            self.assertEqual(resp["code"], "123456")
            self.assertEqual(resp["loginId"], "login-id")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_generate_otp_for_test_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "login-id",
                    "deliveryMethod": "email",
                    "loginOptions": {
                        "stepup": True,
                        "customClaims": None,
                        "mfa": False,
                    },
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_user_set_temporary_password(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.set_temporary_password,
                "login-id",
                "some-password",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            mock_post.return_value = network_resp
            self.client.mgmt.user.set_temporary_password(
                "login-id",
                "some-password",
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_set_temporary_password_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "login-id",
                    "password": "some-password",
                    "setActive": False,
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_user_set_active_password(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.set_active_password,
                "login-id",
                "some-password",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            mock_post.return_value = network_resp
            self.client.mgmt.user.set_active_password(
                "login-id",
                "some-password",
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_set_active_password_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "login-id",
                    "password": "some-password",
                    "setActive": True,
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
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "login-id",
                    "password": "some-password",
                    "setActive": False,
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
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "login-id",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_user_remove_all_passkeys(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.remove_all_passkeys,
                "login-id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            mock_post.return_value = network_resp
            self.client.mgmt.user.remove_all_passkeys(
                "login-id",
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_remove_all_passkeys_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "login-id",
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_user_remove_totp_seed(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.remove_totp_seed,
                "login-id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            mock_post.return_value = network_resp
            self.client.mgmt.user.remove_totp_seed(
                "login-id",
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_remove_totp_seed_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
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
            login_options = LoginOptions(stepup=True)
            resp = self.client.mgmt.user.generate_magic_link_for_test_user(
                DeliveryMethod.EMAIL, "login-id", "bla", login_options
            )
            self.assertEqual(resp["link"], "some-link")
            self.assertEqual(resp["loginId"], "login-id")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_generate_magic_link_for_test_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "login-id",
                    "deliveryMethod": "email",
                    "URI": "bla",
                    "loginOptions": {
                        "stepup": True,
                        "customClaims": None,
                        "mfa": False,
                    },
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
            login_options = LoginOptions(stepup=True)
            resp = self.client.mgmt.user.generate_enchanted_link_for_test_user(
                "login-id", "bla", login_options
            )
            self.assertEqual(resp["link"], "some-link")
            self.assertEqual(resp["loginId"], "login-id")
            self.assertEqual(resp["pendingRef"], "some-ref")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_generate_enchanted_link_for_test_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "login-id",
                    "URI": "bla",
                    "loginOptions": {
                        "stepup": True,
                        "customClaims": None,
                        "mfa": False,
                    },
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
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "loginId": "login-id",
                    "customClaims": {"k1": "v1"},
                    "timeout": 0,
                },
                allow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_generate_sign_up_embedded_link(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException,
                self.client.mgmt.user.generate_sign_up_embedded_link,
                "login-id",
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads("""{"token": "some-token"}""")
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.generate_sign_up_embedded_link(
                "login-id", email_verified=True, phone_verified=True
            )
            self.assertEqual(resp, "some-token")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_generate_sign_up_embedded_link_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json={
                    "loginId": "login-id",
                    "phoneVerified": True,
                    "emailVerified": True,
                    "user": {},
                    "loginOptions": {},
                    "timeout": 0,
                },
                allow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_history(self):
        # Test failed flows
        with patch("requests.post") as mock_post:
            mock_post.return_value.ok = False
            self.assertRaises(
                AuthException, self.client.mgmt.user.history, ["user-id-1", "user-id-2"]
            )

        # Test success flow
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads(
                """
                [
                    {
                        "userId":    "kuku",
                        "city":      "kefar saba",
                        "country":   "Israel",
                        "ip":        "1.1.1.1",
                        "loginTime": 32
                    },
                    {
                        "userId":    "nunu",
                        "city":      "eilat",
                        "country":   "Israele",
                        "ip":        "1.1.1.2",
                        "loginTime": 23
                    }
                ]
                """
            )
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.history(["user-id-1", "user-id-2"])
            self.assertEqual(
                resp,
                [
                    {
                        "userId": "kuku",
                        "city": "kefar saba",
                        "country": "Israel",
                        "ip": "1.1.1.1",
                        "loginTime": 32,
                    },
                    {
                        "userId": "nunu",
                        "city": "eilat",
                        "country": "Israele",
                        "ip": "1.1.1.2",
                        "loginTime": 23,
                    },
                ],
            )
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_history_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json=["user-id-1", "user-id-2"],
                allow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_update_test_user(self):
        with patch("requests.post") as mock_post:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads('{"user": {"id": "u1"}}')
            mock_post.return_value = network_resp
            resp = self.client.mgmt.user.update(
                "id",
                display_name="test-user",
                test=True,
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_post.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_update_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "id",
                    "email": None,
                    "phone": None,
                    "displayName": "test-user",
                    "roleNames": [],
                    "userTenants": [],
                    "test": True,
                    "picture": None,
                    "customAttributes": None,
                    "additionalLoginIds": None,
                    "ssoAppIDs": None,
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_patch_test_user(self):
        with patch("requests.patch") as mock_patch:
            network_resp = mock.Mock()
            network_resp.ok = True
            network_resp.json.return_value = json.loads('{"user": {"id": "u1"}}')
            mock_patch.return_value = network_resp
            resp = self.client.mgmt.user.patch(
                "id",
                display_name="test-user",
                test=True,
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            mock_patch.assert_called_with(
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_patch_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json={
                    "loginId": "id",
                    "displayName": "test-user",
                    "test": True,
                },
                allow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
