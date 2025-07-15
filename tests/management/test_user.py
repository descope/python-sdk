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
from ..async_test_base import (
    parameterized_sync_async_subcase,
    HTTPMockHelper,
    MethodTestHelper,
)


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

    @parameterized_sync_async_subcase("create", "create_async")
    def test_create(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
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
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("create", "create_async")
    def test_create_with_verified_parameters(self, method_name, is_async):
        # Test success flow with verified email and phone
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
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
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("create_test_user", "create_test_user_async")
    def test_create_test_user(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
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
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("invite", "invite_async")
    def test_invite(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
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
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("invite_batch", "invite_batch_async")
    def test_invite_batch(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                [],
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"users": [{"id": "u1"}]}
        ) as mock_post:
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
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
                users=[user],
                invite_url="invite.me",
                send_sms=True,
            )
            users = resp["users"]
            self.assertEqual(users[0]["id"], "u1")

            expectedUsers = {
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
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_create_batch_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json=expectedUsers,
                follow_redirects=False,
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
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
                users=[user],
                invite_url="invite.me",
                send_sms=True,
            )

            del expectedUsers["users"][0]["hashedPassword"]
            expectedUsers["users"][0]["password"] = "clear"
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_create_batch_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json=expectedUsers,
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

            user.password = None
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
                users=[user],
                invite_url="invite.me",
                send_sms=True,
            )

            del expectedUsers["users"][0]["password"]
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_create_batch_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params=None,
                json=expectedUsers,
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("update", "update_async")
    def test_update(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
                "email@something.com",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
                "id",
                display_name="new-name",
                role_names=["domain.com"],
                picture="https://test.com",
                custom_attributes={"ak": "av"},
                sso_app_ids=["app1", "app2"],
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
        # Test success flow with verified flags
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
                "id",
                verified_email=True,
                verified_phone=False,
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("patch", "patch_async")
    def test_patch(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="patch", ok=False
        ) as mock_patch:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
                "email@something.com",
            )

        # Test success flow with some params set
        with HTTPMockHelper.mock_http_call(
            is_async, method="patch", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_patch:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
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
            HTTPMockHelper.assert_http_call(
                mock_patch,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
        # Test success flow with other params
        with HTTPMockHelper.mock_http_call(
            is_async, method="patch", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_patch:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
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
            HTTPMockHelper.assert_http_call(
                mock_patch,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("delete", "delete_async")
    def test_delete(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                self.client.mgmt.user, method_name, "u1"
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("delete_by_user_id", "delete_by_user_id_async")
    def test_delete_by_user_id(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                self.client.mgmt.user, method_name, "u1"
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("logout_user", "logout_user_async")
    def test_logout(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                self.client.mgmt.user, method_name, "u1"
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase(
        "logout_user_by_user_id", "logout_user_by_user_id_async"
    )
    def test_logout_by_user_id(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                self.client.mgmt.user, method_name, "u1"
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase(
        "delete_all_test_users", "delete_all_test_users_async"
    )
    def test_delete_all_test_users(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="delete", ok=False
        ) as mock_delete:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="delete", ok=True
        ) as mock_delete:
            result = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_delete,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_delete_all_test_users_path}",
                params=None,
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("load", "load_async")
    def test_load(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="get", ok=False
        ) as mock_get:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="get", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_get:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user, method_name, "valid-id"
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            HTTPMockHelper.assert_http_call(
                mock_get,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_load_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params={"loginId": "valid-id"},
                follow_redirects=None,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("load_by_user_id", "load_by_user_id_async")
    def test_load_by_user_id(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="get", ok=False
        ) as mock_get:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "user-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="get", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_get:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user, method_name, "user-id"
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            HTTPMockHelper.assert_http_call(
                mock_get,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_load_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                params={"userId": "user-id"},
                follow_redirects=None,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("search_all", "search_all_async")
    def test_search_all(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                ["t1, t2"],
                ["r1", "r2"],
            )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                [],
                [],
                -1,
                0,
            )

            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                [],
                [],
                0,
                -1,
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"users": [{"id": "u1"}, {"id": "u2"}]},
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
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
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test success flow with text and sort
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"users": [{"id": "u1"}, {"id": "u2"}]},
        ) as mock_post:
            sort = [Sort(field="kuku", desc=True), Sort(field="bubu")]
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
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
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test success flow with custom attributes
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"users": [{"id": "u1"}, {"id": "u2"}]},
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
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
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test success flow with time parameters
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"users": [{"id": "u1"}, {"id": "u2"}]},
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
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
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase(
        "search_all_test_users", "search_all_test_users_async"
    )
    def test_search_all_test_users(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                ["t1, t2"],
                ["r1", "r2"],
            )

        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                [],
                [],
                -1,
                0,
            )

            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                [],
                [],
                0,
                -1,
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"users": [{"id": "u1"}, {"id": "u2"}]},
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
                ["t1, t2"],
                ["r1", "r2"],
                sso_app_ids=["app1"],
                login_ids=["l1"],
            )
            users = resp["users"]
            self.assertEqual(len(users), 2)
            self.assertEqual(users[0]["id"], "u1")
            self.assertEqual(users[1]["id"], "u2")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test success flow with text and sort
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"users": [{"id": "u1"}, {"id": "u2"}]},
        ) as mock_post:
            sort = [Sort(field="kuku", desc=True), Sort(field="bubu")]
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
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
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test success flow with custom attributes
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"users": [{"id": "u1"}, {"id": "u2"}]},
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
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
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

        # Test success flow with time parameters
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"users": [{"id": "u1"}]}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
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
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("get_provider_token", "get_provider_token_async")
    def test_get_provider_token(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="get", ok=False
        ) as mock_get:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
                "p1",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="get",
            ok=True,
            json=lambda: {
                "provider": "p1",
                "providerUserId": "puid",
                "accessToken": "access123",
                "refreshToken": "refresh456",
                "expiration": "123123123",
                "scopes": ["s1", "s2"],
            },
        ) as mock_get:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
                "valid-id",
                "p1",
                True,
                True,
            )
            self.assertEqual(resp["provider"], "p1")
            self.assertEqual(resp["providerUserId"], "puid")
            self.assertEqual(resp["accessToken"], "access123")
            self.assertEqual(resp["refreshToken"], "refresh456")
            self.assertEqual(resp["expiration"], "123123123")
            self.assertEqual(resp["scopes"], ["s1", "s2"])
            HTTPMockHelper.assert_http_call(
                mock_get,
                is_async,
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
                follow_redirects=None,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("activate", "activate_async")
    def test_activate(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user, method_name, "valid-id"
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("deactivate", "deactivate_async")
    def test_deactivate(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user, method_name, "valid-id"
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("update_login_id", "update_login_id_async")
    def test_update_login_id(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
                "a@b.c",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "a@b.c"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user, method_name, "valid-id", "a@b.c"
            )
            user = resp["user"]
            self.assertEqual(user["id"], "a@b.c")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("update_email", "update_email_async")
    def test_update_email(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
                "a@b.c",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user, method_name, "valid-id", "a@b.c"
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("update_phone", "update_phone_async")
    def test_update_phone(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
                "+18005551234",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
                "valid-id",
                "+18005551234",
                True,
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase(
        "update_display_name", "update_display_name_async"
    )
    def test_update_display_name(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
                "foo",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user, method_name, "valid-id", "foo"
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("update_picture", "update_picture_async")
    def test_update_picture(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
                "foo",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user, method_name, "valid-id", "foo"
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase(
        "update_custom_attribute", "update_custom_attribute_async"
    )
    def test_update_custom_attribute(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
                "foo",
                "bar",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user, method_name, "valid-id", "foo", "bar"
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("set_roles", "set_roles_async")
    def test_set_roles(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
                ["foo", "bar"],
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user, method_name, "valid-id", ["foo", "bar"]
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("add_roles", "add_roles_async")
    def test_add_roles(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
                ["foo", "bar"],
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user, method_name, "valid-id", ["foo", "bar"]
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("remove_roles", "remove_roles_async")
    def test_remove_roles(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
                ["foo", "bar"],
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user, method_name, "valid-id", ["foo", "bar"]
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("add_sso_apps", "add_sso_apps_async")
    def test_add_sso_apps(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
                ["foo", "bar"],
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user, method_name, "valid-id", ["foo", "bar"]
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("set_sso_apps", "set_sso_apps_async")
    def test_set_sso_apps(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
                ["foo", "bar"],
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user, method_name, "valid-id", ["foo", "bar"]
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("remove_sso_apps", "remove_sso_apps_async")
    def test_remove_sso_apps(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
                ["foo", "bar"],
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user, method_name, "valid-id", ["foo", "bar"]
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("add_tenant", "add_tenant_async")
    def test_add_tenant(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
                "tid",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user, method_name, "valid-id", "tid"
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("remove_tenant", "remove_tenant_async")
    def test_remove_tenant(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
                "tid",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user, method_name, "valid-id", "tid"
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("set_tenant_roles", "set_tenant_roles_async")
    def test_set_tenant_roles(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
                "tid",
                ["foo", "bar"],
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
                "valid-id",
                "tid",
                ["foo", "bar"],
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("add_tenant_roles", "add_tenant_roles_async")
    def test_add_tenant_roles(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
                "tid",
                ["foo", "bar"],
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
                "valid-id",
                "tid",
                ["foo", "bar"],
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase(
        "remove_tenant_roles", "remove_tenant_roles_async"
    )
    def test_remove_tenant_roles(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "valid-id",
                "tid",
                ["foo", "bar"],
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"user": {"id": "u1"}}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
                "valid-id",
                "tid",
                ["foo", "bar"],
            )
            user = resp["user"]
            self.assertEqual(user["id"], "u1")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase(
        "generate_otp_for_test_user", "generate_otp_for_test_user_async"
    )
    def test_generate_otp_for_test_user(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                DeliveryMethod.EMAIL,
                "login-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"code": "123456", "loginId": "login-id"},
        ) as mock_post:
            login_options = LoginOptions(stepup=True)
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
                DeliveryMethod.EMAIL,
                "login-id",
                login_options,
            )
            self.assertEqual(resp["code"], "123456")
            self.assertEqual(resp["loginId"], "login-id")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase(
        "set_temporary_password", "set_temporary_password_async"
    )
    def test_user_set_temporary_password(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "login-id",
                "some-password",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
                "login-id",
                "some-password",
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase(
        "set_active_password", "set_active_password_async"
    )
    def test_user_set_active_password(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "login-id",
                "some-password",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            result = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
                "login-id",
                "some-password",
            )
            self.assertIsNone(result)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("set_password", "set_password_async")
    def test_user_set_password(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "login-id",
                "some-password",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
                "login-id",
                "some-password",
            )
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("expire_password", "expire_password_async")
    def test_user_expire_password(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "login-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
                "login-id",
            )
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase(
        "remove_all_passkeys", "remove_all_passkeys_async"
    )
    def test_user_remove_all_passkeys(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "login-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
                "login-id",
            )
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("remove_totp_seed", "remove_totp_seed_async")
    def test_user_remove_totp_seed(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "login-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True
        ) as mock_post:
            MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
                "login-id",
            )
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase(
        "generate_magic_link_for_test_user", "generate_magic_link_for_test_user_async"
    )
    def test_generate_magic_link_for_test_user(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "login-id",
                "email",
                "bla",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {"link": "some-link", "loginId": "login-id"},
        ) as mock_post:
            login_options = LoginOptions(stepup=True)
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
                DeliveryMethod.EMAIL,
                "login-id",
                "bla",
                login_options,
            )
            self.assertEqual(resp["link"], "some-link")
            self.assertEqual(resp["loginId"], "login-id")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase(
        "generate_enchanted_link_for_test_user",
        "generate_enchanted_link_for_test_user_async",
    )
    def test_generate_enchanted_link_for_test_user(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "login-id",
                "bla",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async,
            method="post",
            ok=True,
            json=lambda: {
                "link": "some-link",
                "loginId": "login-id",
                "pendingRef": "some-ref",
            },
        ) as mock_post:
            login_options = LoginOptions(stepup=True)
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
                "login-id",
                "bla",
                login_options,
            )
            self.assertEqual(resp["link"], "some-link")
            self.assertEqual(resp["loginId"], "login-id")
            self.assertEqual(resp["pendingRef"], "some-ref")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase(
        "generate_embedded_link", "generate_embedded_link_async"
    )
    def test_generate_embedded_link(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "login-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"token": "some-token"}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user, method_name, "login-id", {"k1": "v1"}
            )
            self.assertEqual(resp, "some-token")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase(
        "generate_sign_up_embedded_link", "generate_sign_up_embedded_link_async"
    )
    def test_generate_sign_up_embedded_link(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                "login-id",
            )

        # Test success flow
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: {"token": "some-token"}
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user,
                method_name,
                "login-id",
                email_verified=True,
                phone_verified=True,
            )
            self.assertEqual(resp, "some-token")
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
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
                follow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    @parameterized_sync_async_subcase("history", "history_async")
    def test_history(self, method_name, is_async):
        # Test failed flows
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=False
        ) as mock_post:
            self.assertRaises(
                AuthException,
                MethodTestHelper.call_method,
                self.client.mgmt.user,
                method_name,
                ["user-id-1", "user-id-2"],
            )

        # Test success flow
        expected_response = [
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
        ]
        with HTTPMockHelper.mock_http_call(
            is_async, method="post", ok=True, json=lambda: expected_response
        ) as mock_post:
            resp = MethodTestHelper.call_method(
                self.client.mgmt.user, method_name, ["user-id-1", "user-id-2"]
            )
            self.assertEqual(resp, expected_response)
            HTTPMockHelper.assert_http_call(
                mock_post,
                is_async,
                f"{common.DEFAULT_BASE_URL}{MgmtV1.user_history_path}",
                headers={
                    **common.default_headers,
                    "Authorization": f"Bearer {self.dummy_project_id}:{self.dummy_management_key}",
                    "x-descope-project-id": self.dummy_project_id,
                },
                json=["user-id-1", "user-id-2"],
                follow_redirects=False,
                verify=True,
                params=None,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_update_test_user(self):
        with patch("httpx.post") as mock_post:
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )

    def test_patch_test_user(self):
        with patch("httpx.patch") as mock_patch:
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
                follow_redirects=False,
                verify=True,
                timeout=DEFAULT_TIMEOUT_SECONDS,
            )
