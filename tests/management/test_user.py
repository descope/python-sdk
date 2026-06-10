import pytest

from descope import AssociatedTenant, AuthException
from descope.common import DeliveryMethod, LoginOptions
from descope.management.common import MgmtV1, Sort
from descope.management.user import UserObj
from descope.management.user_pwd import (
    UserPassword,
    UserPasswordBcrypt,
    UserPasswordDjango,
    UserPasswordFirebase,
    UserPasswordPbkdf2,
)

from tests.conftest import PROJECT_ID, assert_http_called, make_response
from tests.common import DEFAULT_BASE_URL, default_headers
from tests.testutils import PUBLIC_KEY_DICT


class TestUser:
    async def test_create(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.create("valid-id"))

        # Test success flow
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(
                client.mgmt.user.create(
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
            )
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_create_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

    async def test_create_with_verified_parameters(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test success flow with verified email and phone
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(
                client.mgmt.user.create(
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
            )
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_create_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

    async def test_create_test_user(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.create("valid-id"))

        # Test success flow
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(
                client.mgmt.user.create_test_user(
                    login_id="name@mail.com",
                    email="name@mail.com",
                    display_name="Name",
                    user_tenants=[
                        AssociatedTenant("tenant1"),
                        AssociatedTenant("tenant2", ["role1", "role2"]),
                    ],
                    custom_attributes={"ak": "av"},
                )
            )
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.test_user_create_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

    async def test_invite(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.invite("valid-id"))

        # Test success flow
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(
                client.mgmt.user.invite(
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
                    locale="en",
                )
            )
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_create_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
                    "locale": "en",
                },
                follow_redirects=False,
            )

    async def test_invite_batch(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.invite_batch([]))

        # Test success flow
        with client.mock_mgmt_post(make_response({"users": [{"id": "u1"}]})) as mock_post:
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
            resp = await client.invoke(
                client.mgmt.user.invite_batch(
                    users=[user],
                    invite_url="invite.me",
                    send_sms=True,
                    locale="en",
                )
            )
            users = resp["users"]
            assert users[0]["id"] == "u1"

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
                "locale": "en",
            }
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_create_batch_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json=expected_users,
                follow_redirects=False,
            )

            bcrypt = UserPasswordBcrypt(hash="h")
            assert bcrypt.to_dict() == {"bcrypt": {"hash": "h"}}

            pbkdf2 = UserPasswordPbkdf2(hash="h", salt="s", iterations=14, variant="sha256")
            assert pbkdf2.to_dict() == {
                "pbkdf2": {
                    "hash": "h",
                    "salt": "s",
                    "iterations": 14,
                    "type": "sha256",
                }
            }

            django = UserPasswordDjango(hash="h")
            assert django.to_dict() == {"django": {"hash": "h"}}

            user.password = UserPassword(cleartext="clear")
            resp = await client.invoke(
                client.mgmt.user.invite_batch(
                    users=[user],
                    invite_url="invite.me",
                    send_sms=True,
                    locale="en",
                )
            )

            del expected_users["users"][0]["hashedPassword"]
            expected_users["users"][0]["password"] = "clear"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_create_batch_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json=expected_users,
                follow_redirects=False,
            )

            user.password = None
            resp = await client.invoke(
                client.mgmt.user.invite_batch(
                    users=[user],
                    invite_url="invite.me",
                    send_sms=True,
                    locale="en",
                )
            )

            del expected_users["users"][0]["password"]
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_create_batch_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json=expected_users,
                follow_redirects=False,
            )

    async def test_update(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.update("valid-id", "email@something.com"))

        # Test success flow
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(
                client.mgmt.user.update(
                    "id",
                    display_name="new-name",
                    role_names=["domain.com"],
                    picture="https://test.com",
                    custom_attributes={"ak": "av"},
                    sso_app_ids=["app1", "app2"],
                )
            )
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_update_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

        # Test success flow with verified flags
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(
                client.mgmt.user.update("id", verified_email=True, verified_phone=False)
            )
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_update_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

    async def test_patch(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_patch(make_response(status=500)) as mock_patch:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.patch("valid-id", "email@something.com"))

        # Test success flow with some params set
        with client.mock_mgmt_patch(make_response({"user": {"id": "u1"}})) as mock_patch:
            resp = await client.invoke(
                client.mgmt.user.patch(
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
            )
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_patch, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_patch_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

        # Test success flow with other params
        with client.mock_mgmt_patch(make_response({"user": {"id": "u1"}})) as mock_patch:
            resp = await client.invoke(
                client.mgmt.user.patch(
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
            )
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_patch, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_patch_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

    async def test_patch_with_status(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test invalid status value
        with pytest.raises(AuthException) as exc_info:
            await client.invoke(client.mgmt.user.patch("valid-id", status="invalid_status"))

        assert exc_info.value.status_code == 400
        assert "Invalid status value: invalid_status" in str(exc_info.value)

        # Test valid status values
        valid_statuses = ["enabled", "disabled", "invited"]

        for status in valid_statuses:
            with client.mock_mgmt_patch(make_response({"user": {"id": "u1"}})) as mock_patch:
                resp = await client.invoke(client.mgmt.user.patch("id", status=status))
                user = resp["user"]
                assert user["id"] == "u1"

                assert_http_called(
                    mock_patch, client.mode,
                    f"{DEFAULT_BASE_URL}{MgmtV1.user_patch_path}",
                    headers={
                        **default_headers,
                        "Authorization": f"Bearer {PROJECT_ID}:key",
                        "x-descope-project-id": PROJECT_ID,
                    },
                    params=None,
                    json={
                        "loginId": "id",
                        "status": status,
                    },
                    follow_redirects=False,
                )

        # Test that status is not included when None
        with client.mock_mgmt_patch(make_response({"user": {"id": "u1"}})) as mock_patch:
            resp = await client.invoke(client.mgmt.user.patch("id", display_name="test", status=None))
            user = resp["user"]
            assert user["id"] == "u1"

            # Verify that status is not in the JSON payload
            call_args = mock_patch.call_args
            json_payload = call_args[1]["json"]
            assert "status" not in json_payload
            assert json_payload["displayName"] == "test"

    async def test_patch_batch(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test invalid status value in batch
        users_with_invalid_status = [
            UserObj(login_id="user1", status="invalid_status"),
            UserObj(login_id="user2", status="enabled"),
        ]

        with pytest.raises(AuthException) as exc_info:
            await client.invoke(client.mgmt.user.patch_batch(users_with_invalid_status))

        assert exc_info.value.status_code == 400
        assert "Invalid status value: invalid_status for user user1" in str(exc_info.value)

        # Test successful batch patch
        users = [
            UserObj(login_id="user1", email="user1@test.com", status="enabled"),
            UserObj(login_id="user2", display_name="User Two", status="disabled"),
            UserObj(login_id="user3", phone="+123456789", status="invited"),
        ]

        with client.mock_mgmt_patch(
            make_response({"patchedUsers": [{"id": "u1"}, {"id": "u2"}, {"id": "u3"}], "failedUsers": []})
        ) as mock_patch:
            resp = await client.invoke(client.mgmt.user.patch_batch(users))

            assert len(resp["patchedUsers"]) == 3
            assert len(resp["failedUsers"]) == 0

            assert_http_called(
                mock_patch, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_patch_batch_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
                follow_redirects=False,
            )

        # Test batch with mixed success/failure response
        with client.mock_mgmt_patch(
            make_response({"patchedUsers": [{"id": "u1"}], "failedUsers": [{"failure": "User not found", "user": {"loginId": "user2"}}]})
        ) as mock_patch:
            resp = await client.invoke(
                client.mgmt.user.patch_batch([UserObj(login_id="user1"), UserObj(login_id="user2")])
            )

            assert len(resp["patchedUsers"]) == 1
            assert len(resp["failedUsers"]) == 1
            assert resp["failedUsers"][0]["failure"] == "User not found"

        # Test failed batch operation
        with client.mock_mgmt_patch(make_response(status=500)) as mock_patch:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.user.patch_batch([UserObj(login_id="user1")])
                )

        # Test with test users flag
        with client.mock_mgmt_patch(
            make_response({"patchedUsers": [{"id": "u1"}], "failedUsers": []})
        ) as mock_patch:
            await client.invoke(
                client.mgmt.user.patch_batch([UserObj(login_id="test_user1")], test=True)
            )

            call_args = mock_patch.call_args
            json_payload = call_args[1]["json"]
            assert json_payload["users"][0]["test"]

    async def test_delete(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.delete("valid-id"))

        # Test success flow
        with client.mock_mgmt_post(make_response({})) as mock_post:
            assert await client.invoke(client.mgmt.user.delete("u1")) is None
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_delete_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "u1",
                },
                follow_redirects=False,
            )

    async def test_delete_by_user_id(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.delete_by_user_id("valid-id"))

        # Test success flow
        with client.mock_mgmt_post(make_response({})) as mock_post:
            assert await client.invoke(client.mgmt.user.delete_by_user_id("u1")) is None
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_delete_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "userId": "u1",
                },
                follow_redirects=False,
            )

    async def test_logout(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.logout_user("valid-id"))

        # Test success flow
        with client.mock_mgmt_post(make_response({})) as mock_post:
            assert await client.invoke(client.mgmt.user.logout_user("u1")) is None
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_logout_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "u1",
                },
                follow_redirects=False,
            )

    async def test_logout_by_user_id(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.logout_user_by_user_id("valid-id"))

        # Test success flow
        with client.mock_mgmt_post(make_response({})) as mock_post:
            assert await client.invoke(client.mgmt.user.logout_user_by_user_id("u1")) is None
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_logout_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "userId": "u1",
                },
                follow_redirects=False,
            )

    async def test_delete_all_test_users(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_delete(make_response(status=500)) as mock_delete:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.delete_all_test_users())

        # Test success flow
        with client.mock_mgmt_delete(make_response({})) as mock_delete:
            assert await client.invoke(client.mgmt.user.delete_all_test_users()) is None
            assert_http_called(
                mock_delete, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_delete_all_test_users_path}",
                params=None,
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                follow_redirects=False,
            )

    async def test_load(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_get(make_response(status=500)) as mock_get:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.load("valid-id"))

        # Test success flow
        with client.mock_mgmt_get(make_response({"user": {"id": "u1"}})) as mock_get:
            resp = await client.invoke(client.mgmt.user.load("valid-id"))
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_get, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_load_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params={"loginId": "valid-id"},
                follow_redirects=True,
            )

    async def test_load_by_user_id(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_get(make_response(status=500)) as mock_get:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.load_by_user_id("user-id"))

        # Test success flow
        with client.mock_mgmt_get(make_response({"user": {"id": "u1"}})) as mock_get:
            resp = await client.invoke(client.mgmt.user.load_by_user_id("user-id"))
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_get, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_load_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params={"userId": "user-id"},
                follow_redirects=True,
            )

    async def test_load_users(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.load_users([""]))

        with client.mock_mgmt_post(make_response({})) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.load_users(None, False))

        # Test success flow
        with client.mock_mgmt_post(make_response({"users": [{"id": "u1"}, {"id": "u2"}]})) as mock_post:
            resp = await client.invoke(
                client.mgmt.user.load_users(
                    ["uid"],
                    include_invalid_users=True,
                )
            )
            users = resp["users"]
            assert len(users) == 2
            assert users[0]["id"] == "u1"
            assert users[1]["id"] == "u2"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.users_load_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "userIds": ["uid"],
                    "includeInvalidUsers": True,
                },
                follow_redirects=False,
            )

    async def test_search_all(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.search_all(["t1, t2"], ["r1", "r2"]))

        with client.mock_mgmt_post(make_response({})) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.search_all([], [], -1, 0))

            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.search_all([], [], 0, -1))

        # Test success flow
        with client.mock_mgmt_post(make_response({"users": [{"id": "u1"}, {"id": "u2"}]})) as mock_post:
            resp = await client.invoke(
                client.mgmt.user.search_all(
                    ["t1, t2"],
                    ["r1", "r2"],
                    with_test_user=True,
                    sso_app_ids=["app1"],
                    login_ids=["l1"],
                )
            )
            users = resp["users"]
            assert len(users) == 2
            assert users[0]["id"] == "u1"
            assert users[1]["id"] == "u2"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.users_search_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

        # Test success flow with text and sort
        with client.mock_mgmt_post(make_response({"users": [{"id": "u1"}, {"id": "u2"}]})) as mock_post:
            sort = [Sort(field="kuku", desc=True), Sort(field="bubu")]
            resp = await client.invoke(
                client.mgmt.user.search_all(
                    ["t1, t2"],
                    ["r1", "r2"],
                    with_test_user=True,
                    sso_app_ids=["app1"],
                    text="blue",
                    sort=sort,
                )
            )
            users = resp["users"]
            assert len(users) == 2
            assert users[0]["id"] == "u1"
            assert users[1]["id"] == "u2"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.users_search_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

        # Test success flow with custom attributes
        with client.mock_mgmt_post(make_response({"users": [{"id": "u1"}, {"id": "u2"}]})) as mock_post:
            resp = await client.invoke(
                client.mgmt.user.search_all(
                    ["t1, t2"],
                    ["r1", "r2"],
                    with_test_user=True,
                    custom_attributes={"ak": "av"},
                    statuses=["invited"],
                    phones=["+111111"],
                    emails=["a@b.com"],
                )
            )
            users = resp["users"]
            assert len(users) == 2
            assert users[0]["id"] == "u1"
            assert users[1]["id"] == "u2"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.users_search_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

        # Test success flow with time parameters
        with client.mock_mgmt_post(make_response({"users": [{"id": "u1"}, {"id": "u2"}]})) as mock_post:
            resp = await client.invoke(
                client.mgmt.user.search_all(
                    from_created_time=100,
                    to_created_time=200,
                    from_modified_time=300,
                    to_modified_time=400,
                    limit=10,
                    page=0,
                )
            )
            users = resp["users"]
            assert len(users) == 2
            assert users[0]["id"] == "u1"
            assert users[1]["id"] == "u2"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.users_search_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

        # Test success flow with tenant_role_ids and tenant_role_names
        with client.mock_mgmt_post(make_response({"users": [{"id": "u1"}, {"id": "u2"}]})) as mock_post:
            resp = await client.invoke(
                client.mgmt.user.search_all(
                    tenant_role_ids={"tenant1": {"values": ["roleA", "roleB"], "and": True}},
                    tenant_role_names={"tenant2": {"values": ["admin", "user"], "and": False}},
                )
            )
            users = resp["users"]
            assert len(users) == 2
            assert users[0]["id"] == "u1"
            assert users[1]["id"] == "u2"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.users_search_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "tenantIds": [],
                    "roleNames": [],
                    "limit": 0,
                    "page": 0,
                    "testUsersOnly": False,
                    "withTestUser": False,
                    "tenantRoleIds": {"tenant1": {"values": ["roleA", "roleB"], "and": True}},
                    "tenantRoleNames": {"tenant2": {"values": ["admin", "user"], "and": False}},
                },
                follow_redirects=False,
            )

    async def test_search_all_test_users(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.search_all_test_users(["t1, t2"], ["r1", "r2"]))

        with client.mock_mgmt_post(make_response({})) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.user.search_all_test_users([], [], -1, 0)
                )

            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.user.search_all_test_users([], [], 0, -1)
                )

        # Test success flow
        with client.mock_mgmt_post(make_response({"users": [{"id": "u1"}, {"id": "u2"}]})) as mock_post:
            resp = await client.invoke(
                client.mgmt.user.search_all_test_users(
                    ["t1, t2"],
                    ["r1", "r2"],
                    sso_app_ids=["app1"],
                    login_ids=["l1"],
                )
            )
            users = resp["users"]
            assert len(users) == 2
            assert users[0]["id"] == "u1"
            assert users[1]["id"] == "u2"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.test_users_search_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

        # Test success flow with text and sort
        with client.mock_mgmt_post(make_response({"users": [{"id": "u1"}, {"id": "u2"}]})) as mock_post:
            sort = [Sort(field="kuku", desc=True), Sort(field="bubu")]
            resp = await client.invoke(
                client.mgmt.user.search_all_test_users(
                    ["t1, t2"],
                    ["r1", "r2"],
                    sso_app_ids=["app1"],
                    text="blue",
                    sort=sort,
                )
            )
            users = resp["users"]
            assert len(users) == 2
            assert users[0]["id"] == "u1"
            assert users[1]["id"] == "u2"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.test_users_search_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

        # Test success flow with custom attributes
        with client.mock_mgmt_post(make_response({"users": [{"id": "u1"}, {"id": "u2"}]})) as mock_post:
            resp = await client.invoke(
                client.mgmt.user.search_all_test_users(
                    ["t1, t2"],
                    ["r1", "r2"],
                    custom_attributes={"ak": "av"},
                    statuses=["invited"],
                    phones=["+111111"],
                    emails=["a@b.com"],
                )
            )
            users = resp["users"]
            assert len(users) == 2
            assert users[0]["id"] == "u1"
            assert users[1]["id"] == "u2"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.test_users_search_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

        # Test success flow with time parameters
        with client.mock_mgmt_post(make_response({"users": [{"id": "u1"}]})) as mock_post:
            resp = await client.invoke(
                client.mgmt.user.search_all_test_users(
                    from_created_time=100,
                    to_created_time=200,
                    from_modified_time=300,
                    to_modified_time=400,
                    limit=10,
                    page=0,
                )
            )
            users = resp["users"]
            assert len(users) == 1
            assert users[0]["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.test_users_search_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

        # Test success flow with tenant_role_ids and tenant_role_names
        with client.mock_mgmt_post(make_response({"users": [{"id": "u1"}, {"id": "u2"}]})) as mock_post:
            resp = await client.invoke(
                client.mgmt.user.search_all_test_users(
                    tenant_role_ids={"tenant1": {"values": ["roleA", "roleB"], "and": True}},
                    tenant_role_names={"tenant2": {"values": ["admin", "user"], "and": False}},
                )
            )
            users = resp["users"]
            assert len(users) == 2
            assert users[0]["id"] == "u1"
            assert users[1]["id"] == "u2"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.test_users_search_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "tenantIds": [],
                    "roleNames": [],
                    "limit": 0,
                    "page": 0,
                    "testUsersOnly": True,
                    "withTestUser": True,
                    "tenantRoleIds": {"tenant1": {"values": ["roleA", "roleB"], "and": True}},
                    "tenantRoleNames": {"tenant2": {"values": ["admin", "user"], "and": False}},
                },
                follow_redirects=False,
            )

    async def test_get_provider_token(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_get(make_response(status=500)) as mock_get:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.get_provider_token("valid-id", "p1"))

        # Test success flow
        with client.mock_mgmt_get(
            make_response({
                "provider": "p1",
                "providerUserId": "puid",
                "accessToken": "access123",
                "refreshToken": "refresh456",
                "expiration": "123123123",
                "scopes": ["s1", "s2"],
            })
        ) as mock_get:
            resp = await client.invoke(
                client.mgmt.user.get_provider_token("valid-id", "p1", True, True)
            )
            assert resp["provider"] == "p1"
            assert resp["providerUserId"] == "puid"
            assert resp["accessToken"] == "access123"
            assert resp["refreshToken"] == "refresh456"
            assert resp["expiration"] == "123123123"
            assert resp["scopes"] == ["s1", "s2"]
            assert_http_called(
                mock_get, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_get_provider_token}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params={
                    "loginId": "valid-id",
                    "provider": "p1",
                    "withRefreshToken": True,
                    "forceRefresh": True,
                },
                follow_redirects=True,
            )

    async def test_activate(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.activate("valid-id"))

        # Test success flow
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(client.mgmt.user.activate("valid-id"))
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_update_status_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "valid-id",
                    "status": "enabled",
                },
                follow_redirects=False,
            )

    async def test_deactivate(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.deactivate("valid-id"))

        # Test success flow
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(client.mgmt.user.deactivate("valid-id"))
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_update_status_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "valid-id",
                    "status": "disabled",
                },
                follow_redirects=False,
            )

    async def test_update_login_id(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.update_login_id("valid-id", "a@b.c"))

        # Test success flow
        with client.mock_mgmt_post(make_response({"user": {"id": "a@b.c"}})) as mock_post:
            resp = await client.invoke(client.mgmt.user.update_login_id("valid-id", "a@b.c"))
            user = resp["user"]
            assert user["id"] == "a@b.c"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_update_login_id_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "valid-id",
                    "newLoginId": "a@b.c",
                },
                follow_redirects=False,
            )

    async def test_update_email(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.update_email("valid-id", "a@b.c"))

        # Test success flow
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(client.mgmt.user.update_email("valid-id", "a@b.c"))
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_update_email_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "valid-id",
                    "email": "a@b.c",
                    "verified": None,
                    "failOnConflict": None,
                },
                follow_redirects=False,
            )

    async def test_update_phone(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.update_phone("valid-id", "+18005551234"))

        # Test success flow
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(client.mgmt.user.update_phone("valid-id", "+18005551234", True))
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_update_phone_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "valid-id",
                    "phone": "+18005551234",
                    "verified": True,
                    "failOnConflict": None,
                },
                follow_redirects=False,
            )

    async def test_update_display_name(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.update_display_name("valid-id", "foo"))

        # Test success flow
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(client.mgmt.user.update_display_name("valid-id", "foo"))
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_update_name_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "valid-id",
                    "displayName": "foo",
                },
                follow_redirects=False,
            )

    async def test_update_picture(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.update_picture("valid-id", "foo"))

        # Test success flow
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(client.mgmt.user.update_picture("valid-id", "foo"))
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_update_picture_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "valid-id",
                    "picture": "foo",
                },
                follow_redirects=False,
            )

    async def test_update_custom_attribute(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.user.update_custom_attribute("valid-id", "foo", "bar")
                )

        # Test success flow
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(
                client.mgmt.user.update_custom_attribute("valid-id", "foo", "bar")
            )
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_update_custom_attribute_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                json={
                    "loginId": "valid-id",
                    "attributeKey": "foo",
                    "attributeValue": "bar",
                },
                follow_redirects=False,
                params=None,
            )

    async def test_set_roles(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.set_roles("valid-id", ["foo", "bar"]))

        # Test success flow
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(client.mgmt.user.set_roles("valid-id", ["foo", "bar"]))
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_set_role_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "valid-id",
                    "roleNames": ["foo", "bar"],
                },
                follow_redirects=False,
            )

    async def test_add_roles(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.add_roles("valid-id", ["foo", "bar"]))

        # Test success flow
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(client.mgmt.user.add_roles("valid-id", ["foo", "bar"]))
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_add_role_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "valid-id",
                    "roleNames": ["foo", "bar"],
                },
                follow_redirects=False,
            )

    async def test_remove_roles(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.remove_roles("valid-id", ["foo", "bar"]))

        # Test success flow
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(client.mgmt.user.remove_roles("valid-id", ["foo", "bar"]))
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_remove_role_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "valid-id",
                    "roleNames": ["foo", "bar"],
                },
                follow_redirects=False,
            )

    async def test_add_sso_apps(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.add_sso_apps("valid-id", ["foo", "bar"]))

        # Test success flow
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(client.mgmt.user.add_sso_apps("valid-id", ["foo", "bar"]))
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_add_sso_apps}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "valid-id",
                    "ssoAppIds": ["foo", "bar"],
                },
                follow_redirects=False,
            )

    async def test_set_sso_apps(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.set_sso_apps("valid-id", ["foo", "bar"]))

        # Test success flow
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(client.mgmt.user.set_sso_apps("valid-id", ["foo", "bar"]))
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_set_sso_apps}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "valid-id",
                    "ssoAppIds": ["foo", "bar"],
                },
                follow_redirects=False,
            )

    async def test_remove_sso_apps(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.remove_sso_apps("valid-id", ["foo", "bar"]))

        # Test success flow
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(client.mgmt.user.remove_sso_apps("valid-id", ["foo", "bar"]))
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_remove_sso_apps}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "valid-id",
                    "ssoAppIds": ["foo", "bar"],
                },
                follow_redirects=False,
            )

    async def test_add_tenant(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.add_tenant("valid-id", "tid"))

        # Test success flow
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(client.mgmt.user.add_tenant("valid-id", "tid"))
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_add_tenant_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "valid-id",
                    "tenantId": "tid",
                },
                follow_redirects=False,
            )

    async def test_remove_tenant(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.remove_tenant("valid-id", "tid"))

        # Test success flow
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(client.mgmt.user.remove_tenant("valid-id", "tid"))
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_remove_tenant_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "valid-id",
                    "tenantId": "tid",
                },
                follow_redirects=False,
            )

    async def test_set_tenant_roles(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.user.set_tenant_roles("valid-id", "tid", ["foo", "bar"])
                )

        # Test success flow
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(
                client.mgmt.user.set_tenant_roles("valid-id", "tid", ["foo", "bar"])
            )
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_set_role_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "valid-id",
                    "tenantId": "tid",
                    "roleNames": ["foo", "bar"],
                },
                follow_redirects=False,
            )

    async def test_add_tenant_roles(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.user.add_tenant_roles("valid-id", "tid", ["foo", "bar"])
                )

        # Test success flow
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(
                client.mgmt.user.add_tenant_roles("valid-id", "tid", ["foo", "bar"])
            )
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_add_role_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "valid-id",
                    "tenantId": "tid",
                    "roleNames": ["foo", "bar"],
                },
                follow_redirects=False,
            )

    async def test_remove_tenant_roles(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.user.remove_tenant_roles("valid-id", "tid", ["foo", "bar"])
                )

        # Test success flow
        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(
                client.mgmt.user.remove_tenant_roles("valid-id", "tid", ["foo", "bar"])
            )
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_remove_role_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "valid-id",
                    "tenantId": "tid",
                    "roleNames": ["foo", "bar"],
                },
                follow_redirects=False,
            )

    async def test_generate_otp_for_test_user(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.user.generate_otp_for_test_user("login-id", "email")
                )

        # Test success flow
        with client.mock_mgmt_post(
            make_response({"code": "123456", "loginId": "login-id"})
        ) as mock_post:
            login_options = LoginOptions(stepup=True)
            resp = await client.invoke(
                client.mgmt.user.generate_otp_for_test_user(DeliveryMethod.EMAIL, "login-id", login_options)
            )
            assert resp["code"] == "123456"
            assert resp["loginId"] == "login-id"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_generate_otp_for_test_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

    async def test_user_set_temporary_password(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.user.set_temporary_password("login-id", "some-password")
                )

        # Test success flow
        with client.mock_mgmt_post(make_response({})) as mock_post:
            await client.invoke(
                client.mgmt.user.set_temporary_password(
                    "login-id",
                    "some-password",
                )
            )
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_set_temporary_password_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "login-id",
                    "password": "some-password",
                    "setActive": False,
                },
                follow_redirects=False,
            )

    async def test_user_set_active_password(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.user.set_active_password("login-id", "some-password")
                )

        # Test success flow
        with client.mock_mgmt_post(make_response({})) as mock_post:
            await client.invoke(
                client.mgmt.user.set_active_password(
                    "login-id",
                    "some-password",
                )
            )
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_set_active_password_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "login-id",
                    "password": "some-password",
                    "setActive": True,
                },
                follow_redirects=False,
            )

    async def test_user_set_password(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.user.set_password("login-id", "some-password")
                )

        # Test success flow
        with client.mock_mgmt_post(make_response({})) as mock_post:
            await client.invoke(
                client.mgmt.user.set_password(
                    "login-id",
                    "some-password",
                )
            )
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_set_password_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "login-id",
                    "password": "some-password",
                },
                follow_redirects=False,
            )

    async def test_user_expire_password(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.expire_password("login-id"))

        # Test success flow
        with client.mock_mgmt_post(make_response({})) as mock_post:
            await client.invoke(
                client.mgmt.user.expire_password(
                    "login-id",
                )
            )
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_expire_password_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "login-id",
                },
                follow_redirects=False,
            )

    async def test_user_remove_all_passkeys(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.remove_all_passkeys("login-id"))

        # Test success flow
        with client.mock_mgmt_post(make_response({})) as mock_post:
            await client.invoke(
                client.mgmt.user.remove_all_passkeys(
                    "login-id",
                )
            )
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_remove_all_passkeys_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "login-id",
                },
                follow_redirects=False,
            )

    async def test_user_remove_totp_seed(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.remove_totp_seed("login-id"))

        # Test success flow
        with client.mock_mgmt_post(make_response({})) as mock_post:
            await client.invoke(
                client.mgmt.user.remove_totp_seed(
                    "login-id",
                )
            )
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_remove_totp_seed_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "login-id",
                },
                follow_redirects=False,
            )

    async def test_generate_magic_link_for_test_user(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.user.generate_magic_link_for_test_user("login-id", "email", "bla")
                )

        # Test success flow
        with client.mock_mgmt_post(
            make_response({"link": "some-link", "loginId": "login-id"})
        ) as mock_post:
            login_options = LoginOptions(stepup=True)
            resp = await client.invoke(
                client.mgmt.user.generate_magic_link_for_test_user(
                    DeliveryMethod.EMAIL, "login-id", "bla", login_options
                )
            )
            assert resp["link"] == "some-link"
            assert resp["loginId"] == "login-id"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_generate_magic_link_for_test_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

    async def test_generate_enchanted_link_for_test_user(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.user.generate_enchanted_link_for_test_user("login-id", "bla")
                )

        # Test success flow
        with client.mock_mgmt_post(
            make_response({"link": "some-link", "loginId": "login-id", "pendingRef": "some-ref"})
        ) as mock_post:
            login_options = LoginOptions(stepup=True)
            resp = await client.invoke(
                client.mgmt.user.generate_enchanted_link_for_test_user("login-id", "bla", login_options)
            )
            assert resp["link"] == "some-link"
            assert resp["loginId"] == "login-id"
            assert resp["pendingRef"] == "some-ref"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_generate_enchanted_link_for_test_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

    async def test_generate_embedded_link(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.generate_embedded_link("login-id"))

        # Test success flow
        with client.mock_mgmt_post(make_response({"token": "some-token"})) as mock_post:
            resp = await client.invoke(
                client.mgmt.user.generate_embedded_link("login-id", {"k1": "v1"})
            )
            assert resp == "some-token"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_generate_embedded_link_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                json={
                    "loginId": "login-id",
                    "customClaims": {"k1": "v1"},
                    "timeout": 0,
                },
                follow_redirects=False,
                params=None,
            )

    async def test_generate_sign_up_embedded_link(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(
                    client.mgmt.user.generate_sign_up_embedded_link("login-id")
                )

        # Test success flow
        with client.mock_mgmt_post(make_response({"token": "some-token"})) as mock_post:
            resp = await client.invoke(
                client.mgmt.user.generate_sign_up_embedded_link(
                    "login-id", email_verified=True, phone_verified=True
                )
            )
            assert resp == "some-token"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_generate_sign_up_embedded_link_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
                params=None,
            )

    async def test_history(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        # Test failed flows
        with client.mock_mgmt_post(make_response(status=500)) as mock_post:
            with pytest.raises(AuthException):
                await client.invoke(client.mgmt.user.history(["user-id-1", "user-id-2"]))

        # Test success flow
        with client.mock_mgmt_post(
            make_response([
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
            ])
        ) as mock_post:
            resp = await client.invoke(client.mgmt.user.history(["user-id-1", "user-id-2"]))
            assert resp == [
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
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_history_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                json=["user-id-1", "user-id-2"],
                follow_redirects=False,
                params=None,
            )

    async def test_update_test_user(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_post(make_response({"user": {"id": "u1"}})) as mock_post:
            resp = await client.invoke(
                client.mgmt.user.update(
                    "id",
                    display_name="test-user",
                    test=True,
                )
            )
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_post, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_update_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
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
            )

    async def test_patch_test_user(self, client_factory):
        client = client_factory.make(PROJECT_ID, PUBLIC_KEY_DICT, False, "key")

        with client.mock_mgmt_patch(make_response({"user": {"id": "u1"}})) as mock_patch:
            resp = await client.invoke(
                client.mgmt.user.patch(
                    "id",
                    display_name="test-user",
                    test=True,
                )
            )
            user = resp["user"]
            assert user["id"] == "u1"
            assert_http_called(
                mock_patch, client.mode,
                f"{DEFAULT_BASE_URL}{MgmtV1.user_patch_path}",
                headers={
                    **default_headers,
                    "Authorization": f"Bearer {PROJECT_ID}:key",
                    "x-descope-project-id": PROJECT_ID,
                },
                params=None,
                json={
                    "loginId": "id",
                    "displayName": "test-user",
                    "test": True,
                },
                follow_redirects=False,
            )
