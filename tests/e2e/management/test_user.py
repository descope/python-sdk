"""E2E test: user management CRUD + test-user flow + invite."""

import uuid

import pytest

from descope import AuthException, DeliveryMethod
from descope.common import REFRESH_SESSION_TOKEN_NAME, SESSION_TOKEN_NAME
from descope.management.user import UserObj

pytestmark = pytest.mark.e2e


class TestE2E_ManagementUser:
    async def test_management_user_capabilities(self, descope_client):
        user_login_id = f"des-{uuid.uuid4().hex[:8]}@copeland.com"
        invited_login_id = f"des-invited-{uuid.uuid4().hex[:8]}@copeland.com"
        invited1_login_id = f"des-1-invited-{uuid.uuid4().hex[:8]}@copeland.com"
        invited2_login_id = f"des-2-invited-{uuid.uuid4().hex[:8]}@copeland.com"
        test_user_login_id = f"test-{uuid.uuid4().hex[:10]}"
        role1_name = f"role-{uuid.uuid4().hex[:8]}"
        role2_name = f"role-{uuid.uuid4().hex[:8]}"
        updated_login_id: str = ""

        try:
            # ----------------------------------------------------------------
            # User CRUD
            # ----------------------------------------------------------------
            resp = await descope_client.invoke(descope_client.mgmt.user.create(user_login_id))
            user = resp["user"]
            assert user
            assert user["email"] == user_login_id
            assert user["verifiedEmail"]
            assert user["status"] == "invited"

            resp = await descope_client.invoke(descope_client.mgmt.user.load(user_login_id))
            assert resp["user"]["email"] == user_login_id
            assert resp["user"]["verifiedEmail"]
            assert resp["user"]["status"] == "invited"

            new_login_id = f"bane-{uuid.uuid4().hex[:8]}@copeland.com"
            resp = await descope_client.invoke(descope_client.mgmt.user.update_login_id(user_login_id, new_login_id))
            updated_login_id = new_login_id
            assert updated_login_id in resp["user"]["loginIds"]

            search_resp = await descope_client.invoke(descope_client.mgmt.user.search_all())
            users = search_resp.get("users", [])
            assert any(updated_login_id in (u.get("loginIds") or []) for u in users)

            await descope_client.invoke(
                descope_client.mgmt.user.update(updated_login_id, display_name="Desmond Copeland")
            )

            await descope_client.invoke(descope_client.mgmt.role.create(role1_name))
            await descope_client.invoke(descope_client.mgmt.role.create(role2_name))

            await descope_client.invoke(
                descope_client.mgmt.user.patch(
                    updated_login_id,
                    phone="+1234567890",
                    middle_name="Middle",
                    role_names=[role1_name],
                )
            )
            resp = await descope_client.invoke(descope_client.mgmt.user.load(updated_login_id))
            u = resp["user"]
            assert updated_login_id in u["loginIds"]
            assert u["name"] == "Desmond Copeland"
            assert u.get("middleName") == "Middle"
            assert u.get("phone") == "+1234567890"
            assert role1_name in u.get("roleNames", [])
            assert u.get("verifiedPhone")

            await descope_client.invoke(
                descope_client.mgmt.user.patch(updated_login_id, role_names=[role1_name, role2_name])
            )
            u = (await descope_client.invoke(descope_client.mgmt.user.load(updated_login_id)))["user"]
            role_names_list = u.get("roleNames", [])
            assert len(role_names_list) == 2
            assert role1_name in role_names_list
            assert role2_name in role_names_list

            await descope_client.invoke(descope_client.mgmt.user.patch(updated_login_id, role_names=[]))
            u = (await descope_client.invoke(descope_client.mgmt.user.load(updated_login_id)))["user"]
            assert len(u.get("roleNames", [])) == 0
            assert u.get("phone") == "+1234567890"

            await descope_client.invoke(descope_client.mgmt.user.delete(updated_login_id))
            search_resp = await descope_client.invoke(descope_client.mgmt.user.search_all())
            assert not any(updated_login_id in (u.get("loginIds") or []) for u in search_resp.get("users", []))

            # ----------------------------------------------------------------
            # Test-user flow
            # ----------------------------------------------------------------
            with pytest.raises(AuthException):
                await descope_client.invoke(
                    descope_client.mgmt.user.generate_otp_for_test_user(
                        method=DeliveryMethod.EMAIL,
                        login_id=test_user_login_id,
                    )
                )

            create_resp = await descope_client.invoke(
                descope_client.mgmt.user.create_test_user(
                    login_id=test_user_login_id,
                    email=f"e2e-{uuid.uuid4().hex[:8]}@example.com",
                    phone="+12025550142",
                    display_name="foo bar test",
                )
            )
            test_user = create_resp["user"]
            assert test_user["loginIds"][0] == test_user_login_id
            test_user_id = test_user["userId"]

            resp = await descope_client.invoke(descope_client.mgmt.user.load_by_user_id(test_user_id))
            assert resp["user"]

            search_resp = await descope_client.invoke(descope_client.mgmt.user.search_all(test_users_only=True))
            test_users = search_resp.get("users", [])
            assert any(u["userId"] == test_user_id for u in test_users)

            gen_resp = await descope_client.invoke(
                descope_client.mgmt.user.generate_otp_for_test_user(
                    method=DeliveryMethod.EMAIL,
                    login_id=test_user_login_id,
                )
            )
            code = gen_resp["code"]
            assert code
            assert gen_resp["loginId"] == test_user_login_id

            jwt_response = await descope_client.invoke(
                descope_client.otp.verify_code(
                    method=DeliveryMethod.EMAIL,
                    login_id=test_user_login_id,
                    code=code,
                )
            )
            assert jwt_response.get("firstSeen")
            assert jwt_response[SESSION_TOKEN_NAME]["jwt"]
            assert jwt_response[REFRESH_SESSION_TOKEN_NAME]["jwt"]
            assert jwt_response["user"]["userId"] == test_user_id

            await descope_client.invoke(descope_client.mgmt.user.delete(test_user_login_id))
            with pytest.raises(AuthException):
                await descope_client.invoke(descope_client.mgmt.user.load_by_user_id(test_user_id))

            # ----------------------------------------------------------------
            # Invite flow
            # ----------------------------------------------------------------
            resp = await descope_client.invoke(descope_client.mgmt.user.invite(invited_login_id))
            u = resp["user"]
            assert u["email"] == invited_login_id
            assert u["verifiedEmail"]
            assert u["status"] == "invited"

            resp = await descope_client.invoke(descope_client.mgmt.user.load(invited_login_id))
            assert resp["user"]["email"] == invited_login_id
            assert resp["user"]["verifiedEmail"]
            assert resp["user"]["status"] == "invited"

            batch_resp = await descope_client.invoke(
                descope_client.mgmt.user.invite_batch([UserObj(invited1_login_id), UserObj(invited2_login_id)])
            )
            created = batch_resp["createdUsers"]
            failed = batch_resp["failedUsers"]
            assert len(created) == 2
            assert len(failed) == 0
            for cu in created:
                assert cu["email"]
                assert cu["verifiedEmail"]
                assert cu["status"] == "invited"

            await descope_client.invoke(descope_client.mgmt.user.load(invited1_login_id))
            await descope_client.invoke(descope_client.mgmt.user.load(invited2_login_id))

        finally:
            for rname in [role1_name, role2_name]:
                try:
                    await descope_client.invoke(descope_client.mgmt.role.delete(rname))
                except AuthException as e:
                    if e.status_code and e.status_code >= 500:
                        raise
            login_ids = [
                user_login_id,
                updated_login_id,
                test_user_login_id,
                invited_login_id,
                invited1_login_id,
                invited2_login_id,
            ]
            for uid in login_ids:
                if not uid:
                    continue
                try:
                    await descope_client.invoke(descope_client.mgmt.user.delete(uid))
                except AuthException as e:
                    if e.status_code and e.status_code >= 500:
                        raise
