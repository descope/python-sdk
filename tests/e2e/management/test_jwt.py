"""E2E test: management JWT sign-in."""

import uuid

import pytest

pytestmark = pytest.mark.e2e


class TestE2E_ManagementJWT:
    async def test_management_jwt_sign_in(self, descope_client):
        login_id = f"jwt-user-{uuid.uuid4()}@example.com"

        try:
            await descope_client.invoke(descope_client.mgmt.user.create(login_id))

            resp = await descope_client.invoke(descope_client.mgmt.jwt.sign_in(login_id))

            session_token = resp["sessionToken"]
            assert session_token
            assert session_token["jwt"]

        finally:
            try:
                await descope_client.invoke(descope_client.mgmt.user.delete(login_id))
            except Exception:
                pass
