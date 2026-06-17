"""E2E test: magic-link sign-up, sign-in, and session flow."""

import uuid

import pytest

from descope import DeliveryMethod
from descope.common import REFRESH_SESSION_TOKEN_NAME, SESSION_TOKEN_NAME

pytestmark = pytest.mark.e2e


def _extract_project_id_from_iss(iss: str) -> str:
    """Return the last path component of the 'iss' JWT claim."""
    return iss.rsplit("/", 1)[-1]


class TestE2E_Magiclink:
    @pytest.fixture(autouse=True)
    async def _cleanup(self, descope_client):
        """Delete all test users after each test."""
        yield
        await descope_client.invoke(descope_client.mgmt.user.delete_all_test_users())

    async def test_magiclink_methods(self, descope_client):
        login_id = f"user-{uuid.uuid4()}"
        uri = "http://test.me"

        # Create a test user
        await descope_client.invoke(
            descope_client.mgmt.user.create_test_user(
                login_id=login_id,
                email="doron@google.com",
                phone="+972-52-5554321",
                display_name="foo bar test",
            )
        )

        # --- Sign-up via magic link ---
        td = await descope_client.invoke(
            descope_client.mgmt.user.generate_magic_link_for_test_user(
                method=DeliveryMethod.EMAIL,
                login_id=login_id,
                uri=uri,
            )
        )
        raw_link = td["link"]
        token = raw_link[raw_link.index("=") + 1 :]

        await descope_client.invoke(
            descope_client.magiclink.sign_up_or_in(
                method=DeliveryMethod.EMAIL,
                login_id=login_id,
                uri=uri,
            )
        )

        jwt_response = await descope_client.invoke(descope_client.magiclink.verify(token=token))
        assert jwt_response, "magiclink.verify after sign-up returned empty response"

        refresh_token = jwt_response[REFRESH_SESSION_TOKEN_NAME]["jwt"]
        assert refresh_token, "Refresh token is empty after sign-up"

        # --- Sign-in via magic link ---
        td2 = await descope_client.invoke(
            descope_client.mgmt.user.generate_magic_link_for_test_user(
                method=DeliveryMethod.EMAIL,
                login_id=login_id,
                uri=uri,
            )
        )
        raw_link2 = td2["link"]
        sign_in_token = raw_link2[raw_link2.index("=") + 1 :]

        await descope_client.invoke(
            descope_client.magiclink.sign_in(
                method=DeliveryMethod.EMAIL,
                login_id=login_id,
                uri=uri,
            )
        )

        jwt_response = await descope_client.invoke(descope_client.magiclink.verify(token=sign_in_token))
        session_token = jwt_response[SESSION_TOKEN_NAME]["jwt"]
        assert session_token, "Session token is empty after sign-in"
        refresh_token = jwt_response[REFRESH_SESSION_TOKEN_NAME]["jwt"]
        assert refresh_token, "Refresh token is empty after sign-in"

        # --- Validate & refresh session ---
        await descope_client.invoke(descope_client.validate_session(session_token))

        refreshed = await descope_client.invoke(descope_client.refresh_session(refresh_token))
        assert refreshed, "refresh_session returned empty response"

        new_session_token = refreshed[SESSION_TOKEN_NAME]["jwt"]
        assert new_session_token, "New session token is empty after refresh"

        resp = await descope_client.invoke(descope_client.validate_session(new_session_token))
        assert resp, "validate_session returned empty response for refreshed token"

        token_data = resp[SESSION_TOKEN_NAME]
        assert token_data["sub"] == resp["userId"]
        assert _extract_project_id_from_iss(token_data["iss"]) == resp["projectId"]

        # --- Logout ---
        await descope_client.invoke(descope_client.logout(refresh_token))
