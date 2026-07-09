"""E2E test: OTP sign-up / sign-in flow.

Runs against a real Descope backend; skipped when env vars are absent.
Exercises both the sync DescopeClient and async DescopeClientAsync via the
UnifiedClientBase.invoke() pattern.
"""

import uuid

import pytest

from descope import DeliveryMethod
from descope.common import REFRESH_SESSION_TOKEN_NAME, SESSION_TOKEN_NAME

pytestmark = pytest.mark.e2e


class TestE2E_OTP:
    @pytest.fixture(autouse=True)
    async def _cleanup(self, descope_client):
        """Delete all test users after each test."""
        yield
        await descope_client.invoke(descope_client.mgmt.user.delete_all_test_users())

    async def test_otp_sign_up_and_sign_in(self, descope_client):
        login_id = f"user-{uuid.uuid4()}"

        # Create a test user with a phone number for SMS OTP
        await descope_client.invoke(
            descope_client.mgmt.user.create_test_user(
                login_id=login_id,
                phone="+972-52-5554321",
                display_name="E2E OTP Test User",
            )
        )

        # --- Sign-up ---
        # Pre-generate the OTP code before initiating sign-up so it is ready
        generate_res = await descope_client.invoke(
            descope_client.mgmt.user.generate_otp_for_test_user(
                method=DeliveryMethod.SMS,
                login_id=login_id,
            )
        )
        await descope_client.invoke(
            descope_client.otp.sign_up(
                method=DeliveryMethod.SMS,
                login_id=login_id,
                user={"name": "E2E OTP Test User", "phone": "+972-52-5554321"},
            )
        )
        code = generate_res.get("code", "")
        assert code, "OTP code returned by generate_otp_for_test_user was empty"

        jwt_response = await descope_client.invoke(
            descope_client.otp.verify_code(
                method=DeliveryMethod.SMS,
                login_id=login_id,
                code=code,
            )
        )
        assert jwt_response, "verify_code after sign-up returned empty response"

        # --- Sign-in ---
        generate_res = await descope_client.invoke(
            descope_client.mgmt.user.generate_otp_for_test_user(
                method=DeliveryMethod.SMS,
                login_id=login_id,
            )
        )
        await descope_client.invoke(
            descope_client.otp.sign_in(
                method=DeliveryMethod.SMS,
                login_id=login_id,
            )
        )
        code = generate_res.get("code", "")
        assert code, "OTP code returned by generate_otp_for_test_user was empty"

        jwt_response = await descope_client.invoke(
            descope_client.otp.verify_code(
                method=DeliveryMethod.SMS,
                login_id=login_id,
                code=code,
            )
        )
        assert jwt_response, "verify_code after sign-in returned empty response"

        session_token = jwt_response[SESSION_TOKEN_NAME].get("jwt")
        assert session_token, "Session token is empty after sign-in"
        refresh_token = jwt_response[REFRESH_SESSION_TOKEN_NAME].get("jwt")
        assert refresh_token, "Refresh token is empty after sign-in"

        # --- Validate & refresh session ---
        # validate_session is sync on both clients (inherited from _client_base)
        await descope_client.invoke(descope_client.validate_session(session_token))

        refreshed = await descope_client.invoke(descope_client.refresh_session(refresh_token))
        assert refreshed, "refresh_session returned empty response"

        # --- Logout ---
        await descope_client.invoke(descope_client.logout(refresh_token))
