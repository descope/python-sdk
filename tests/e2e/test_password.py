"""E2E test: password sign-up, sign-in, and management flows.

Prerequisites: the e2e project must have password authentication enabled with a
policy of minLength >= 9, uppercase required, non-alphanumeric required.

Deferred: test_password_reset (requires MailSlurp — not ported).
"""

import uuid

import pytest

from descope import AuthException
from descope.common import REFRESH_SESSION_TOKEN_NAME, SESSION_TOKEN_NAME

pytestmark = pytest.mark.e2e

_PASSWORD = "WASD+ijkl"


class TestE2E_Password:
    async def test_password_sign_up(self, descope_client):
        login_id = f"pw-user-{uuid.uuid4()}@example.com"
        try:
            # Verify the project policy is configured as required by this test
            policy = await descope_client.invoke(descope_client.password.get_policy())
            assert policy["minLength"] > 5, f"sandbox password policy: minLength must be > 5, got {policy['minLength']}"
            assert policy.get("nonAlphanumeric"), (
                f"sandbox password policy: nonAlphanumeric must be enabled (got {policy})"
            )

            # Negative: too-short password
            with pytest.raises(AuthException):
                await descope_client.invoke(descope_client.password.sign_up(login_id, "A!a4", {"name": "Test User"}))

            # Negative: no non-alphanumeric character
            with pytest.raises(AuthException):
                await descope_client.invoke(
                    descope_client.password.sign_up(login_id, "Aaa456789", {"name": "Test User"})
                )

            # Success: valid sign-up
            jwt_response = await descope_client.invoke(
                descope_client.password.sign_up(login_id, _PASSWORD, {"name": "Test User"})
            )
            assert jwt_response, "password.sign_up returned empty response"
            assert jwt_response[SESSION_TOKEN_NAME]["jwt"], "Session token missing after sign-up"
            assert jwt_response[REFRESH_SESSION_TOKEN_NAME]["jwt"], "Refresh token missing after sign-up"
            assert jwt_response.get("firstSeen") is True

            # Duplicate sign-up must raise
            with pytest.raises(AuthException):
                await descope_client.invoke(descope_client.password.sign_up(login_id, _PASSWORD))

            # Negative sign-ins
            with pytest.raises(AuthException):
                await descope_client.invoke(descope_client.password.sign_in("bar@foo.com", _PASSWORD))
            with pytest.raises(AuthException):
                await descope_client.invoke(descope_client.password.sign_in(login_id, ""))
            with pytest.raises(AuthException):
                await descope_client.invoke(descope_client.password.sign_in(login_id, "asdf"))

            # Success: sign-in
            jwt_response = await descope_client.invoke(descope_client.password.sign_in(login_id, _PASSWORD))
            assert jwt_response[SESSION_TOKEN_NAME]["jwt"], "Session token missing after sign-in"
            assert jwt_response[REFRESH_SESSION_TOKEN_NAME]["jwt"], "Refresh token missing after sign-in"
            assert jwt_response.get("firstSeen") is False
            assert jwt_response.get("user", {}).get("name") == "Test User"

            # Replace password
            new_password = _PASSWORD + "a"
            await descope_client.invoke(descope_client.password.replace(login_id, _PASSWORD, new_password))

            # Sign in with new password
            jwt_response = await descope_client.invoke(descope_client.password.sign_in(login_id, new_password))
            assert jwt_response[SESSION_TOKEN_NAME]["jwt"], "Session token missing after sign-in with new password"
            assert jwt_response[REFRESH_SESSION_TOKEN_NAME]["jwt"], (
                "Refresh token missing after sign-in with new password"
            )
            assert jwt_response.get("firstSeen") is False
            refresh_token = jwt_response[REFRESH_SESSION_TOKEN_NAME]["jwt"]

            await descope_client.invoke(descope_client.logout(refresh_token))
        finally:
            try:
                await descope_client.invoke(descope_client.mgmt.user.delete(login_id))
            except Exception:
                # best-effort cleanup — user may already be gone; don't mask the test result
                pass

    async def test_set_temporary_and_active_password(self, descope_client):
        login_id = f"pw-user-{uuid.uuid4()}@example.com"
        try:
            # Set up: sign up the user first
            await descope_client.invoke(descope_client.password.sign_up(login_id, _PASSWORD, {"name": "Temp Pw Test"}))

            # Set a temporary password — must require replacement before use
            await descope_client.invoke(descope_client.mgmt.user.set_temporary_password(login_id, "WASD+ijklll"))

            # Temporary password cannot be used directly for sign-in
            with pytest.raises(AuthException):
                await descope_client.invoke(descope_client.password.sign_in(login_id, "WASD+ijklll"))

            # Set an active password — immediately usable
            await descope_client.invoke(descope_client.mgmt.user.set_active_password(login_id, "WASD+ijkqqq"))

            # Active password works for sign-in
            jwt_response = await descope_client.invoke(descope_client.password.sign_in(login_id, "WASD+ijkqqq"))
            assert jwt_response[SESSION_TOKEN_NAME]["jwt"], "Session token missing after sign-in with active password"
        finally:
            try:
                await descope_client.invoke(descope_client.mgmt.user.delete(login_id))
            except Exception:
                # best-effort cleanup — user may already be gone; don't mask the test result
                pass
