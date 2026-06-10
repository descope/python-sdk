from __future__ import annotations

from typing import Iterable

from descope._auth_base import AsyncAuthBase
from descope.authmethod._password_base import PasswordBase
from descope.common import REFRESH_SESSION_COOKIE_NAME, EndpointsV1


class PasswordAsync(PasswordBase, AsyncAuthBase):
    """Async Password auth-method. All network calls are coroutines; validation is sync (no I/O)."""

    async def sign_up(
        self,
        login_id: str,
        password: str,
        user: dict | None = None,
        audience: str | None | Iterable[str] = None,
    ) -> dict:
        """Create a new user with a password and return session JWTs."""
        self._validate_login_id(login_id)
        self._validate_password(password)

        uri = EndpointsV1.sign_up_password_path
        body = self._compose_signup_body(login_id, password, user)
        response = await self._http.post(uri, body=body)

        resp = response.json()
        return self._auth.generate_jwt_response(resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None), audience)

    async def sign_in(
        self,
        login_id: str,
        password: str,
        audience: str | None | Iterable[str] = None,
    ) -> dict:
        """Verify the user's password and return session JWTs."""
        self._validate_login_id(login_id)
        self._validate_sign_in_password(password)

        uri = EndpointsV1.sign_in_password_path
        response = await self._http.post(uri, body={"loginId": login_id, "password": password})

        resp = response.json()
        return self._auth.generate_jwt_response(resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None), audience)

    async def send_reset(
        self,
        login_id: str,
        redirect_url: str | None = None,
        template_options: dict | None = None,
    ) -> dict:
        """Send a password reset prompt to the user per the configured reset method."""
        self._validate_login_id(login_id)

        uri = EndpointsV1.send_reset_password_path
        body: dict[str, str | bool | dict | None] = {
            "loginId": login_id,
            "redirectUrl": redirect_url,
        }
        if template_options is not None:
            body["templateOptions"] = template_options

        response = await self._http.post(uri, body=body)
        return response.json()

    async def update(self, login_id: str, new_password: str, refresh_token: str) -> None:
        """Update the password for an existing logged-in user."""
        self._validate_login_id(login_id)
        self._validate_new_password(new_password)
        self._validate_refresh_token(refresh_token)

        uri = EndpointsV1.update_password_path
        await self._http.post(
            uri,
            body={"loginId": login_id, "newPassword": new_password},
            pswd=refresh_token,
        )

    async def replace(
        self,
        login_id: str,
        old_password: str,
        new_password: str,
        audience: str | None | Iterable[str] = None,
    ) -> dict:
        """Authenticate with old_password, then replace it with new_password; returns session JWTs."""
        self._validate_login_id(login_id)
        self._validate_old_password(old_password)
        self._validate_new_password(new_password)

        uri = EndpointsV1.replace_password_path
        response = await self._http.post(
            uri,
            body={
                "loginId": login_id,
                "oldPassword": old_password,
                "newPassword": new_password,
            },
        )

        resp = response.json()
        return self._auth.generate_jwt_response(resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None), audience)

    async def get_policy(self) -> dict:
        """Return the project's password policy (min length, character requirements, etc.)."""
        response = await self._http.get(uri=EndpointsV1.password_policy_path)
        return response.json()
