from __future__ import annotations

from typing import Iterable, Optional, Union

from descope._auth_base import AsyncAuthBase
from descope.authmethod._totp_base import TOTPBase
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    EndpointsV1,
    LoginOptions,
    validate_refresh_token_provided,
)


class TOTPAsync(TOTPBase, AsyncAuthBase):
    """Async TOTP auth-method. All network calls are coroutines; validation is sync (no I/O)."""

    async def sign_up(self, login_id: str, user: Optional[dict] = None) -> dict:
        """Sign up a new user via TOTP; returns provisioningURL, image, and key."""
        self._validate_login_id(login_id)

        uri = EndpointsV1.sign_up_auth_totp_path
        body = self._compose_signup_body(login_id, user)
        response = await self._http.post(uri, body=body)
        return response.json()

    async def sign_in_code(
        self,
        login_id: str,
        code: str,
        login_options: Optional[LoginOptions] = None,
        refresh_token: Optional[str] = None,
        audience: Union[str, None, Iterable[str]] = None,
    ) -> dict:
        """Verify a TOTP code and return session JWTs."""
        self._validate_login_id(login_id)
        self._validate_code(code)
        validate_refresh_token_provided(login_options, refresh_token)

        uri = EndpointsV1.verify_totp_path
        body = self._compose_signin_body(login_id, code, login_options)
        response = await self._http.post(uri, body=body, pswd=refresh_token)

        resp = response.json()
        return self._auth.generate_jwt_response(resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None), audience)

    async def update_user(self, login_id: str, refresh_token: str) -> dict:
        """Add TOTP to an existing user; returns provisioningURL, image, and key."""
        self._validate_login_id(login_id)
        self._validate_refresh_token(refresh_token)

        uri = EndpointsV1.update_totp_path
        body = self._compose_update_user_body(login_id)
        response = await self._http.post(uri, body=body, pswd=refresh_token)
        return response.json()
