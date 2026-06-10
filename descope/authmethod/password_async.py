from __future__ import annotations

from typing import Iterable

from descope._auth_base import AsyncAuthBase
from descope.authmethod._password_base import PasswordBase
from descope.common import REFRESH_SESSION_COOKIE_NAME, EndpointsV1
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class PasswordAsync(PasswordBase, AsyncAuthBase):
    """Async Password auth-method. All network calls are coroutines; validation is sync (no I/O)."""

    async def sign_up(
        self,
        login_id: str,
        password: str,
        user: dict | None = None,
        audience: str | None | Iterable[str] = None,
    ) -> dict:
        if not login_id:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "login_id cannot be empty")

        if not password:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "password cannot be empty")

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
        if not login_id:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "login_id cannot be empty")

        if not password:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Password cannot be empty")

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
        if not login_id:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "login_id cannot be empty")

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
        if not login_id:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "login_id cannot be empty")

        if not new_password:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "new_password cannot be empty")

        if not refresh_token:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Refresh token cannot be empty")

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
        if not login_id:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "login_id cannot be empty")

        if not old_password:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "old_password cannot be empty")

        if not new_password:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "new_password cannot be empty")

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
        response = await self._http.get(uri=EndpointsV1.password_policy_path)
        return response.json()
