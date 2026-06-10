from __future__ import annotations

from typing import Iterable, Optional, Union

from descope._auth_base import AsyncAuthBase
from descope.authmethod._webauthn_base import WebAuthnBase
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    EndpointsV1,
    LoginOptions,
    validate_refresh_token_provided,
)
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class WebAuthnAsync(WebAuthnBase, AsyncAuthBase):
    """Async WebAuthn auth-method. All network calls are coroutines; validation is sync (no I/O)."""

    async def sign_up_start(
        self,
        login_id: Optional[str],
        origin: Optional[str],
        user: Optional[dict] = None,
    ) -> dict:
        if not login_id:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty")

        if not origin:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Origin cannot be empty")

        if not user:
            user = {}

        uri = EndpointsV1.sign_up_auth_webauthn_start_path
        body = self._compose_sign_up_start_body(login_id, user, origin)
        response = await self._http.post(uri, body=body)
        return response.json()

    async def sign_up_finish(
        self,
        transaction_id: str,
        response,
        audience: Union[str, None, Iterable[str]] = None,
    ) -> dict:
        if not transaction_id:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Transaction id cannot be empty")

        if not response:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Response cannot be empty")

        uri = EndpointsV1.sign_up_auth_webauthn_finish_path
        body = self._compose_sign_up_in_finish_body(transaction_id, response)
        response = await self._http.post(uri, body=body)
        resp = response.json()
        return self._auth.generate_jwt_response(resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None), audience)

    async def sign_in_start(
        self,
        login_id: str,
        origin: str,
        login_options: Optional[LoginOptions] = None,
        refresh_token: Optional[str] = None,
    ) -> dict:
        if not login_id:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty")

        if not origin:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Origin cannot be empty")

        validate_refresh_token_provided(login_options, refresh_token)

        uri = EndpointsV1.sign_in_auth_webauthn_start_path
        body = self._compose_sign_in_start_body(login_id, origin, login_options)
        response = await self._http.post(uri, body=body, pswd=refresh_token)
        return response.json()

    async def sign_in_finish(
        self,
        transaction_id: str,
        response,
        audience: Union[str, None, Iterable[str]] = None,
    ) -> dict:
        if not transaction_id:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Transaction id cannot be empty")

        if not response:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Response cannot be empty")

        uri = EndpointsV1.sign_in_auth_webauthn_finish_path
        body = self._compose_sign_up_in_finish_body(transaction_id, response)
        response = await self._http.post(uri, body=body)
        resp = response.json()
        return self._auth.generate_jwt_response(resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None), audience)

    async def sign_up_or_in_start(
        self,
        login_id: str,
        origin: str,
    ) -> dict:
        if not login_id:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty")

        if not origin:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Origin cannot be empty")

        uri = EndpointsV1.sign_up_or_in_auth_webauthn_start_path
        body = self._compose_sign_up_or_in_start_body(login_id, origin)
        response = await self._http.post(uri, body=body)
        return response.json()

    async def update_start(self, login_id: str, refresh_token: str, origin: str) -> dict:
        if not login_id:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Identifier cannot be empty")

        if not refresh_token:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Refresh token cannot be empty")

        uri = EndpointsV1.update_auth_webauthn_start_path
        body = self._compose_update_start_body(login_id, origin)
        response = await self._http.post(uri, body=body, pswd=refresh_token)
        return response.json()

    async def update_finish(self, transaction_id: str, response: str) -> None:
        if not transaction_id:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Transaction id cannot be empty")

        if not response:
            raise AuthException(400, ERROR_TYPE_INVALID_ARGUMENT, "Response cannot be empty")

        uri = EndpointsV1.update_auth_webauthn_finish_path
        body = self._compose_update_finish_body(transaction_id, response)
        await self._http.post(uri, body=body)
