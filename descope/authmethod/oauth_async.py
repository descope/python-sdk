from __future__ import annotations

from typing import Optional

from descope._auth_base import AsyncAuthBase
from descope.authmethod._oauth_base import OAuthBase
from descope.common import (
    REFRESH_SESSION_COOKIE_NAME,
    EndpointsV1,
    LoginOptions,
    validate_refresh_token_provided,
)
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class OAuthAsync(OAuthBase, AsyncAuthBase):
    """Async OAuth auth-method. All network calls are coroutines; validation is sync (no I/O)."""

    async def start(
        self,
        provider: str,
        return_url: str = "",
        login_options: Optional[LoginOptions] = None,
        refresh_token: Optional[str] = None,
    ) -> dict:
        if not self._verify_provider(provider):
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"Unknown OAuth provider: {provider}",
            )

        validate_refresh_token_provided(login_options, refresh_token)

        uri = EndpointsV1.oauth_start_path
        params = self._compose_start_params(provider, return_url)
        response = await self._http.post(
            uri,
            body=login_options.__dict__ if login_options else {},
            params=params,
            pswd=refresh_token,
        )
        return response.json()

    async def exchange_token(self, code: str) -> dict:
        self._validate_exchange_code(code)
        uri = EndpointsV1.oauth_exchange_token_path
        body = self._compose_exchange_body(code)
        response = await self._http.post(uri, body=body)
        return self._auth.generate_jwt_response(
            response.json(), response.cookies.get(REFRESH_SESSION_COOKIE_NAME), None
        )
