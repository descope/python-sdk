from __future__ import annotations

from typing import Optional

from descope._authmethod_base import AuthMethodBase
from descope.authmethod._oauth_base import OAuthBase
from descope.common import (
    EndpointsV1,
    LoginOptions,
    validate_refresh_token_provided,
)
from descope.exceptions import ERROR_TYPE_INVALID_ARGUMENT, AuthException


class OAuth(OAuthBase, AuthMethodBase):
    def start(
        self,
        provider: str,
        return_url: str = "",
        login_options: Optional[LoginOptions] = None,
        refresh_token: Optional[str] = None,
    ) -> dict:
        """ """
        if not self._verify_provider(provider):
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_ARGUMENT,
                f"Unknown OAuth provider: {provider}",
            )

        validate_refresh_token_provided(login_options, refresh_token)

        uri = EndpointsV1.oauth_start_path
        params = OAuth._compose_start_params(provider, return_url)
        response = self._http.post(
            uri,
            body=login_options.__dict__ if login_options else {},
            params=params,
            pswd=refresh_token,
        )

        return response.json()

    def exchange_token(self, code: str) -> dict:
        return self._auth.exchange_token(EndpointsV1.oauth_exchange_token_path, code)
